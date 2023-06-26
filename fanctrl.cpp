/*
MIT License

Copyright (c) 2021-2022 L. E. Spalt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <assert.h>
#include <winsock2.h>
#include <intrin.h>
#include <thread>
#include <semaphore>
#include <queue>
#include <set>
#include "fanctrl.h"
#include "util.h"
#include "plusaes.hpp"
#include "nlohmann/json.hpp"

#pragma comment(lib, "Ws2_32.lib")

struct AsyncCommand
{
    enum Type { CMD_SET_POWER, CMD_SET_SPEED };

    Type    type   = Type(0);
    int     value  = 0;
};

struct XiCtx
{
    unsigned int                        devId = 0;
    unsigned int                        lastHelloDeviceTimestamp = 0;
    DWORD                               lastHelloLocalTimestampMs = 0;
    ByteVec                             token;
    int                                 cmdId = 0;
    SOCKET                              sock = INVALID_SOCKET;
    sockaddr_in                         sockaddr = {};
    std::mutex                          mutex;
    std::deque<AsyncCommand>            asyncSendQueue;
    std::counting_semaphore<INT_MAX>    asyncSendQueueSema = std::counting_semaphore<INT_MAX>( 0 );  // represents number of elements in async send queue
    std::counting_semaphore<INT_MAX>    asyncInFlightSema = std::counting_semaphore<INT_MAX>( 0 );   // represents number of outstanding async requests
    std::set<int>                       asyncInFlightCmds;
    fanLogCb                            log = nullptr;
};

static XiCtx ctx;


static void token2KeyIV( const ByteVec& token, ByteVec& key, ByteVec& iv )
{
    key = md5( token );
    iv = md5( concat(key,token) );
}

static ByteVec decrypt( const ByteVec& msg, const ByteVec& token )
{
    ByteVec key, iv;
    ByteVec decrypted( msg.size() );
    unsigned long paddedSize;
    
    token2KeyIV( token, key, iv );

    plusaes::Error err = plusaes::decrypt_cbc( 
        msg.data(), (int)msg.size(), 
        key.data(), (int)key.size(), 
        (unsigned char(*)[16])iv.data(), 
        decrypted.data(), (int)decrypted.size(), &paddedSize );

    if( err != plusaes::kErrorOk )
        printf("ERROR: decryption failed, error %d\n", (int)err );

    decrypted.resize( decrypted.size() - paddedSize );
    return decrypted;
}

static ByteVec encrypt( const ByteVec& msg, const ByteVec& token )
{
    ByteVec key, iv;
    ByteVec encrypted( (msg.size() + 15) & ~15 );

    token2KeyIV( token, key, iv );

    plusaes::Error err = plusaes::encrypt_cbc( 
        msg.data(), (int)msg.size(), 
        key.data(), (int)key.size(), 
        (unsigned char(*)[16])iv.data(), 
        encrypted.data(), (int)encrypted.size(), true );
    
    if( err != plusaes::kErrorOk )
        printf("ERROR: encryption failed, error %d\n", (int)err );

    return encrypted;
}

static int send( SOCKET sock, const sockaddr_in& addr, const ByteVec& data )
{
    int n = sendto( sock, (char*)data.data(), (int)data.size(), 0, (SOCKADDR*)&addr, (int)sizeof(addr) );
    if( n == SOCKET_ERROR || n != (int)data.size() )
    {
        printf( "ERROR: sendto() failed or incomplete.\n" );
        return -1;
    }
    return n;
}

static int recv( SOCKET sock, ByteVec& data )
{
    int optsize = 4, maxmsgsize;
    getsockopt( sock, SOL_SOCKET, SO_MAX_MSG_SIZE, (char*)&maxmsgsize, &optsize );

    data.resize( maxmsgsize );
    int n = recv( sock, (char*)data.data(), (int)data.size(), 0 );
    if( n == SOCKET_ERROR )
    {
        printf( "ERROR: recv() failed.\n" );
        return -1;
    }
    data.resize( n );
    return n;
}

static ByteVec encodeXiPacket( const ByteVec& msg )
{
    DWORD deltaSecs = (GetTickCount() - ctx.lastHelloLocalTimestampMs) / 1000;

    ByteVec packet = concat( ByteVec(32), encrypt(msg,ctx.token) );

    unsigned char* hdr = &packet[0];
    hdr[0] = 0x21;
    hdr[1] = 0x31;
    hdr[2] = (unsigned char)(packet.size() >> 8);
    hdr[3] = (unsigned char)(packet.size() & 0xff);
    *((unsigned int*)&hdr[8]) = _byteswap_ulong( ctx.devId );
    *((unsigned int*)&hdr[12]) = _byteswap_ulong( ctx.lastHelloDeviceTimestamp + (unsigned)deltaSecs );

    memcpy( &packet[16], &ctx.token[0], 16 );
    ByteVec checksum = md5( packet );
    memcpy( &packet[16], checksum.data(), 16 );

    return packet;
}

static ByteVec decodeXiPacket( const ByteVec& msg )
{
    return decrypt( ByteVec(msg.begin()+32,msg.end()), ctx.token );
}

static void asyncCmdEnqueue( const AsyncCommand& cmd )
{
    // We enqueue async commands rather than sending them directly, just to avoid spamming
    // the fan with commands when the user goes nuts on the inputs.

    std::unique_lock lock( ctx.mutex );

    // If there's already an async command of the same type enqueued, override it.
    // We always do this, so there can be at most one.
    // Actually delete and re-insert the command, rather than just replacing it,
    // so that the ordering remains intact.
    bool overridden = false;
    for( int i=0; i<(int)ctx.asyncSendQueue.size(); ++i )
    {
        if( ctx.asyncSendQueue[i].type == cmd.type )
        {
            ctx.asyncSendQueue.erase( ctx.asyncSendQueue.begin() + i );
            overridden = true;
            break;
        }
    }

    ctx.asyncSendQueue.push_back( cmd );
    lock.unlock();

    if( !overridden )  // if we've overridden, the number of queue elements didn't change
        ctx.asyncSendQueueSema.release();
}

static void asyncSendWorker()
{
    std::unique_lock lock( ctx.mutex );
    lock.unlock();

    while( true )
    {
        ctx.asyncSendQueueSema.acquire();
        lock.lock();

        while( !ctx.asyncSendQueue.empty() )
        {
            AsyncCommand cmd = ctx.asyncSendQueue.front();
            ctx.asyncSendQueue.pop_front();

            std::string cmdstr;

            const int id = ++ctx.cmdId;

            if( cmd.type == AsyncCommand::CMD_SET_POWER )
                cmdstr = R"({"id": )" + std::to_string(id) + R"(, "method": "set_properties", "params": [{"did": "power", "siid": 2, "piid": 1, "value": )" + (cmd.value?"true":"false") + std::string("}]}");
            else if( cmd.type == AsyncCommand::CMD_SET_SPEED )
                cmdstr = R"({"id": )" + std::to_string(id) + R"(, "method": "set_properties", "params": [{"did": "fan_speed", "siid": 2, "piid": 10, "value": )" + std::to_string(cmd.value) + "}]}";

            ctx.log( ("ASYNC CMD: " + cmdstr).c_str() );
            ByteVec packet = encodeXiPacket( cstr2bytes(cmdstr) );
            send( ctx.sock, ctx.sockaddr, packet );

            ctx.asyncInFlightCmds.insert( id );
            ctx.asyncInFlightSema.release();
        }

        lock.unlock();

        // Waiting this long here seems to throttle requests enough so we don't ever get "busy" answers from the fan.
        // We could reduce this latency, but that'd require implementing a retry mechanism for "busy" answers to be robust.
        // We do want *some* latency here, so that rapid-fire requests have a chance to pile up in the queue, with only
        // the most recent one surviving to actually be sent to the fan.
        Sleep( 200 );
    }
}

static void asyncRecvWorker()
{
    std::unique_lock lock( ctx.mutex );
    lock.unlock();

    while( true )
    {
        // recv() will block until we receive something. We use the extra semaphore here to avoid
        // receiving data on the async path when the request really came from a sync command.
        ctx.asyncInFlightSema.acquire();

        ByteVec received;
        recv( ctx.sock, received );

        lock.lock();

        ByteVec decoded = decodeXiPacket( received );
        std::string str = bytes2str( decoded );
        ctx.log( ("ASYNC RSP: " + str).c_str());

        // We track cmd IDs here. This isn't really needed, but if one day we want to implement
        // retries on "busy" answers then this is where we'd start extending things.
        nlohmann::json json = nlohmann::json::parse(str);
        int recvId = json["id"];
        assert( ctx.asyncInFlightCmds.find(recvId) != ctx.asyncInFlightCmds.end() );
        ctx.asyncInFlightCmds.erase( recvId );

        lock.unlock();
    }
}

static void waitForAllAsyncResponses()
{
    std::unique_lock lock( ctx.mutex );
    lock.unlock();

    while( true )
    {
        lock.lock();
        if( ctx.asyncInFlightCmds.empty() )
            break;
        lock.unlock();
        Sleep( 100 );
    }
}

static bool syncCmdHelloHandshake()
{
    waitForAllAsyncResponses();
    std::unique_lock lock( ctx.mutex );

    ctx.log( "HELLO CMD" );

    ByteVec received;
    ByteVec hello = hexstr2bytes( "21310020ffffffffffffffffffffffffffffffffffffffffffffffffffffffff" );    

    if( send( ctx.sock, ctx.sockaddr, hello ) < 0 )
        return false;
    if( recv( ctx.sock, received ) < 0 )
        return false;

    ctx.lastHelloLocalTimestampMs = GetTickCount();
    ctx.devId                     = _byteswap_ulong( *((unsigned int*)&received[8]) );
    ctx.lastHelloDeviceTimestamp  = _byteswap_ulong( *((unsigned int*)&received[12]) );

    char s[512];
    sprintf( s, "HELLO RSP: device 0x%08x, time 0x%08x", ctx.devId, ctx.lastHelloDeviceTimestamp );
    ctx.log( s );

    return true;
}

static std::string syncCmdExecute( const std::string& cmd )
{
    waitForAllAsyncResponses();
    std::unique_lock lock( ctx.mutex );

    ctx.log( ("SYNC CMD: " + cmd).c_str() );

    ByteVec received;
    ByteVec packet = encodeXiPacket( cstr2bytes(cmd) );

    send( ctx.sock, ctx.sockaddr, packet );
    recv( ctx.sock, received );

    ByteVec decoded = decodeXiPacket( received );
    std::string str = bytes2str( decoded );

    ctx.log( ("SYNC RSP: " + str).c_str() );
    return str;
}

static std::string syncCmdGetInfo()
{
    const int id = ++ctx.cmdId;
    std::string cmd = R"({"id": )" + std::to_string(id) + R"(, "method": "miIO.info", "params": []})";
    std::string res = syncCmdExecute( cmd );
    return res;
}


//
// External
//

void fanInit( fanLogCb logCb )
{
    ctx.log = logCb;
    ctx.log( "\n============================\nBegin fan init..." );
    

    // Read config file if it exists. Init it with some defaults if it doesn't.
    // TODO: would be nice to configure this stuff through the property inspector
    char ip[128];
    char token[128];
    int port = 54321;
    {
        std::string configFilename = getExeFileLocation() + "\\config.txt";
        FILE* fp = fopen( configFilename.c_str(), "rb" );
        if( fp )
        {
            fscanf( fp, "%s %s", ip, token );
            fclose( fp );
        }
        else
        {
            sprintf( ip, "192.168.178.90" );
            sprintf( token, "6b5672f9c8fee346f830999a9b47e385" );
            fp = fopen( configFilename.c_str(), "wb" );
            fprintf( fp, "%s %s", ip, token );
            fclose( fp );
        }
    }

    ctx.sockaddr.sin_family = AF_INET;
    ctx.sockaddr.sin_addr.s_addr = inet_addr(ip);
    ctx.sockaddr.sin_port = htons(port);

    char s[512];
    snprintf(s,sizeof(s),"Using IP %s, port %d, token %s", ip, port, token);
    ctx.log( s );
    
    WSADATA wsaData;
    int err = 0;
    if( err=WSAStartup(MAKEWORD(2,2), &wsaData) )
    {
        ctx.log("ERROR: Winsock init failed");
        return;
    }
    
    ctx.token = hexstr2bytes( token );
    ctx.sock  = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );

    if( ctx.sock == INVALID_SOCKET || syncCmdHelloHandshake()==false )
    {
        ctx.log( "Could not establish connection to fan. Make sure IP address is correct and port is not blocked." );
        return;
    }

    ctx.log( "Attempting to retrieve fan info. If this doesn't finish, the most likely cause is a wrong token." );
    syncCmdGetInfo();

    ctx.log( "Fan init complete." );

    std::thread sendThread( asyncSendWorker );
    std::thread recvThread( asyncRecvWorker );
    sendThread.detach();
    recvThread.detach();
}

void fanCleanup()
{
    closesocket(ctx.sock);
    WSACleanup();
    // guess we should also kill worker threads here, but whatever, we're exiting...
}

void fanResyncIfNeeded()
{
    // If more than some time has passed since we last sent a HELLO, do it again.
    // I don't know what the fan's actual timeout is here, this is by trial-and-error.

    DWORD msecSinceLastSync = GetTickCount() - ctx.lastHelloLocalTimestampMs;

    if( msecSinceLastSync < 5 * 60 * 1000 )
        return;

    if( syncCmdHelloHandshake()==false )
        ctx.log( "Fan re-sync failed." );
    else
        ctx.log( "Re-synced to fan." );
}

bool fanGetEnabled()
{
    const int id = ++ctx.cmdId;
    std::string cmd = R"({"id": )" + std::to_string(id) + R"(, "method": "get_properties", "params": [{"did": "2-1", "siid": 2, "piid": 1}]})";
    std::string res = syncCmdExecute( cmd );
    nlohmann::json resobj = nlohmann::json::parse( res );
    bool val = resobj["result"][0]["value"];
    return val;
}

void fanSetEnabled( bool enabled )
{
    AsyncCommand cmd;
    cmd.type = AsyncCommand::CMD_SET_POWER;
    cmd.value = (int)enabled;
    asyncCmdEnqueue( cmd );
}

int fanGetSpeed()
{
    const int id = ++ctx.cmdId;
    std::string cmd = R"({"id": )" + std::to_string(id) + R"(, "method": "get_properties", "params": [{"did": "2-10", "siid": 2, "piid": 10}]})";
    std::string res = syncCmdExecute( cmd );
    nlohmann::json resobj = nlohmann::json::parse( res );
    int val = resobj["result"][0]["value"];
    return val;
}

void fanSetSpeed( int speed )
{
    AsyncCommand cmd;
    cmd.type = AsyncCommand::CMD_SET_SPEED;
    cmd.value = speed;
    asyncCmdEnqueue( cmd );
}
