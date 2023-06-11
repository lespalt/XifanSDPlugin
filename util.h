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


#pragma once

#include <Windows.h>
#include <string>
#include "md5.h"

typedef std::vector<unsigned char> ByteVec;

inline int hexchar2int( char c )
{
    if( c >= '0' && c <= '9' )
        return c - '0';
    else if( c >= 'a' && c <= 'f' )
        return c - 'a' + 10;
    assert(false);
    return 0;
}

inline ByteVec hexstr2bytes( const std::string& s )
{
    assert( (s.length() % 2) == 0 );

    ByteVec ret( s.length() / 2 );
    for( int i=0; i<(int)ret.size(); ++i )
    {
        char upper = s[i*2];
        char lower = s[i*2+1];
        int x = hexchar2int(upper) * 16 + hexchar2int(lower);
        ret[i] = (unsigned char)(x);
    }
    return ret;
}

inline std::string bytes2hexstr( const ByteVec& data )
{
    std::string ret;
    for( int i=0; i<(int)data.size(); ++i )
    {
        char s[3];
        sprintf( s, "%02x", (int)data[i] );
        ret += s;
    }
    return ret;
}

inline std::string bytes2str( const ByteVec& data )
{
    std::string s;
    s.assign( (const char*)data.data(), data.size() );
    return s;
}

inline ByteVec str2bytes( const std::string& s )
{
    ByteVec ret;
    ret.assign( s.begin(), s.end() );
    return ret;
}

inline ByteVec cstr2bytes( const std::string& s )
{
    ByteVec ret = str2bytes( s );
    ret.push_back( 0 );
    return ret;
}

inline ByteVec concat( const ByteVec& a, const ByteVec& b )
{
    ByteVec r = a;
    r.insert( r.end(), b.begin(), b.end() );
    return r;
}

inline ByteVec md5( const ByteVec& data )
{
    MD5_CTX ctx;
    MD5Init( &ctx );
    MD5Update(&ctx,(unsigned char*)data.data(),(int)data.size());
    ByteVec digest(16);
    MD5Final(digest.data(),&ctx);
    return digest;
}

inline std::string getExeFileLocation()
{
    char s[1024];
    GetModuleFileNameA( 0, s, sizeof(s) );
    std::string ret = s;
    ret.erase( ret.find_last_of( '\\' ) );
    return ret;
}
