
#include "MyPlugin.h"
#include <StreamDeckSDK/ESDMain.h>
#include <Windows.h>
#include <time.h>
#include "fanctrl.h"
#include "util.h"

static FILE* g_logfile = 0;

void log( const char* format, ... )
{
    char s[512];
    va_list argptr;
    va_start(argptr, format);
    vsnprintf( s, sizeof(s), format, argptr);
    va_end(argptr);

    if( !g_logfile )
    {
        std::string filename = getExeFileLocation() + "\\fanlog.txt";
        g_logfile = fopen( filename.c_str(), "w" );
    }

    time_t tim = time(0);
    char timstr[64];
    strftime( timstr, sizeof(timstr), "%F %T", localtime(&tim) );
    fprintf( g_logfile, "[%s] %s\n", timstr, s );
    fflush( g_logfile );
}

int main(int argc, const char** argv)
{
    fanInit( log );

    auto plugin = std::make_unique<MyPlugin>();
    int ret = esd_main(argc, argv, plugin.get());

    fanCleanup();

    if( g_logfile )
        fclose( g_logfile );

    return ret;
}
