
#include "MyPlugin.h"
#include <StreamDeckSDK/ESDMain.h>
#include <Windows.h>
#include "fanctrl.h"
#include "util.h"

static FILE* g_logfile = 0;

void log( const char* msg )
{
    if( !g_logfile )
    {
        std::string filename = getExeFileLocation() + "\\fanlog.txt";
        g_logfile = fopen( filename.c_str(), "w" );
    }

    fprintf( g_logfile, "%s\n", msg );
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
