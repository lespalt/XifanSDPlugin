

taskkill /F /T /IM StreamDeck.exe
xcopy /Y %1 com.xifansdplugin.sdPlugin
xcopy /Y com.xifansdplugin.sdPlugin "%appdata%\Elgato\StreamDeck\Plugins\com.xifansdplugin.sdPlugin"
