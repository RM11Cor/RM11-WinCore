package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

public final class WineNativeProcessActivityV489Test {
    @Test public void recognizesNativeWineFromExecutableSymlinkWhenArgvRenamed(){
        assertEquals("WINE_CLIENT",WineNativeProcessActivityV489.category(
            "CarX Street Launcher.exe\0","game-runtime",
            "/data/app/lib/arm64/libwineprobe.so"));
        assertEquals("WINE_CLIENT",WineNativeProcessActivityV489.category(
            "no-wine-argv\0","libwineprobe.so",""));
        assertEquals("WINE_SERVER",WineNativeProcessActivityV489.category(
            "no-server-argv\0","wineserver",""));
        assertEquals("UNKNOWN_APP_PROCESS",WineNativeProcessActivityV489.category(
            "random-service\0","surfaceflinger","/system/bin/app_process64"));
    }
    @Test public void numericPidFilterIsBounded() {
        assertTrue(WineNativeProcessActivityV489.numericPid("123"));
        assertFalse(WineNativeProcessActivityV489.numericPid("self"));
        assertFalse(WineNativeProcessActivityV489.numericPid("task"));
    }
}
