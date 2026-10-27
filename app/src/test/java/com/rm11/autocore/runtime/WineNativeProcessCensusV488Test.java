package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

public final class WineNativeProcessCensusV488Test {
    @Test public void parsesOnlyRealUidField() {
        assertEquals(10353,WineNativeProcessCensusV488.realUid(
            "Name:\twine\nUid:\t10353\t10353\t10353\t10353\nGid:\t10353\n"));
        assertEquals(-1,WineNativeProcessCensusV488.realUid("Gid:\t10353\n"));
        assertEquals(-1,WineNativeProcessCensusV488.realUid("Uid:\tredacted\n"));
    }
    @Test public void identifiesExactNativeWineEntrypointWithoutLeakingPaths(){
        assertEquals("WINE_LOADER",WineNativeProcessCensusV488.role(
                "/data/app/x/lib/arm64/libwineprobe.so\0D:/CarX Launcher.exe\0"));
        assertEquals("SERVER",WineNativeProcessCensusV488.role(
                "/data/app/x/lib/arm64/libwineserverrm11.so\0"));
        assertEquals("OTHER_SAME_UID",WineNativeProcessCensusV488.role(
                "/system/bin/app_process64\0"));
        assertEquals("UNKNOWN",WineNativeProcessCensusV488.role(null));
    }
}
