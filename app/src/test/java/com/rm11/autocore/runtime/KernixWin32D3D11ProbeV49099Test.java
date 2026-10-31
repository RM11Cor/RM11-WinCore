package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

/** Regression: a recompiled CI Win64 probe may have a new SHA and must
 * never collide with the previous APK's isolated probe executable. */
public final class KernixWin32D3D11ProbeV49099Test {
    private static String repeat(char c) {
        StringBuilder out=new StringBuilder();
        for(int i=0;i<64;i++)out.append(c);
        return out.toString();
    }
    @Test public void versionedProbePathsNeverCollideAcrossBuilds() {
        String old=KernixWin32D3D11ProbeV49097.versionedFolder(repeat('a'));
        String fresh=KernixWin32D3D11ProbeV49097.versionedFolder(repeat('b'));
        assertEquals("sha256-"+repeat('a').substring(0,24),old);
        assertNotEquals(old,fresh);
        assertEquals(old,KernixWin32D3D11ProbeV49097.versionedFolder(repeat('a')));
    }
    @Test public void versionedProbeRejectsUntrustedHashes() {
        try{
            KernixWin32D3D11ProbeV49097.versionedFolder("../../not-a-hash");
            fail("path traversal accepted");
        }catch(IllegalStateException expected){
            assertEquals("PROBE_INVALID_SHA256",expected.getMessage());
        }
    }
    @Test public void errorTelemetryIsBoundedToKnownStageNames() {
        assertEquals("PROBE_NAME_OCCUPIED_NOT_OVERWRITTEN",
            KernixWin32D3D11ProbeV49097.failureCode(
                new IllegalStateException("PROBE_NAME_OCCUPIED_NOT_OVERWRITTEN")));
        assertEquals("WINE_C_DRIVE_NOT_PREPARED",
            KernixWin32D3D11ProbeV49097.failureCode(
                new IllegalStateException("WINE_C_DRIVE_NOT_PREPARED")));
        assertEquals("UNKNOWN_STAGE_ERROR",
            KernixWin32D3D11ProbeV49097.failureCode(
                new IllegalStateException("/data/user/0/private/path")));
    }
}
