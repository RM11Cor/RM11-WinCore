package com.rm11.autocore.runtime;
import org.junit.Test;
import static org.junit.Assert.*;

public final class GameExecutableMapSnapshotTest {
    @Test public void resolvesNativeFaultPCWithoutLeakingFullPrivatePath() {
        GameExecutableMapSnapshot maps=new GameExecutableMapSnapshot();
        maps.acceptLine("78a3a96000-78a3aa0000 r-xp 00001000 00:31 123 /data/user/0/private/fex/libfexsample.so");
        String evidence=maps.resolve("00000078a3a9728c");
        assertTrue(evidence.contains("RM11_V463_ASSERT_RIP_RESOLUTION=MAPPED"));
        assertTrue(evidence.contains("RM11_V463_ASSERT_RIP_IMAGE=libfexsample.so"));
        assertTrue(evidence.contains("RM11_V463_ASSERT_RIP_MODULE_OFFSET=0x228c"));
        assertFalse(evidence.contains("/data/user/"));
    }
    @Test public void resolvesNamelessExecutableWithBoundedNeighbors() {
        GameExecutableMapSnapshot maps=new GameExecutableMapSnapshot();
        maps.acceptLine("6ffeb00000-6ffeb10000 r-xp 00000000 00:00 0 /data/private/wine/user32.dll");
        maps.acceptLine("6ffeb10000-6ffeb20000 r-xp 00000000 00:00 0");
        maps.acceptLine("6ffeb30000-6ffeb40000 r-xp 00000000 00:00 0 /data/private/wine/UnityPlayer.dll");
        String s=maps.nearbyExecutableRegions("0000006ffeb1d0d0");
        assertTrue(s.contains("RM11_V469_PC_STATUS=MAPPED"));
        assertTrue(s.contains("RM11_V469_MATCH_MODULE=ANONYMOUS_EXECUTABLE"));
        assertTrue(s.contains("RM11_V469_MATCH_OFFSET_IN_REGION=0xd0d0"));
        assertTrue(s.contains("RM11_V469_PREVIOUS_EXEC_ONLY_MODULE=user32.dll"));
        assertTrue(s.contains("RM11_V469_NEXT_EXEC_ONLY_MODULE=UnityPlayer.dll"));
        assertTrue(s.contains("RM11_V469_MATCH_ANONYMOUS=true"));
        assertFalse(s.contains("/data/private"));
        assertFalse(s.contains("FEX_JIT_CONFIRMED"));
    }
    @Test public void distinguishesInvalidOrUnmappedPC() {
        GameExecutableMapSnapshot maps=new GameExecutableMapSnapshot();
        maps.acceptLine("78a3a96000-78a3aa0000 rw-p 00001000 00:31 123 /data/secret/libfake.so");
        assertTrue(maps.resolve("00000078a3a9728c").contains("UNMAPPED_OR_NOT_SAMPLED"));
        assertTrue(maps.resolve("UNKNOWN").contains("NO_PC"));
    }
}
