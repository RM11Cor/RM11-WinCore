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
    @Test public void distinguishesInvalidOrUnmappedPC() {
        GameExecutableMapSnapshot maps=new GameExecutableMapSnapshot();
        maps.acceptLine("78a3a96000-78a3aa0000 rw-p 00001000 00:31 123 /data/secret/libfake.so");
        assertTrue(maps.resolve("00000078a3a9728c").contains("UNMAPPED_OR_NOT_SAMPLED"));
        assertTrue(maps.resolve("UNKNOWN").contains("NO_PC"));
    }
}
