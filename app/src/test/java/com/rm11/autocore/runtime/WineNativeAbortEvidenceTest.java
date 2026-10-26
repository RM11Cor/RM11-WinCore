package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

public final class WineNativeAbortEvidenceTest {
    @Test public void capturesSplitCallerAndRetainsItDespiteHugeWineTrace() {
        WineNativeAbortEvidence collector=new WineNativeAbortEvidence();
        collector.accept("other\nRM11_V465_NATIVE_ABORT_CALLER_SEEN=tr");
        collector.accept("ue\nRM11_V465_NATIVE_ABORT_CALLER_IMAGE=libfexhost.so\n");
        collector.accept("RM11_V465_NATIVE_ABORT_CALLER_ELF_OFFSET=0xabc123\n");
        for(int i=0;i<30000;i++)collector.accept("Wine RtlInitializeExtendedContext2 noise\n");
        String out=collector.snapshot();
        assertTrue(out.contains("RM11_V465_NATIVE_ABORT_CALLER_SEEN=true"));
        assertTrue(out.contains("RM11_V465_NATIVE_ABORT_CALLER_IMAGE=libfexhost.so"));
        assertTrue(out.contains("RM11_V465_NATIVE_ABORT_CALLER_ELF_OFFSET=0xabc123"));
        assertTrue(out.length()<400);
    }
    @Test public void malformedImagePathNotPublished() {
        WineNativeAbortEvidence collector=new WineNativeAbortEvidence();
        collector.accept("RM11_V465_NATIVE_ABORT_CALLER_IMAGE=/data/private/secret.so\n");
        assertTrue(collector.snapshot().contains("RM11_V465_NATIVE_ABORT_CALLER_IMAGE=UNKNOWN"));
        assertTrue(collector.snapshot().contains("RM11_V465_NATIVE_ABORT_CALLER_SEEN=false"));
    }
}
