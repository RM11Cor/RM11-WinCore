package com.rm11.autocore.runtime;
import org.junit.Test;
import static org.junit.Assert.*;

public final class WineAssertionEvidenceTest {
    @Test public void ignoresBenignThreadNameThenCapturesFirstWineAssertion() {
        WineAssertionEvidence a=new WineAssertionEvidence();
        a.accept("016c:trace:seh:dispatch_exception code=406d1388 (EXCEPTION_WINE_NAME_THREAD) flags=0\n");
        a.accept("native assertion: relevant detail\n");
        a.accept("009c:trace:seh:dispatch_exception code=80000101 flags=1\n");
        a.accept("009c:trace:seh:dispatch_exception rip=00000078a3a9728c rsp=00000001000fda60\n");
        a.accept("009c:err:seh:call_seh_handlers invalid frame 1000fda60\n");
        for(int i=0;i<25000;i++)a.accept("RtlInitializeExtendedContext2 noise noise noise\n");
        String report=a.snapshot();
        assertTrue(report.contains("RM11_V463_ASSERTION_SEEN=true"));
        assertTrue(report.contains("RM11_V463_ASSERTION_THREAD=009c"));
        assertTrue(report.contains("RM11_V463_ASSERTION_RIP=00000078a3a9728c"));
        assertTrue(report.contains("code=80000101"));
        assertTrue(report.contains("native assertion: relevant detail"));
        assertFalse(report.contains("RM11_V463_ASSERTION_THREAD=016c"));
        assertTrue(report.length()<7200);
    }
    @Test public void handlesSplitLinesAndNoAssertion() {
        WineAssertionEvidence a=new WineAssertionEvidence();
        a.accept("009c:trace:seh:dispatch_exception code=406d1388\n");
        assertFalse(a.snapshot().contains("RM11_V463_ASSERTION_SEEN=true"));
        a.accept("009c:trace:seh:dispatch_exception code=80000");
        a.accept("101 flags=1\n");
        assertTrue(a.snapshot().contains("RM11_V463_ASSERTION_SEEN=true"));
        assertEquals("UNKNOWN",a.pcHex());
    }
}
