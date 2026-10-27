package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

public final class WineFirstExceptionEvidenceTest {
    @Test public void capturesFirstAndFatalEvenWhenTailHasRolled() {
        WineFirstExceptionEvidence report=new WineFirstExceptionEvidence();
        report.accept("before one\nbefore two\n");
        report.accept("0024:trace:seh:dispatch_exception code=c0000005 rip=0x1234\n");
        report.accept("trace register line 1\ntrace register line 2\n");
        for(int i=0;i<20000;i++)
            report.accept("noise line that should not overwrite critical messages\n");
        report.accept("0024:err:seh:call_seh_handlers invalid frame 1000fda60\n");
        report.accept("0024:err:seh:NtRaiseException Exception frame is not in stack limits\n");
        String s=report.snapshot();
        assertTrue(s.contains("RM11_V462_SEH_FIRST_EVENT_SEEN=true"));
        assertTrue(s.contains("RM11_V462_SEH_FATAL_EVENT_SEEN=true"));
        assertTrue(s.contains("dispatch_exception code=c0000005"));
        assertTrue(s.contains("invalid frame 1000fda60"));
        assertTrue(s.length()<8000);
    }
    @Test public void capturesFatalInstructionPointerWhenLineIsSplit() {
        WineFirstExceptionEvidence capture=new WineFirstExceptionEvidence();
        capture.accept("Unhandled exception: page fault on read access to 0x0000000000000070 ");
        capture.accept("in 64-bit code (0x00006ffeb1d0d0).\n");
        assertEquals("00006ffeb1d0d0",capture.fatalPcHex());
        assertTrue(capture.snapshot().contains("RM11_V468_FATAL_PC=00006ffeb1d0d0"));
    }
    @Test public void ignoresBenignThreadNamingAndCapturesFirstActionableFaultAndLR() {
        WineFirstExceptionEvidence evidence=new WineFirstExceptionEvidence();
        evidence.accept("016c:trace:seh:dispatch_exception code=406d1388 (EXCEPTION_WINE_NAME_THREAD)\n");
        evidence.accept("00a8:trace:seh:dispatch_exception code=c0000005 (EXCEPTION_ACCESS_VIOLATION)\n");
        evidence.accept("Unhandled exception: page fault on read access to 0x0000000000000070 "
                +"in 64-bit code (0x00006ffeb1d0d0).\n");
        evidence.accept(" Pc:0000006ffeb1d0d0 Sp:000000000010e9f0 "
                +"Lr:0000006ff885c084 Cpsr:20000000\n");
        String snapshot=evidence.snapshot();
        assertTrue(snapshot.contains("RM11_V470_ACTIONABLE_EXCEPTION_SEEN=true"));
        assertTrue(snapshot.contains("FIRST_ACTIONABLE_WINE_EXCEPTION:"));
        assertTrue(snapshot.contains("dispatch_exception code=c0000005"));
        assertEquals("00006ff885c084",evidence.fatalLrHex());
        assertTrue(snapshot.contains("RM11_V470_FATAL_LR=00006ff885c084"));
    }
    @Test public void partialChunksAndNoEventsStayBounded() {
        WineFirstExceptionEvidence report=new WineFirstExceptionEvidence();
        report.accept("0024:trace:seh:dispatch_exception ");
        report.accept("code=e0420611\n");
        String s=report.snapshot();
        assertTrue(s.contains("code=e0420611"));
        assertFalse(s.contains("RM11_V462_SEH_FATAL_EVENT_SEEN=true"));
        for(int i=0;i<5000;i++)report.accept("a");
        assertTrue(report.snapshot().length()<8000);
    }
}
