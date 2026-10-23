package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

public final class WineCrashEvidenceTest {
    @Test public void reportsCrashAtEndBeforeJournalTruncation() {
        StringBuilder log = new StringBuilder();
        for(int i=0;i<2500;i++)log.append("0024:trace:loaddll:loaded module xxxxxxxxxx\n");
        log.append("wine: failed to update prefix, wine.inf not found\n");
        log.append("0024:warn:seh:dispatch_exception code=c0000005 flags=0\n");
        String extracted=WineCrashEvidence.summarize(log.toString(),5,true);
        assertTrue(extracted.contains("Client exit: 5"));
        assertTrue(extracted.contains("Wineboot missing wine.inf warning: OBSERVED"));
        assertTrue(extracted.contains("dispatch_exception code=c0000005"));
        assertTrue(extracted.contains("Terminal Wine log excerpt:"));
        assertTrue("keep result within 11kb event limit",extracted.length()<11000);
    }
    @Test public void doesNotClaimWindowJustBecauseMessageBoxCallStarted() {
        String result=WineCrashEvidence.summarize(
                "RM11_V284_MESSAGEBOXW_CALL_BEGIN\n",5,true);
        assertTrue(result.contains("entry marker: CAPTURED"));
        assertTrue(result.contains("return marker: NOT_CAPTURED"));
        assertTrue(result.contains("Native winex11.so initialization: NOT_DIRECTLY_PROVEN"));
        assertFalse(result.contains("WIN32_GUI_VERIFIED"));
    }
    @Test public void doesNotMislabelTimeoutAsExited() {
        String s=WineCrashEvidence.summarize("",-1,false);
        assertTrue(s.contains("Client exit: TIMEOUT_NOT_EXITED"));
        assertTrue(s.contains("NO_MATCHES_IN_BOUNDED_CAPTURE"));
    }
}
