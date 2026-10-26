package com.rm11.autocore.runtime;
import static org.junit.Assert.*;
import org.junit.Test;
public final class SehProbeVerdictTest {
    private static final String OK="RM11_V460_SEH_PROBE_STARTED=x64\n"
            +"RM11_V460_SEH_HANDLER_REACHED=YES\n"
            +"RM11_V460_SEH_PROBE_PASS=YES\n";
    @Test public void successfulHandlerAndZeroExitAreRequired() {
        assertTrue(SehProbeVerdict.passed(true,0,OK));
        assertFalse(SehProbeVerdict.passed(false,0,OK));
        assertFalse(SehProbeVerdict.passed(true,1,OK));
        assertFalse(SehProbeVerdict.passed(true,0,
                "RM11_V460_SEH_PROBE_STARTED=x64\n"));
    }
    @Test public void invalidFrameIsNeverReportedAsSuccess() {
        assertFalse(SehProbeVerdict.passed(true,0,
                OK+"err:seh:call_seh_handlers invalid frame"));
        assertFalse(SehProbeVerdict.passed(true,0,
                OK+"Exception frame is not in stack limits"));
        assertFalse(SehProbeVerdict.passed(true,0,null));
    }
}
