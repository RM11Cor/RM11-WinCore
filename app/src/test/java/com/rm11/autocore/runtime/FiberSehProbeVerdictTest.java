package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

public final class FiberSehProbeVerdictTest {
    private static final String PASS="RM11_V461_FIBER_PROBE_STARTED=x64\n"
            +"RM11_V461_FIBER_SWITCH_ENTERED=YES\n"
            +"RM11_V461_FIBER_SEH_HANDLER_REACHED=YES\n"
            +"RM11_V461_FIBER_SEH_PASS=YES\n";
    @Test public void requiresAllMilestonesAndSuccessExit(){
        assertTrue(FiberSehProbeVerdict.passed(true,0,PASS));
        assertFalse(FiberSehProbeVerdict.passed(false,0,PASS));
        assertFalse(FiberSehProbeVerdict.passed(true,3,PASS));
        assertFalse(FiberSehProbeVerdict.passed(true,0,PASS.replace(
                "RM11_V461_FIBER_SWITCH_ENTERED=YES","MISSING")));
    }
    @Test public void nativeWineInvalidStackRejectsPass() {
        assertFalse(FiberSehProbeVerdict.passed(true,0,PASS+"err:seh:call_seh_handlers invalid frame"));
    }
}
