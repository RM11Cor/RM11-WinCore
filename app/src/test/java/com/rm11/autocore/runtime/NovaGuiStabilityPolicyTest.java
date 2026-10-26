package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

public final class NovaGuiStabilityPolicyTest {
    @Test public void winefileMustNotAutostartPatchedFontClient(){
        assertFalse(NovaGuiStabilityPolicy.allowAutomaticWinefileFontClient());
    }
    @Test public void isolatedWinefileRetestIsAlsoSuspended(){
        assertFalse(NovaGuiStabilityPolicy.allowStandaloneWinefileFontTest());
    }
    @Test public void repeatedGuiProbeMustNotReintroduceUnverifiedFontHook(){
        assertFalse(NovaGuiStabilityPolicy.allowManualExeFontProbe());
    }
    @Test public void manualFontProbeNeedsExplicitStableTrustedContext(){
        assertTrue(NovaGuiStabilityPolicy.allowManualExeFontProbe(true,true,true));
        assertFalse(NovaGuiStabilityPolicy.allowManualExeFontProbe(false,true,true));
        assertFalse(NovaGuiStabilityPolicy.allowManualExeFontProbe(true,false,true));
        assertFalse(NovaGuiStabilityPolicy.allowManualExeFontProbe(true,true,false));
        assertFalse(NovaGuiStabilityPolicy.allowManualExeFontProbe(false,false,false));
    }
    @Test public void doNotClaimRootCause(){
        assertTrue(NovaGuiStabilityPolicy.summary()
                .contains("RM11_V439_FONT_ROOT_CAUSE_NOT_YET_VERIFIED=true"));
    }
}
