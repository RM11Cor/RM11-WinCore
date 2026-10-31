package com.rm11.autocore.runtime;

import static org.junit.Assert.assertEquals;
import org.junit.Test;

public final class R4GameLaunchProfileV49068Test {
    @Test public void normalGamesDefaultToOriginalExe(){
        assertEquals("DIRECT",R4GameLaunchProfileV49068.effectiveMode(null,false));
        assertEquals("DIRECT",R4GameLaunchProfileV49068.effectiveMode("INVALID",false));
    }
    @Test public void legacyModeSelectable(){
        assertEquals("LEGACY",R4GameLaunchProfileV49068.effectiveMode("LEGACY",false));
    }
    @Test public void carxDoesNotForceLegacy(){
        assertEquals("DIRECT",R4GameLaunchProfileV49068.effectiveMode("DIRECT",true));
    }
}
