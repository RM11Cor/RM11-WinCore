package com.rm11.autocore;

import org.junit.Test;
import static org.junit.Assert.*;

public final class RuntimePrerequisitesTest {
    @Test public void noNativeHostMeansBlocked() {
        assertFalse(RuntimePrerequisites.allVerified(false, true, true, true, true));
    }
    @Test public void noTranslatorMeansBlocked() {
        assertFalse(RuntimePrerequisites.allVerified(true, false, true, true, true));
    }
    @Test public void noWineMeansBlocked() {
        assertFalse(RuntimePrerequisites.allVerified(true, true, false, true, true));
    }
    @Test public void noGraphicsMeansBlocked() {
        assertFalse(RuntimePrerequisites.allVerified(true, true, true, false, true));
    }
    @Test public void noGameMappingMeansBlocked() {
        assertFalse(RuntimePrerequisites.allVerified(true, true, true, true, false));
    }
    @Test public void allReportedPrerequisitesAllowNextStageOnly() {
        assertTrue(RuntimePrerequisites.allVerified(true, true, true, true, true));
    }
}
