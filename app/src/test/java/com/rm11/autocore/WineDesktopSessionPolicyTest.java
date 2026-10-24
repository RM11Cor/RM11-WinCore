package com.rm11.autocore;

import org.junit.Test;
import static org.junit.Assert.*;

/** Regression for the on-device v3.0.3 Explorer exit 0 killing Wine desktop. */
public final class WineDesktopSessionPolicyTest {
    @Test public void explorerNormalExitDoesNotCloseWineDesktop() {
        assertEquals(WineDesktopSessionPolicy.Decision.KEEP_RUNNING,
                WineDesktopSessionPolicy.decide(false,true,false,true));
    }
    @Test public void bothBootstrapHelpersCanFinishWhileServerIsAlive() {
        assertEquals(WineDesktopSessionPolicy.Decision.KEEP_RUNNING,
                WineDesktopSessionPolicy.decide(false,true,false,false));
    }
    @Test public void allChildrenAliveKeepDesktop() {
        assertEquals(WineDesktopSessionPolicy.Decision.KEEP_RUNNING,
                WineDesktopSessionPolicy.decide(false,true,true,true));
    }
    @Test public void deadWineServerClosesSessionEvenWithAliveHelpers() {
        assertEquals(WineDesktopSessionPolicy.Decision.SERVER_STOPPED,
                WineDesktopSessionPolicy.decide(false,false,true,true));
    }
    @Test public void explicitActivityCloseAlwaysWins() {
        assertEquals(WineDesktopSessionPolicy.Decision.CLOSE_REQUESTED,
                WineDesktopSessionPolicy.decide(true,true,true,true));
        assertEquals(WineDesktopSessionPolicy.Decision.CLOSE_REQUESTED,
                WineDesktopSessionPolicy.decide(true,false,false,false));
    }
}
