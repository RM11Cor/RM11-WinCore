package com.rm11.autocore;

import org.junit.Test;
import static org.junit.Assert.*;

public final class WineDesktopRecoveryPolicyTest {
    @Test public void firstUnexpectedServerFailureMayRecover() {
        assertTrue(WineDesktopRecoveryPolicy.mayRestartAfterServerDeath(false,1));
    }
    @Test public void laterFailureCannotLoopForever() {
        assertFalse(WineDesktopRecoveryPolicy.mayRestartAfterServerDeath(false,2));
        assertFalse(WineDesktopRecoveryPolicy.mayRestartAfterServerDeath(false,3));
        assertFalse(WineDesktopRecoveryPolicy.mayRestartAfterServerDeath(false,0));
    }
    @Test public void androidCloseSuppressesRecoveryEvenOnFirstFailure() {
        assertFalse(WineDesktopRecoveryPolicy.mayRestartAfterServerDeath(true,1));
    }
}
