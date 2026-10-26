package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

public final class NovaWineSessionStateTest {
    @Test public void requiresHealthyDesktop() {
        NovaWineSessionState s=new NovaWineSessionState();
        assertFalse(s.canLaunchExe());
        s.markWinefileReady(true);
        assertTrue(s.canLaunchExe());
        s.markWinefileReady(false);
        assertFalse(s.canLaunchExe());
    }

    @Test public void crashPermanentlyBlocksSameSessionEvenAfterRecovery() {
        NovaWineSessionState s=new NovaWineSessionState();
        s.markWinefileReady(true);
        s.markServerCrashed(1);
        s.markWinefileReady(true);
        assertFalse(s.canLaunchExe());
        assertTrue(s.hasServerCrashed());
        assertEquals(1,s.serverExitCode());
        assertTrue(s.diagnostic().contains("RM11_V441_DIRECT_EXE_ALLOWED=false"));
    }

    @Test public void freshSessionCanStartWithoutEditingPersistentPrefix() {
        NovaWineSessionState first=new NovaWineSessionState();
        first.markServerCrashed(1);
        NovaWineSessionState next=new NovaWineSessionState();
        next.markWinefileReady(true);
        assertFalse(first.canLaunchExe());
        assertTrue(next.canLaunchExe());
    }
}
