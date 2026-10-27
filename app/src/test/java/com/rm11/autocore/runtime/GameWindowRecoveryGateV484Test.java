package com.rm11.autocore.runtime;

import static org.junit.Assert.*;
import org.junit.Test;
public final class GameWindowRecoveryGateV484Test {
    @Test public void noNoguiProcessDependencyAfterV483DeviceRegression(){
        assertTrue(GameWindowRecoveryGateV484.recovery(
                25000,2,true,true,false,12,12));
        assertFalse(GameWindowRecoveryGateV484.recovery(
                25000,1,true,true,false,12,12));
        assertFalse(GameWindowRecoveryGateV484.recovery(
                25000,2,true,true,false,0,0));
        assertFalse(GameWindowRecoveryGateV484.recovery(
                25000,2,true,true,true,12,12));
        assertFalse(GameWindowRecoveryGateV484.recovery(
                25000,2,true,false,false,12,12));
        assertFalse(GameWindowRecoveryGateV484.recovery(
                10000,2,true,true,false,12,12));
    }
    @Test public void alwaysCollectIndependentReadOnlyInventory() {
        assertTrue(GameWindowRecoveryGateV484.inventory(20500,-1,true,true));
        assertTrue(GameWindowRecoveryGateV484.inventory(40100,1,true,true));
        assertFalse(GameWindowRecoveryGateV484.inventory(40500,2,true,true));
        assertFalse(GameWindowRecoveryGateV484.inventory(20500,1,true,true));
        assertEquals(12,GameWindowRecoveryGateV484.nonnegativeCount(
            "x11_root_children=12\nx11_children_unmapped=12\n","x11_children_unmapped="));
        assertEquals(-1,GameWindowRecoveryGateV484.nonnegativeCount(
            "x11_unavailable\n","x11_children_unmapped="));
    }
}
