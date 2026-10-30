package com.rm11.autocore;

import org.junit.Test;
import static org.junit.Assert.*;

public final class RM11ControllerVisibilityV49042Test {
    @Test public void hidesWhenControllerConnectsAndRestoresOnRemoval(){
        assertTrue(RM11ControllerVisibilityV49042.shouldShowTouch(true,false));
        assertFalse(RM11ControllerVisibilityV49042.shouldShowTouch(true,true));
        assertTrue(RM11ControllerVisibilityV49042.shouldShowTouch(true,false));
    }
    @Test public void manualHideStaysHiddenWhenControllerDisconnects(){
        assertFalse(RM11ControllerVisibilityV49042.shouldShowTouch(false,true));
        assertFalse(RM11ControllerVisibilityV49042.shouldShowTouch(false,false));
    }
}
