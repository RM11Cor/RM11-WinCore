package com.rm11.autocore;

import org.junit.Test;
import static org.junit.Assert.*;

public final class WineShellStartupPolicyTest {
    private static final String EMPTY =
        "RM11_V410_X11_ROOT_WINDOW_QUERY_OK\n"
        + "x11_children_viewable=0\nx11_attribute_errors=0\n";
    @Test public void startsBundledWinefileOnlyAfterVerifiedEmptyDesktop() {
        assertFalse(WineShellStartupPolicy.shouldLaunchFileManager(EMPTY,7000,3,false));
        assertFalse(WineShellStartupPolicy.shouldLaunchFileManager(EMPTY,10000,1,false));
        assertTrue(WineShellStartupPolicy.shouldLaunchFileManager(EMPTY,10000,2,false));
    }
    @Test public void neverStartTwiceOrWhenX11HasVisibleWindows() {
        assertFalse(WineShellStartupPolicy.shouldLaunchFileManager(EMPTY,12000,3,true));
        assertFalse(WineShellStartupPolicy.shouldLaunchFileManager(
            EMPTY.replace("viewable=0\n","viewable=1\n"),12000,3,false));
    }
    @Test public void neverGuessFromBrokenX11OrAttributeErrors() {
        assertFalse(WineShellStartupPolicy.shouldLaunchFileManager(
            "RM11_V410_X11_WINDOW_QUERY_FAILED=timeout",12000,3,false));
        assertFalse(WineShellStartupPolicy.shouldLaunchFileManager(
            EMPTY.replace("attribute_errors=0\n","attribute_errors=1\n"),12000,3,false));
    }
}
