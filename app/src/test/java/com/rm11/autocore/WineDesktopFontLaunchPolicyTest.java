package com.rm11.autocore;

import org.junit.Test;
import static org.junit.Assert.*;

public final class WineDesktopFontLaunchPolicyTest {
    @Test public void onlyVerifiedAndroidGlyphCanOptInOnFirstAttempt() {
        assertTrue(WineDesktopFontLaunchPolicy.enableForWinefile(true,false,1));
        assertFalse(WineDesktopFontLaunchPolicy.enableForWinefile(false,false,1));
        assertFalse(WineDesktopFontLaunchPolicy.enableForWinefile(true,true,1));
        assertFalse(WineDesktopFontLaunchPolicy.enableForWinefile(true,false,2));
        assertFalse(WineDesktopFontLaunchPolicy.enableForWinefile(true,false,0));
    }

    @Test public void unexpectedEarlyNonZeroExitGetsOnlyOneBoundedRetry() {
        assertTrue(WineDesktopFontLaunchPolicy.retryAfterEarlyWinefileFailure(
                false,1,127,400));
        assertTrue(WineDesktopFontLaunchPolicy.retryAfterEarlyWinefileFailure(
                false,1,1,14999));
        assertFalse(WineDesktopFontLaunchPolicy.retryAfterEarlyWinefileFailure(
                false,1,0,450));
        assertFalse(WineDesktopFontLaunchPolicy.retryAfterEarlyWinefileFailure(
                false,2,127,1));
        assertFalse(WineDesktopFontLaunchPolicy.retryAfterEarlyWinefileFailure(
                true,1,127,1));
        assertFalse(WineDesktopFontLaunchPolicy.retryAfterEarlyWinefileFailure(
                false,1,127,15000));
        assertFalse(WineDesktopFontLaunchPolicy.retryAfterEarlyWinefileFailure(
                false,1,127,-1));
    }
}
