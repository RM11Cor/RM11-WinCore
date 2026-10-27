package com.rm11.autocore.runtime;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

public final class X11VulkanTouchStabilityVerdictTest {
    @Test public void successNeedsLiveSwapchainForFullHold() {
        String log="RM11_V477_VK_QUEUE_PRESENT_RESULT=0\n"
                +"RM11_V477_SWAPCHAIN_HELD_THROUGH_VISIBLE_PERIOD=YES\n"
                +"RM11_V477_SWAPCHAIN_VISIBLE_HOLD_COMPLETE=YES\n"
                +"RM11_V477_PROCESS_COMPLETED=0\n";
        assertEquals("LIVE_SWAPCHAIN_HELD_FOR_DISPLAY_TOUCH_RESULT_USER_UNVERIFIED",
                X11VulkanTouchStabilityVerdict.classify(log));
        assertEquals("FRAME_SUBMITTED_SWAPCHAIN_LIFETIME_UNVERIFIED",
                X11VulkanTouchStabilityVerdict.classify(
                    "RM11_V477_PRESENT_STATUS=MAGENTA_FRAME_SUBMITTED_VIA_XLIB\n"));
        assertEquals("EMPTY_OR_NATIVE_ABORT",
                X11VulkanTouchStabilityVerdict.classify(null));
    }
}
