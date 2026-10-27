package com.rm11.autocore.runtime;

/** Visual proof is user-reported. Native queue success alone is not evidence
 * that a pixel survived touch-induced X11 damage. */
public final class X11VulkanTouchStabilityVerdict {
    private X11VulkanTouchStabilityVerdict(){}
    public static String classify(String s) {
        if(s==null||s.isEmpty())return "EMPTY_OR_NATIVE_ABORT";
        if(s.contains("RM11_V477_VK_CREATE_SWAPCHAIN_RESULT=-3"))
            return "SWAPCHAIN_CREATION_FAILED";
        if(s.contains("RM11_V477_VK_QUEUE_PRESENT_RESULT=0")
                &&s.contains("RM11_V477_SWAPCHAIN_HELD_THROUGH_VISIBLE_PERIOD=YES")
                &&s.contains("RM11_V477_SWAPCHAIN_VISIBLE_HOLD_COMPLETE=YES")
                &&s.contains("RM11_V477_PROCESS_COMPLETED=0"))
            return "LIVE_SWAPCHAIN_HELD_FOR_DISPLAY_TOUCH_RESULT_USER_UNVERIFIED";
        if(s.contains("RM11_V477_PRESENT_STATUS=MAGENTA_FRAME_SUBMITTED_VIA_XLIB"))
            return "FRAME_SUBMITTED_SWAPCHAIN_LIFETIME_UNVERIFIED";
        return "INCOMPLETE_OR_DRIVER_ABORT";
    }
}
