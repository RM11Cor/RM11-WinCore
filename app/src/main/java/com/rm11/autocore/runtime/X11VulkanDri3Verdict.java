package com.rm11.autocore.runtime;

/** v476: extension presence is an X11 server fact, not proof of Vulkan WSI. */
public final class X11VulkanDri3Verdict {
    private X11VulkanDri3Verdict(){}
    public static String classify(String s){
        if(s==null||s.isEmpty())return "EMPTY_OR_NATIVE_ABORT";
        if(s.contains("RM11_V476_XLIB_DISPLAY=CONNECT_FAILED"))
            return "X11_CONNECT_FAILED";
        if(s.contains("RM11_V476_X11_EXT_DRI3=NO")
            ||s.contains("RM11_V476_X11_EXT_Present=NO"))
            return "SERVER_DRI3_OR_PRESENT_EXTENSION_MISSING";
        if(s.contains("RM11_V476_VK_CREATE_SWAPCHAIN_RESULT=-3"))
            return "SWAPCHAIN_INITIALIZATION_FAILED_MINUS3_ROOT_CAUSE_UNCONFIRMED";
        if(s.contains("RM11_V476_PRESENT_STATUS=MAGENTA_FRAME_SUBMITTED_VIA_XLIB")
            &&s.contains("RM11_V476_VK_QUEUE_PRESENT_RESULT=0"))
            return "VULKAN_QUEUE_PRESENT_ACCEPTED_ANDROID_VISUAL_UNVERIFIED";
        if(s.contains("RM11_V476_CPU_XLIB_BASELINE_COLOR=GREEN_00CC44_GPU_UNVERIFIED"))
            return "CPU_XLIB_GREEN_DRAW_REQUESTED_VISUAL_UNVERIFIED";
        return "INCOMPLETE_OR_DRIVER_ABORT";
    }
}
