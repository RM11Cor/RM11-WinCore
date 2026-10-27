package com.rm11.autocore.runtime;

/** v477: extension presence is an X11 server fact, not proof of Vulkan WSI. */
public final class X11VulkanSwapchainVerdict {
    private X11VulkanSwapchainVerdict(){}
    public static String classify(String s){
        if(s==null||s.isEmpty())return "EMPTY_OR_NATIVE_ABORT";
        if(s.contains("RM11_V477_XLIB_DISPLAY=CONNECT_FAILED"))
            return "X11_CONNECT_FAILED";
        if(s.contains("RM11_V477_X11_EXT_DRI3=NO")
            ||s.contains("RM11_V477_X11_EXT_Present=NO"))
            return "SERVER_DRI3_OR_PRESENT_EXTENSION_MISSING";
        if(s.contains("RM11_V477_PRESENT_STATUS=COLOR_ATTACHMENT_ONLY_SUCCESS_NO_TRANSFER_CLEAR"))
            return "COLOR_ATTACHMENT_SWAPCHAIN_CREATED_GPU_PRESENT_UNVERIFIED";
        if(s.contains("RM11_V477_VK_CREATE_SWAPCHAIN_RESULT=-3")
            ||s.contains("RM11_V477_PRESENT_STATUS=ALL_VALID_SWAPCHAIN_TRIALS_FAILED"))
            return "ALL_VALID_SWAPCHAIN_TRIALS_FAILED_ROOT_CAUSE_UNCONFIRMED";
        if(s.contains("RM11_V477_PRESENT_STATUS=MAGENTA_FRAME_SUBMITTED_VIA_XLIB")
            &&s.contains("RM11_V477_VK_QUEUE_PRESENT_RESULT=0"))
            return "VULKAN_QUEUE_PRESENT_ACCEPTED_ANDROID_VISUAL_UNVERIFIED";
        if(s.contains("RM11_V477_CPU_XLIB_BASELINE_COLOR=GREEN_00CC44_GPU_UNVERIFIED"))
            return "CPU_XLIB_GREEN_DRAW_REQUESTED_VISUAL_UNVERIFIED";
        return "INCOMPLETE_OR_DRIVER_ABORT";
    }
}
