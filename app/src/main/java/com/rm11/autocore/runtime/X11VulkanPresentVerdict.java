package com.rm11.autocore.runtime;

/** v475 distinguishes a Vulkan queue-present success from visual screenshot evidence. */
public final class X11VulkanPresentVerdict {
    private X11VulkanPresentVerdict(){}
    public static String classify(String log) {
        if(log==null||log.isEmpty())return "CHILD_EMPTY_OR_DRIVER_ABORT";
        if(log.contains("RM11_V475_XLIB_DISPLAY=CONNECT_FAILED"))
            return "LIVE_X11_DISPLAY_CONNECT_FAILED";
        if(log.contains("RM11_V475_XLIB_CLIENT=DLOPEN_FAILED")
            ||log.contains("RM11_V475_XLIB_CLIENT=SYMBOLS_MISSING"))
            return "PRIVATE_XLIB_LINKAGE_FAILED";
        if(log.contains("RM11_V475_PRIVATE_VULKAN_LOADER=DLOPEN_FAILED"))
            return "PRIVATE_VULKAN_LOADER_LINKAGE_FAILED";
        if(log.contains("RM11_V475_VK_CREATE_XLIB_SURFACE_RESULT=")
            &&!log.contains("RM11_V475_X11_VULKAN_SURFACE=CREATED"))
            return "VULKAN_XLIB_SURFACE_CREATE_FAILED";
        if(log.contains("RM11_V475_PRESENT_STATUS=VK_KHR_SWAPCHAIN_NOT_SUPPORTED"))
            return "SWAPCHAIN_EXTENSION_UNAVAILABLE";
        if(log.contains("RM11_V475_PRESENT_STATUS=SWAPCHAIN_CREATION_FAILED"))
            return "SWAPCHAIN_CREATE_FAILED";
        if(log.contains("RM11_V475_PRESENT_STATUS=VK_QUEUE_PRESENT_FAILED"))
            return "VK_QUEUE_PRESENT_FAILED";
        if(log.contains("RM11_V475_PRESENT_STATUS=MAGENTA_FRAME_SUBMITTED_VIA_XLIB")
           &&log.contains("RM11_V475_VK_QUEUE_PRESENT_RESULT=0")
           &&log.contains("RM11_V475_FRAME_PRESENT_TEST_RESULT=0")
           &&log.contains("RM11_V475_PROCESS_COMPLETED=0"))
            return "VK_QUEUE_PRESENT_OK_ANDROID_VISIBLE_PIXELS_UNVERIFIED";
        return "PRESENT_INCOMPLETE_OR_NATIVE_ABORT";
    }
}
