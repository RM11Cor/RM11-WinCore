package com.rm11.autocore.runtime;

/** No X11 present-support assertion without genuine vkCreateXlibSurfaceKHR. */
public final class X11VulkanSurfaceVerdict {
    private X11VulkanSurfaceVerdict(){}
    public static String classify(String log){
        if(log==null||log.isEmpty())return "NO_OUTPUT_OR_NATIVE_ABORT";
        if(log.contains("RM11_V474_XLIB_DISPLAY=CONNECT_FAILED"))
            return "LIVE_X11_DISPLAY_NOT_ACCESSIBLE";
        if(log.contains("RM11_V474_XLIB_CLIENT=DLOPEN_FAILED")
            ||log.contains("RM11_V474_XLIB_CLIENT=SYMBOLS_MISSING"))
            return "XLIB_BIONIC_LINKAGE_FAILED";
        if(log.contains("RM11_V474_VK_XLIB_SURFACE_EXTENSION=NOT_AVAILABLE"))
            return "PRIVATE_VULKAN_XLIB_EXTENSION_NOT_AVAILABLE";
        if(log.contains("RM11_V474_X11_SURFACE_PRESENT_QUEUE=SUPPORTED")
          &&log.contains("RM11_V474_X11_VULKAN_SURFACE=CREATED"))
            return "XLIB_SURFACE_AND_PRESENT_QUEUE_CONFIRMED_SWAPCHAIN_UNVERIFIED";
        if(log.contains("RM11_V474_X11_VULKAN_SURFACE=CREATED"))
            return "XLIB_SURFACE_CREATED_PRESENT_QUEUE_UNVERIFIED";
        if(log.contains("RM11_V474_VK_CREATE_XLIB_SURFACE_RESULT="))
            return "VULKAN_XLIB_SURFACE_CREATION_FAILED";
        return "INCOMPLETE_OR_DRIVER_ABORT";
    }
}
