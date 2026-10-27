package com.rm11.autocore.runtime;

/** A successful queue present is not itself an Android screenshot. */
public final class X11VulkanPresentVerdict {
    private X11VulkanPresentVerdict(){}
    public static String classify(String s) {
        if(s==null||s.isEmpty())return "NATIVE_ABORT_OR_EMPTY_LOG";
        if(s.contains("RM11_V475_QUEUE_PRESENT_RESULT=0")
            &&s.contains("RM11_V475_GPU_FENCE_WAIT_RESULT=0")
            &&s.contains("RM11_V475_GREEN_FRAME_PRESENT_ENQUEUED=true"))
            return "GPU_GREEN_FRAME_QUEUED_PIXEL_VERIFICATION_SEPARATE";
        if(s.contains("RM11_V475_QUEUE_PRESENT_RESULT="))
            return "QUEUE_PRESENT_FAILED";
        if(s.contains("RM11_V475_CREATE_SWAPCHAIN_RESULT=")
            &&!s.contains("RM11_V475_SWAPCHAIN_CREATED=true"))
            return "SWAPCHAIN_CREATION_FAILED";
        if(s.contains("RM11_V475_SWAPCHAIN_CREATED=true"))
            return "SWAPCHAIN_CREATED_RENDER_OR_PRESENT_FAILED";
        if(s.contains("RM11_V475_CREATE_DEVICE_RESULT="))
            return "DEVICE_CREATION_OR_EARLY_SWAPCHAIN_FAILURE";
        if(s.contains("RM11_V475_SURFACE_CREATED=true"))
            return "SURFACE_CREATED_SWAPCHAIN_UNVERIFIED";
        return "BEFORE_SWAPCHAIN_OR_DRIVER_ABORT";
    }
}
