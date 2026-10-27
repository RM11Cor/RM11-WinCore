package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

public final class X11VulkanSurfaceVerdictTest {
    @Test public void xlibSurfaceAndPresentQueueAreNotSwapchainProof(){
        String out="RM11_V474_XLIB_DISPLAY=CONNECTED\n"
            +"RM11_V474_VK_CREATE_XLIB_SURFACE_RESULT=0\n"
            +"RM11_V474_X11_VULKAN_SURFACE=CREATED\n"
            +"RM11_V474_X11_SURFACE_PRESENT_QUEUE=SUPPORTED\n"
            +"RM11_V474_SWAPCHAIN_PRESENT=NOT_ATTEMPTED\n";
        assertEquals("XLIB_SURFACE_AND_PRESENT_QUEUE_CONFIRMED_SWAPCHAIN_UNVERIFIED",
            X11VulkanSurfaceVerdict.classify(out));
    }
    @Test public void x11AbsentAndNativeAbortNeverCountAsSuccess() {
        assertEquals("LIVE_X11_DISPLAY_NOT_ACCESSIBLE",
            X11VulkanSurfaceVerdict.classify(
               "RM11_V474_XLIB_DISPLAY=CONNECT_FAILED\n"));
        assertEquals("NO_OUTPUT_OR_NATIVE_ABORT",
            X11VulkanSurfaceVerdict.classify(""));
        assertEquals("VULKAN_XLIB_SURFACE_CREATION_FAILED",
            X11VulkanSurfaceVerdict.classify(
               "RM11_V474_VK_CREATE_XLIB_SURFACE_RESULT=-7\n"));
    }
}
