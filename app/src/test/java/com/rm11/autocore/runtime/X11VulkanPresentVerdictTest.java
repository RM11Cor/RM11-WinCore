package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

public final class X11VulkanPresentVerdictTest {
    @Test public void actualQueuePresentIsNotProofThatUserSawPixels() {
        String out="RM11_V475_X11_VULKAN_SURFACE=CREATED\n"
            +"RM11_V475_VK_CREATE_SWAPCHAIN_RESULT=0\n"
            +"RM11_V475_VK_QUEUE_SUBMIT_RESULT=0\n"
            +"RM11_V475_VK_QUEUE_PRESENT_RESULT=0\n"
            +"RM11_V475_PRESENT_STATUS=MAGENTA_FRAME_SUBMITTED_VIA_XLIB\n"
            +"RM11_V475_FRAME_PRESENT_TEST_RESULT=0\n"
            +"RM11_V475_PROCESS_COMPLETED=0\n";
        assertEquals("VK_QUEUE_PRESENT_OK_ANDROID_VISIBLE_PIXELS_UNVERIFIED",
            X11VulkanPresentVerdict.classify(out));
    }
    @Test public void oldSurfaceOnlyOrPartialNativeCrashIsNotSuccess() {
        assertEquals("PRESENT_INCOMPLETE_OR_NATIVE_ABORT",
            X11VulkanPresentVerdict.classify(
                "RM11_V475_X11_VULKAN_SURFACE=CREATED\n"));
        assertEquals("CHILD_EMPTY_OR_DRIVER_ABORT",
            X11VulkanPresentVerdict.classify(""));
        assertEquals("SWAPCHAIN_CREATE_FAILED",
            X11VulkanPresentVerdict.classify(
                "RM11_V475_PRESENT_STATUS=SWAPCHAIN_CREATION_FAILED\n"));
        assertEquals("VK_QUEUE_PRESENT_FAILED",
            X11VulkanPresentVerdict.classify(
                "RM11_V475_PRESENT_STATUS=VK_QUEUE_PRESENT_FAILED\n"));
    }
}
