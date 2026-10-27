package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

public final class X11VulkanPresentVerdictTest {
    @Test public void queueSubmissionNeedsFenceAndPresentationResult() {
        assertEquals("GPU_GREEN_FRAME_QUEUED_PIXEL_VERIFICATION_SEPARATE",
            X11VulkanPresentVerdict.classify(
                "RM11_V475_GPU_FENCE_WAIT_RESULT=0\n"
               +"RM11_V475_QUEUE_PRESENT_RESULT=0\n"
               +"RM11_V475_GREEN_FRAME_PRESENT_ENQUEUED=true\n"));
        assertEquals("QUEUE_PRESENT_FAILED",
            X11VulkanPresentVerdict.classify("RM11_V475_QUEUE_PRESENT_RESULT=-1000000000\n"));
    }
    @Test public void surfaceOnlyMustNotCountAsPresented(){
        assertEquals("SURFACE_CREATED_SWAPCHAIN_UNVERIFIED",
            X11VulkanPresentVerdict.classify("RM11_V475_SURFACE_CREATED=true\n"));
        assertEquals("SWAPCHAIN_CREATION_FAILED",
            X11VulkanPresentVerdict.classify("RM11_V475_CREATE_SWAPCHAIN_RESULT=-3\n"));
        assertEquals("NATIVE_ABORT_OR_EMPTY_LOG",X11VulkanPresentVerdict.classify(""));
    }
}
