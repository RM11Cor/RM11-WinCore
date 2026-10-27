package com.rm11.autocore.runtime;
import org.junit.Test;
import static org.junit.Assert.*;
public final class X11VulkanSwapchainVerdictTest {
    @Test public void extensionMissingIsNotGPUFailureProof() {
        assertEquals("SERVER_DRI3_OR_PRESENT_EXTENSION_MISSING",
            X11VulkanSwapchainVerdict.classify(
                "RM11_V477_X11_EXT_DRI3=NO\nRM11_V477_VK_CREATE_SWAPCHAIN_RESULT=-3\n"));
    }
    @Test public void parameterErrorAloneCannotProveCause(){
        assertEquals("ALL_VALID_SWAPCHAIN_TRIALS_FAILED_ROOT_CAUSE_UNCONFIRMED",
            X11VulkanSwapchainVerdict.classify(
                "RM11_V477_X11_EXT_DRI3=YES\nRM11_V477_X11_EXT_Present=YES\nRM11_V477_VK_CREATE_SWAPCHAIN_RESULT=-3\n"));
    }
    @Test public void colorAttachmentOnlyIsNotGPUDisplayProof(){
        assertEquals("COLOR_ATTACHMENT_SWAPCHAIN_CREATED_GPU_PRESENT_UNVERIFIED",
            X11VulkanSwapchainVerdict.classify(
                "RM11_V477_PRESENT_STATUS=COLOR_ATTACHMENT_ONLY_SUCCESS_NO_TRANSFER_CLEAR\\n"));
    }
    @Test public void greenXlibNotGPUFrameAndEmptyFailsClosed(){
        assertEquals("CPU_XLIB_GREEN_DRAW_REQUESTED_VISUAL_UNVERIFIED",
            X11VulkanSwapchainVerdict.classify(
                "RM11_V477_CPU_XLIB_BASELINE_COLOR=GREEN_00CC44_GPU_UNVERIFIED\n"));
        assertEquals("EMPTY_OR_NATIVE_ABORT",X11VulkanSwapchainVerdict.classify(""));
    }
}
