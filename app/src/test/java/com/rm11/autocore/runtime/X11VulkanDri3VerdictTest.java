package com.rm11.autocore.runtime;
import org.junit.Test;
import static org.junit.Assert.*;
public final class X11VulkanDri3VerdictTest {
    @Test public void extensionMissingIsNotGPUFailureProof() {
        assertEquals("SERVER_DRI3_OR_PRESENT_EXTENSION_MISSING",
            X11VulkanDri3Verdict.classify(
                "RM11_V476_X11_EXT_DRI3=NO\nRM11_V476_VK_CREATE_SWAPCHAIN_RESULT=-3\n"));
    }
    @Test public void parameterErrorAloneCannotProveCause(){
        assertEquals("SWAPCHAIN_INITIALIZATION_FAILED_MINUS3_ROOT_CAUSE_UNCONFIRMED",
            X11VulkanDri3Verdict.classify(
                "RM11_V476_X11_EXT_DRI3=YES\nRM11_V476_X11_EXT_Present=YES\nRM11_V476_VK_CREATE_SWAPCHAIN_RESULT=-3\n"));
    }
    @Test public void greenXlibNotGPUFrameAndEmptyFailsClosed(){
        assertEquals("CPU_XLIB_GREEN_DRAW_REQUESTED_VISUAL_UNVERIFIED",
            X11VulkanDri3Verdict.classify(
                "RM11_V476_CPU_XLIB_BASELINE_COLOR=GREEN_00CC44_GPU_UNVERIFIED\n"));
        assertEquals("EMPTY_OR_NATIVE_ABORT",X11VulkanDri3Verdict.classify(""));
    }
}
