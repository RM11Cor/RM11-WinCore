package com.rm11.autocore;
import static org.junit.Assert.*;
import org.junit.Test;
public final class VulkanEvidenceTest {
    @Test public void instanceFailureNotReady(){assertTrue(VulkanEvidence.evaluate(false,1,true,1,true).contains("تعذر"));}
    @Test public void zeroGpuNotReady(){assertTrue(VulkanEvidence.evaluate(true,0,false,0,false).contains("GPU"));}
    @Test public void noGraphicsQueueNotReady(){assertTrue(VulkanEvidence.evaluate(true,1,true,0,true).contains("Graphics"));}
    @Test public void noDeviceNotReady(){assertTrue(VulkanEvidence.evaluate(true,1,false,1,true).contains("تعذر"));}
    @Test public void noSwapchainNotEquivalentToRendering(){assertTrue(VulkanEvidence.evaluate(true,1,true,1,false).contains("swapchain"));}
    @Test public void successDoesNotClaimGameExecution(){String s=VulkanEvidence.evaluate(true,1,true,1,true);assertTrue(s.contains("EXE"));assertFalse(s.contains("تم تشغيل لعبة"));}
}
