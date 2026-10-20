package com.rm11.autocore;

import org.junit.Test;
import static org.junit.Assert.*;
import java.util.Arrays;
import java.util.Collections;

public final class RuntimeReadinessTest {
    private static final int VULKAN_1_3=(1 << 22) | (3 << 12);
    @Test public void arm64AndVulkanWithoutRuntimeIsNotExecutable() {
        RuntimeReadiness.Assessment a=RuntimeReadiness.assess(Arrays.asList("arm64-v8a", "armeabi-v7a"), VULKAN_1_3,false,false,false);
        assertTrue(a.arm64Supported);
        assertTrue(a.androidVulkanAdvertised);
        assertFalse(a.executionReady);
        assertTrue(a.runtime.contains("غير جاهز"));
    }
    @Test public void unsupportedAbiNeverClaimsReady() {
        RuntimeReadiness.Assessment a=RuntimeReadiness.assess(Collections.singletonList("x86"),VULKAN_1_3,true,true,true);
        assertFalse(a.executionReady);
        assertTrue(a.cpu.contains("غير معلنة"));
    }
    @Test public void noVulkanReportDoesNotMeanNoGpu() {
        RuntimeReadiness.Assessment a=RuntimeReadiness.assess(Collections.singletonList("arm64-v8a"),0,false,false,false);
        assertFalse(a.androidVulkanAdvertised);
        assertTrue(a.graphics.contains("لا نفترض غياب"));
    }
    @Test public void rawVulkanVersionPackedDecodedCorrectly() {
        assertTrue(RuntimeReadiness.vulkanVersionString(VULKAN_1_3).startsWith("1.3.0"));
    }
    @Test public void unknownVulkanVersionIsNotFabricated() {
        assertTrue(RuntimeReadiness.vulkanVersionString(0).contains("غير مُعلَن"));
    }
    @Test public void allVerifiedComponentsStillNeedGameTest() {
        RuntimeReadiness.Assessment a=RuntimeReadiness.assess(Collections.singletonList("arm64-v8a"),VULKAN_1_3,true,true,true);
        assertTrue(a.executionReady);
        assertTrue(a.runtime.contains("اختباراً مستقلاً"));
    }
}
