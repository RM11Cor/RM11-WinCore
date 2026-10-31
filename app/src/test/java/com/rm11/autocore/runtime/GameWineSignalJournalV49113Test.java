package com.rm11.autocore.runtime;
import static org.junit.Assert.*;
import org.junit.Test;

public final class GameWineSignalJournalV49113Test {
    @Test public void preservesRealWineAndDx12Failures(){
        assertTrue(GameWineSignalJournalV49113.important(
            "0120:err:vulkan:vkCreateSwapchainKHR failed VK_ERROR_INITIALIZATION_FAILED"));
        assertTrue(GameWineSignalJournalV49113.important(
            "info:vkd3d-proton:d3d12_device_caps_init_shader_model: Enabling Shader Model 6.6"));
        assertTrue(GameWineSignalJournalV49113.important(
            "X connection to 127.0.0.1:2 broken (explicit kill or server shutdown)."));
        assertTrue(GameWineSignalJournalV49113.important(
            "0120:trace:loaddll:build_module Loaded witcher3.exe: native"));
    }
    @Test public void doesNotConfuseSehTraceFloodWithGameFailure(){
        assertFalse(GameWineSignalJournalV49113.important(
            "0150:trace:unwind:RtlVirtualUnwind2_arm64 ret pc=6fffed489c"));
        assertFalse(GameWineSignalJournalV49113.important(
            "0150:trace:seh:RtlInitializeExtendedContext2 context 0007ff"));
    }
}
