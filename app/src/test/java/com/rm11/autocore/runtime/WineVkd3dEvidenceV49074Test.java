package com.rm11.autocore.runtime;
import static org.junit.Assert.*;
import org.junit.Test;
public class WineVkd3dEvidenceV49074Test {
    @Test public void detectsRealDeviceTeardownWithoutClaimingRenderedFrames(){
        WineVkd3dEvidenceV49074 r=new WineVkd3dEvidenceV49074("witcher3.exe");
        r.accept("0114:trace:loaddll:build_module Loaded L\\"Z:\\\\game\\\\d3d12.dll\\" at 0x: native\n");
        r.accept("240266.834:0110:0158:info:vkd3d-proton:initializing device\n");
        r.accept("0114:err:vulkan:win32u_vkDestroyDevice destroyed device 0x123\n");
        String out=r.snapshot();
        assertTrue(out.contains("R4_V49074_VKD3D_PROTON_LOG_OBSERVED=true"));
        assertTrue(out.contains("R4_V49074_VULKAN_DEVICE_DESTROY_LOG=true"));
        assertTrue(out.contains("R4_V49074_ANDROID_FRAME_VISIBLE=NOT_PROVEN"));
    }
    @Test public void criticalErrorDoesNotGetOverwrittenByFloodOfUnwind(){
        WineVkd3dEvidenceV49074 r=new WineVkd3dEvidenceV49074("witcher3.exe");
        r.accept("err:vkd3d-proton: vk_error_initialization_failed\n");
        for(int i=0;i<3000;i++)r.accept("trace:unwind:irrelevant line\n");
        String out=r.snapshot();
        assertTrue(out.contains("vk_error_initialization_failed"));
        assertTrue(out.contains("R4_V49074_VULKAN_INIT_ERROR_SIGNAL=true"));
    }
}
