package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

/** Proof requires three independent paths: Win32 frames, Android pixels,
 * and native Wine DXVK DLLs. No fallback or single blue frame is sufficient. */
public final class KernixDx11DeviceEvidenceV49102Test {
    private static final String SUCCESS=
        "RM11_V49029_STAGE=CREATE_D3D11_DEVICE_SWAPCHAIN HRESULT=0x00000000\n"+
        "KERNIX_V49101_RESULT_FRAMES=900 FAILED=0\n"+
        "KERNIX_V49101_FINAL_COMPLETE=1 STATUS=0\n";
    private static final String PIXELS=
        "KERNIX_DX11_PIXELCOPY=SUCCESS\n"+
        "KERNIX_DX11_DISTINCT_COLORS_VISIBLE=3\n"+
        "KERNIX_DX11_COLOR_TRANSITION_PROVEN=true\n";
    private static final String WINE=
        "00d4:trace:loaddll:build_module Loaded L\"Z:\\files\\mini-dxvk-v49021\\d3d11.dll\" at 0x1000: native\n"+
        "00d4:trace:loaddll:build_module Loaded L\"Z:\\files\\mini-dxvk-v49021\\dxgi.dll\" at 0x2000: native\n"+
        "info:  DXVK: v2.7.1\ninfo: Found device: Adreno (TM) 840 (turnip)\n";
    @Test public void validatesActualThreeEvidencePaths(){
        assertTrue(KernixDx11DeviceEvidenceV49102.verified(SUCCESS,PIXELS,WINE));
    }
    @Test public void rejectsSingleBlueFrame(){
        assertFalse(KernixDx11DeviceEvidenceV49102.verified(
            SUCCESS,PIXELS.replace("VISIBLE=3","VISIBLE=1"),WINE));
    }
    @Test public void rejectsMissingFinal(){
        assertFalse(KernixDx11DeviceEvidenceV49102.verified(
            SUCCESS.replace("FINAL_COMPLETE=1","FINAL_COMPLETE=0"),PIXELS,WINE));
    }
    @Test public void rejectsWineD3dFallback(){
        assertFalse(KernixDx11DeviceEvidenceV49102.verified(
            SUCCESS,PIXELS,WINE.replace("DXVK: v2.7.1","WineD3D")));
    }
    @Test public void rejectsNonzeroPresentErrors(){
        assertFalse(KernixDx11DeviceEvidenceV49102.verified(
            SUCCESS.replace("FAILED=0","FAILED=1"),PIXELS,WINE));
    }
}
