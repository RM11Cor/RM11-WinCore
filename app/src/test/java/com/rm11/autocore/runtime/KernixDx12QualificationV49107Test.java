package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * The signed Windows DX12 240-frame test alone is not a visual proof.
 * Native Win32 progress, app-local VKD3D on Adreno, and distinct Android
 * PixelCopy colors must all agree; this never qualifies real games.
 */
public final class KernixDx12QualificationV49107Test {
    private static final String WIN32=
        "KERNIX_V49106_STAGE=PROGRAM_STARTED HRESULT=0x00000000\n"+
        "KERNIX_V49106_STAGE=D3D12_CREATE_DEVICE HRESULT=0x00000000\n"+
        "KERNIX_V49106_STAGE=D3D12_CREATE_COMMAND_QUEUE HRESULT=0x00000000\n"+
        "KERNIX_V49106_STAGE=DXGI_CREATE_SWAPCHAIN HRESULT=0x00000000\n"+
        "KERNIX_V49106_STAGE=DXGI_SWAPCHAIN3 HRESULT=0x00000000\n"+
        "KERNIX_V49106_STAGE=D3D12_CREATE_COMMAND_LIST HRESULT=0x00000000\n"+
        "KERNIX_V49106_STAGE=D3D12_CREATE_FENCE HRESULT=0x00000000\n"+
        "KERNIX_V49106_PRESENT FRAME=1 COLOR=0 HRESULT=0x00000000\n"+
        "KERNIX_V49106_PRESENT FRAME=61 COLOR=1 HRESULT=0x00000000\n"+
        "KERNIX_V49106_PRESENT FRAME=121 COLOR=2 HRESULT=0x00000000\n"+
        "KERNIX_V49106_PRESENT FRAME=181 COLOR=3 HRESULT=0x00000000\n"+
        "KERNIX_V49106_STAGE=D3D12_FRAMES_PRESENT_COMPLETE HRESULT=0x00000000\n"+
        "KERNIX_V49106_RESULT_FRAMES=240 EXPECTED=240 FAILED=0\n";
    private static final String DLLROOT=
        "C:\\KERNIX\\engine-tests\\mini-vkd3d-v49106-abc\\";
    private static final String WINE=
        "010c:trace:loaddll:build_module Loaded L\""+DLLROOT+
            "KERNIX-D3D12-FRAMES.exe\" at 0: native\n"+
        "010c:trace:loaddll:build_module Loaded L\""+DLLROOT+
            "d3d12.dll\" at 0: native\n"+
        "010c:trace:loaddll:build_module Loaded L\""+DLLROOT+
            "d3d12core.dll\" at 0: native\n"+
        "010c:trace:loaddll:build_module Loaded L\""+DLLROOT+
            "dxgi.dll\" at 0: native\n"+
        "info: Found device: Adreno (TM) 840 (turnip Mesa driver 26.2.6)\n"+
        "info:vkd3d-proton:vkd3d_get_vk_version: vkd3d-proton - applicationVersion: 3.0.1.\n";
    @Test public void allIndependentPathsRequired(){
        assertTrue(KernixEngineQualificationV49090
            .verifiedWin64Dx12Frames(WIN32,0b0111,WINE));
        assertTrue(KernixEngineQualificationV49090
            .verifiedWin64Dx12Frames(WIN32,0b0011,WINE));
    }
    @Test public void rejectIncompletePresentOrSingleColor(){
        assertFalse(KernixEngineQualificationV49090
            .verifiedWin64Dx12Frames(WIN32,0b0001,WINE));
        assertFalse(KernixEngineQualificationV49090
            .verifiedWin64Dx12Frames(WIN32.replace(
                "RESULT_FRAMES=240 EXPECTED=240 FAILED=0",
                "RESULT_FRAMES=239 EXPECTED=240 FAILED=1"),0b0011,WINE));
        assertFalse(KernixEngineQualificationV49090
            .verifiedWin64Dx12Frames(WIN32.replace(
                "FRAME=121 COLOR=2 HRESULT=0x00000000",
                "FRAME=121 COLOR=2 HRESULT=0x887A0005"),0b0011,WINE));
        assertFalse(KernixEngineQualificationV49090
            .verifiedWin64Dx12Frames(WIN32.replace(
                "DXGI_CREATE_SWAPCHAIN", "DXGI_CREATE_SWAPCHAIN_FAILED"),0b0011,WINE));
    }
    @Test public void rejectWineD3dOrUnrelatedDlls(){
        assertFalse(KernixEngineQualificationV49090
            .verifiedWin64Dx12Frames(WIN32,0b0011,WINE.replace(
                "d3d12core.dll","d3d12core.missing")));
        assertFalse(KernixEngineQualificationV49090
            .verifiedWin64Dx12Frames(WIN32,0b0011,WINE.replace(
                "Found device: Adreno","Found device: llvmpipe")));
        assertFalse(KernixEngineQualificationV49090
            .verifiedWin64Dx12Frames(WIN32,0b0011,WINE.replace(
                "mini-vkd3d-v49106","unrelated-stage")));
        assertFalse(KernixEngineQualificationV49090
            .verifiedWin64Dx12Frames(WIN32,0b0011,WINE.replace(
                "applicationVersion: 3.0.1","applicationVersion: 0.0.0")));
    }
    @Test public void buildAndPartialEngineProofNeverCertifyAllGames(){
        boolean[] stages={false,false,false,false,false,true,false};
        assertFalse(KernixEngineQualificationV49090.mandatoryComplete(stages));
        assertEquals("WINE_FEX_WIN32_EXIT",
            KernixEngineQualificationV49090.firstMissing(stages));
    }
}
