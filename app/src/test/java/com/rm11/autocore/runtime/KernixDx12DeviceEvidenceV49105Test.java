package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

/** D3D12 device success is NOT a DirectX12 frame or game qualification. */
public final class KernixDx12DeviceEvidenceV49105Test {
    private static final String OK=
        "KERNIX_V49103_D3D12_STAGE=PROGRAM_STARTED HRESULT=0x00000000\n"+
        "KERNIX_V49103_D3D12_STAGE=D3D12_CREATE_DEVICE HRESULT=0x00000000\n"+
        "KERNIX_V49103_D3D12_STAGE=D3D12_CREATE_COMMAND_QUEUE HRESULT=0x00000000\n"+
        "KERNIX_V49103_D3D12_STAGE=D3D12_CREATE_COMMAND_ALLOCATOR HRESULT=0x00000000\n"+
        "KERNIX_V49103_D3D12_STAGE=D3D12_DEVICE_QUEUE_COMPLETE HRESULT=0x00000000\n";
    private static final String WINE=
        "Loaded L\"C:\\KERNIX\\engine-tests\\mini-vkd3d-v49103-abcdef\\KERNIX-D3D12-DEVICE.exe\" at 0: native\n"+
        "Loaded L\"C:\\KERNIX\\engine-tests\\mini-vkd3d-v49103-abcdef\\d3d12.dll\" at 0: native\n"+
        "Loaded L\"C:\\KERNIX\\engine-tests\\mini-vkd3d-v49103-abcdef\\d3d12core.dll\" at 0: native\n"+
        "Loaded L\"C:\\KERNIX\\engine-tests\\mini-vkd3d-v49103-abcdef\\dxgi.dll\" at 0: native\n"+
        "info: Found device: Adreno (TM) 840 (turnip)\n"+
        "info:vkd3d-proton:vkd3d_get_vk_version: applicationVersion: 3.0.1\n";
    @Test public void verifiedFoundationalWin32Stages(){
        assertTrue(KernixDx12DeviceEvidenceV49105.verifiedDeviceStages(OK));
        assertTrue(KernixDx12DeviceEvidenceV49105.verifiedWineVkd3dTurnip(WINE));
    }
    @Test public void testRejectsMissingCommandAllocator(){
        assertFalse(KernixDx12DeviceEvidenceV49105.verifiedDeviceStages(
            OK.replace("KERNIX_V49103_D3D12_STAGE=D3D12_CREATE_COMMAND_ALLOCATOR HRESULT=0x00000000\n","")));
    }
    @Test public void rejectFailedDeviceAndExtraLines(){
        assertFalse(KernixDx12DeviceEvidenceV49105.verifiedDeviceStages(
            OK.replace("CREATE_DEVICE HRESULT=0x00000000","CREATE_DEVICE HRESULT=0x80004005")));
        assertFalse(KernixDx12DeviceEvidenceV49105.verifiedDeviceStages(
            OK+"KERNIX_V49103_D3D12_STAGE=D3D12_DEVICE_QUEUE_INCOMPLETE HRESULT=0x80004005\n"));
    }
    @Test public void rejectUnrelatedWineDxgiOrWrongVersion(){
        assertFalse(KernixDx12DeviceEvidenceV49105.verifiedWineVkd3dTurnip(
            WINE.replace("d3d12core.dll","not-core.dll")));
        assertFalse(KernixDx12DeviceEvidenceV49105.verifiedWineVkd3dTurnip(
            WINE.replace("applicationVersion: 3.0.1","applicationVersion: 0.0.0")));
        assertFalse(KernixDx12DeviceEvidenceV49105.verifiedWineVkd3dTurnip(
            WINE.replace("Found device: Adreno","Found device: CPU")));
    }
    @Test public void timeCoherenceRequired(){
        long now=100_000_000L;
        assertTrue(KernixDx12DeviceEvidenceV49105.coherentTimes(
            now-1000,now-500,now));
        assertFalse(KernixDx12DeviceEvidenceV49105.coherentTimes(
            now-1000000,now-500,now));
        assertFalse(KernixDx12DeviceEvidenceV49105.coherentTimes(
            now+1000,now-500,now));
    }
}
