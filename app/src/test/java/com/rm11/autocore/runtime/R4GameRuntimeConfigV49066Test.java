package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

/** v49128: DX12 game selections must fail closed without device evidence. */
public final class R4GameRuntimeConfigV49066Test {
    @Test public void missingEvidenceAlwaysBlocksVkd3d() {
        assertFalse(R4GameRuntimeConfigV49066.mayEnableVkd3d(false,null));
        assertFalse(R4GameRuntimeConfigV49066.mayEnableVkd3d(true,null));
        assertFalse(R4GameRuntimeConfigV49066.mayEnableVkd3d(true,new boolean[0]));
        assertFalse(R4GameRuntimeConfigV49066.mayEnableVkd3d(true,new boolean[6]));
        assertFalse(R4GameRuntimeConfigV49066.mayEnableVkd3d(true,new boolean[7]));
    }
    @Test public void onlySameDeviceGpuWsiAndDx12FrameProofUnlocks() {
        boolean[] stages=new boolean[7];
        stages[2]=true;
        stages[3]=true;
        assertFalse(R4GameRuntimeConfigV49066.mayEnableVkd3d(true,stages));
        stages[5]=true;
        assertTrue(R4GameRuntimeConfigV49066.mayEnableVkd3d(true,stages));
        assertFalse(R4GameRuntimeConfigV49066.mayEnableVkd3d(false,stages));
        for(int i:new int[]{2,3,5}) {
            stages[i]=false;
            assertFalse(R4GameRuntimeConfigV49066.mayEnableVkd3d(true,stages));
            stages[i]=true;
        }
    }
}
