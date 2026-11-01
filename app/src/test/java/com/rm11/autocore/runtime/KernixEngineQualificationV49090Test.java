package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

/** Fail closed: build files, an X11 root window and one successful Vulkan
 * call cannot certify the full Wine/FEX/DirectX/gamepad engine. */
public final class KernixEngineQualificationV49090Test {
    @Test public void incompleteOrMissingEvidenceNeverQualifiesEngine(){
        assertEquals(7,KernixEngineQualificationV49090.REQUIRED.length);
        assertFalse(KernixEngineQualificationV49090.mandatoryComplete(null));
        assertFalse(KernixEngineQualificationV49090.mandatoryComplete(new boolean[0]));
        assertFalse(KernixEngineQualificationV49090.mandatoryComplete(new boolean[7]));
        boolean[] onlyVulkan={false,false,true,true,false,false,false};
        assertFalse(KernixEngineQualificationV49090.mandatoryComplete(onlyVulkan));
        assertEquals("WINE_FEX_WIN32_EXIT",
            KernixEngineQualificationV49090.firstMissing(onlyVulkan));
    }
    @Test public void fullAcceptanceRequiresEveryIndependentStage(){
        boolean[] complete={true,true,true,true,true,true,true};
        assertTrue(KernixEngineQualificationV49090.mandatoryComplete(complete));
        assertEquals("NONE",KernixEngineQualificationV49090.firstMissing(complete));
        for(int i=0;i<complete.length;i++){
            complete[i]=false;
            assertFalse(KernixEngineQualificationV49090.mandatoryComplete(complete));
            assertEquals(KernixEngineQualificationV49090.REQUIRED[i],
                KernixEngineQualificationV49090.firstMissing(complete));
            complete[i]=true;
        }
    }
    @Test public void onlyCurrentSignedP11Win64ReceiptMayPromoteOneStage(){
        // Run this contract without Android's host-JVM JSONObject stubs.
        assertTrue(KernixEngineQualificationV49090.currentProtonWin64Evidence(
            true,true,true,"PINNED_PREFIX_RESTART_ONLY",false));
        boolean[] stages=new boolean[7];stages[0]=true;
        assertFalse(KernixEngineQualificationV49090.mandatoryComplete(stages));
        assertEquals("WIN32_X11_VISIBLE_FRAME",
            KernixEngineQualificationV49090.firstMissing(stages));
        assertFalse(KernixEngineQualificationV49090.currentProtonWin64Evidence(
            false,true,true,"PINNED_PREFIX_RESTART_ONLY",false));
        assertFalse(KernixEngineQualificationV49090.currentProtonWin64Evidence(
            true,false,true,"PINNED_PREFIX_RESTART_ONLY",false));
        assertFalse(KernixEngineQualificationV49090.currentProtonWin64Evidence(
            true,true,false,"PINNED_PREFIX_RESTART_ONLY",false));
        assertFalse(KernixEngineQualificationV49090.currentProtonWin64Evidence(
            true,true,true,"UNKNOWN",false));
        assertFalse(KernixEngineQualificationV49090.currentProtonWin64Evidence(
            true,true,true,null,false));
        assertFalse(KernixEngineQualificationV49090.currentProtonWin64Evidence(
            true,true,true,"PINNED_PREFIX_RESTART_ONLY",true));
    }
    @Test public void nullDeviceProofNeverQualifies(){
        assertFalse(KernixEngineQualificationV49090.recordGpuQueue(null,null));
        assertFalse(KernixEngineQualificationV49090.recordNativeWsi(null,null));
        assertEquals("WINE_FEX_WIN32_EXIT",
            KernixEngineQualificationV49090.firstMissing(new boolean[7]));
    }
}
