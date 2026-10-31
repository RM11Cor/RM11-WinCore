package com.rm11.autocore.runtime;

import org.junit.Test;
import org.json.JSONObject;
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
    @Test public void noSyntheticGpuProofCanBeRecorded(){
        assertFalse(KernixEngineQualificationV49090.recordGpuQueue(null,null));
        assertFalse(KernixEngineQualificationV49090.recordGpuQueue(
            null,new JSONObject()));
        assertFalse(KernixEngineQualificationV49090.recordNativeWsi(
            null,new JSONObject()));
        JSONObject status=KernixEngineQualificationV49090.snapshot(null);
        assertEquals("ENGINE_NOT_YET_QUALIFIED",status.optString("state"));
        assertFalse(status.optBoolean("qualified"));
        assertEquals(7,status.optJSONArray("checks").length());
        assertEquals("WINE_FEX_WIN32_EXIT",status.optString("firstMissing"));
    }
}
