package com.rm11.autocore.runtime;
import org.junit.Test;
import static org.junit.Assert.*;

public class KernixComponentRulesV49150Test {
    @Test public void fileIsNotDeviceProof(){
        assertEquals(KernixComponentRulesV49150.State.MISSING,
            KernixComponentRulesV49150.state(false,true));
        assertEquals(KernixComponentRulesV49150.State.PACKAGED_UNVERIFIED,
            KernixComponentRulesV49150.state(true,false));
        assertEquals(KernixComponentRulesV49150.State.DEVICE_QUALIFIED,
            KernixComponentRulesV49150.state(true,true));
    }
    @Test public void missingGuiAlwaysBlocksExceptAntiCheatReview(){
        assertEquals("BLOCKED",KernixComponentRulesV49150
            .recommend("Direct3D 11",false,false,true,true,true,true).backend);
        assertFalse(KernixComponentRulesV49150
            .recommend("Direct3D 12",false,false,true,true,true,true).attemptAllowed);
        assertEquals("MANUAL_REVIEW",KernixComponentRulesV49150
            .recommend("Direct3D 11",true,false,true,true,true,true).backend);
    }
    @Test public void dx12DoesNotFallBackToWineD3d(){
        KernixComponentRulesV49150.Plan plan=KernixComponentRulesV49150
            .recommend("Direct3D 12",false,true,true,true,false,true);
        assertEquals("BLOCKED",plan.backend);
        assertFalse(plan.attemptAllowed);
        assertEquals("VKD3D",KernixComponentRulesV49150
            .recommend("Direct3D 12",false,true,true,false,true,true).backend);
    }
    @Test public void dx11UsesOnlyQualifiedDxvk(){
        assertEquals("WINED3D",KernixComponentRulesV49150
            .recommend("Direct3D 11",false,true,true,false,false,true).backend);
        assertEquals("DXVK",KernixComponentRulesV49150
            .recommend("Direct3D 11",false,true,true,true,false,true).backend);
    }
    @Test public void unknownApiNeverForcesProvider(){
        assertEquals("AUTO_PROBE",KernixComponentRulesV49150
            .recommend("Unknown",false,true,true,true,true,true).backend);
    }
    @Test public void vulkanRequiresNativeWsi(){
        assertEquals("BLOCKED",KernixComponentRulesV49150
            .recommend("Vulkan",false,true,true,true,true,false).backend);
        assertEquals("NATIVE_VULKAN",KernixComponentRulesV49150
            .recommend("Vulkan",false,true,true,false,false,true).backend);
    }
}
