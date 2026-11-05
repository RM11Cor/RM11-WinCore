package com.rm11.autocore.runtime;

/** Dependency-free CI smoke tests for fail-closed component selection. */
public final class KernixComponentRulesSmoke {
    private static void check(boolean truth,String message) {
        if(!truth)throw new AssertionError(message);
    }
    public static void main(String[] args) {
        check(KernixComponentRulesV49150.state(false,true)
                ==KernixComponentRulesV49150.State.MISSING,
            "Unpackaged component must never be device qualified");
        check(KernixComponentRulesV49150.state(true,false)
                ==KernixComponentRulesV49150.State.PACKAGED_UNVERIFIED,
            "Bundled binary is not runtime proof");
        check(KernixComponentRulesV49150.state(true,true)
                ==KernixComponentRulesV49150.State.DEVICE_QUALIFIED,
            "Verified provider");
        KernixComponentRulesV49150.Plan gdiBlock=KernixComponentRulesV49150
            .recommend("Direct3D 11",false,false,true,true,true,true);
        check(!gdiBlock.attemptAllowed&&"BLOCKED".equals(gdiBlock.backend),
            "GUI failure must block renderer auto activation");
        KernixComponentRulesV49150.Plan dx12Block=KernixComponentRulesV49150
            .recommend("Direct3D 12",false,true,true,true,false,true);
        check(!dx12Block.attemptAllowed&&"BLOCKED".equals(dx12Block.backend),
            "Never silently run D3D12 over WineD3D");
        check("VKD3D".equals(KernixComponentRulesV49150
            .recommend("Direct3D 12",false,true,true,true,true,true).backend),
            "Device qualified D3D12 backend");
        check("WINED3D".equals(KernixComponentRulesV49150
            .recommend("Direct3D 11",false,true,true,false,false,true).backend),
            "Conservative D3D11 fallback when DXVK lacks proof");
        check("DXVK".equals(KernixComponentRulesV49150
            .recommend("Direct3D 11",false,true,true,true,false,true).backend),
            "Qualified DXVK backend");
        check("BLOCKED".equals(KernixComponentRulesV49150
            .recommend("Vulkan",false,true,true,true,true,false).backend),
            "Native Vulkan requires WSI");
        check("MANUAL_REVIEW".equals(KernixComponentRulesV49150
            .recommend("Direct3D 11",true,true,true,true,true,true).backend),
            "Protected game cannot be assumed supported");
        check("AUTO_PROBE".equals(KernixComponentRulesV49150
            .recommend("unknown",false,true,true,true,true,true).backend),
            "Unknown graphics API must not be forced to DXVK/VKD3D");
        System.out.println("KERNIX_COMPONENT_FREEZE_RULES_SMOKE_PASS");
    }
}
