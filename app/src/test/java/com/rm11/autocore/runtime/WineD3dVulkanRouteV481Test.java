package com.rm11.autocore.runtime;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import org.junit.Test;
import java.util.HashMap;
import java.util.Map;

public final class WineD3dVulkanRouteV481Test {
    @Test public void neverChangesUnprovenProcess() {
        Map<String,String> environment=new HashMap<>();
        environment.put("WINE_D3D_CONFIG","renderer=gl;csmt=1");
        assertEquals("NOT_PROVEN_KEEP_BASELINE",
            WineD3dVulkanRouteV481.apply("SKIPPED_NO_V478_PROOF",environment));
        assertEquals("renderer=gl;csmt=1",environment.get("WINE_D3D_CONFIG"));
        assertNull(new HashMap<String,String>().get("WINE_D3D_CONFIG"));
    }
    @Test public void selectsWine11VulkanAndPreservesUnrelatedKeys() {
        Map<String,String> env=new HashMap<>();
        env.put("WINE_D3D_CONFIG","csmt=0x1;Renderer=gl;VideoPciVendorID=0xc0de");
        assertEquals("ENABLED_PRIVATE_VULKAN",
            WineD3dVulkanRouteV481.apply("ENABLED_GAME_ONLY_SW_WSI",env));
        assertEquals("csmt=0x1;VideoPciVendorID=0xc0de;renderer=vulkan",
            env.get("WINE_D3D_CONFIG"));
    }
    @Test public void startsFromEmptyEnvironmentAndHandlesNull() {
        Map<String,String> env=new HashMap<>();
        assertEquals("ENABLED_PRIVATE_VULKAN",
            WineD3dVulkanRouteV481.apply("ENABLED_GAME_ONLY_SW_WSI",env));
        assertEquals("renderer=vulkan",env.get("WINE_D3D_CONFIG"));
        assertEquals("DENIED_NULL_ENV",
            WineD3dVulkanRouteV481.apply("ENABLED_GAME_ONLY_SW_WSI",null));
    }
}
