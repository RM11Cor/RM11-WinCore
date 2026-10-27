package com.rm11.autocore.engine;

import java.io.IOException;
import java.util.Locale;
import java.util.Map;

/**
 * Reject known software/diagnostic Vulkan WSI routes in a future real
 * hardware-game session. An accepted result is NOT proof of an actual
 * hardware frame; activation still requires signed ICD+DXVK proof and
 * real physical Android display validation.
 */
public final class EngineHardwareWsiPolicy {
    private EngineHardwareWsiPolicy(){}

    public static void requireNoSoftwareWsi(Map<String,String> env)
            throws IOException {
        if(env==null)throw new IOException("ENGINE_GRAPHICS_ENV_MISSING");
        String wsi=env.get("MESA_VK_WSI_DEBUG");
        if(wsi!=null){
            for(String token:wsi.toLowerCase(Locale.ROOT).split("[,; ]+")){
                if("sw".equals(token))
                    throw new IOException("ENGINE_SOFTWARE_WSI_CANNOT_CERTIFY_HARDWARE");
            }
        }
        if("1".equals(env.get("RM11_V479_PRIVATE_VULKAN_GAME")))
            throw new IOException("ENGINE_LEGACY_SOFTWARE_VULKAN_PROBE_NOT_RENDERER");
    }
}
