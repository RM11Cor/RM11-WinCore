package com.rm11.autocore.runtime;

import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Wine 11 supports WINE_D3D_CONFIG=renderer=vulkan. Only the selected game's
 * child gets this flag after the device-proven private Mesa+software WSI path
 * is accepted. Wineserver, desktop, Wine prefix and unrelated apps stay intact.
 */
public final class WineD3dVulkanRouteV481 {
    private WineD3dVulkanRouteV481(){}

    public static String apply(String privateWsi, Map<String,String> env) {
        if(env==null)return "DENIED_NULL_ENV";
        if(!"ENABLED_GAME_ONLY_SW_WSI".equals(privateWsi))
            return "NOT_PROVEN_KEEP_BASELINE";
        String previous=env.get("WINE_D3D_CONFIG");
        if(previous!=null && previous.length()>4096)
            return "DENIED_OVERSIZED_EXISTING_CONFIG";
        List<String> options=new ArrayList<>();
        if(previous!=null)for(String item:previous.split("[,;]")) {
            String value=item.trim();
            if(value.isEmpty())continue;
            String key=value.contains("=")?
                    value.substring(0,value.indexOf('=')).trim():value;
            if(!"renderer".equals(key.toLowerCase(Locale.ROOT)))
                options.add(value);
        }
        options.add("renderer=vulkan");
        env.put("WINE_D3D_CONFIG",String.join(";",options));
        return "ENABLED_PRIVATE_VULKAN";
    }
}
