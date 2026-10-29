package com.rm11.autocore.runtime;

import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Known official Steam Windows launch settings, limited to a validated
 * user-selected EXE basename. Never alter the Wine desktop, other games,
 * game files, registry, Vulkan ICD or wineserver.
 */
public final class GameLaunchFlagsV485 {
    private GameLaunchFlagsV485() {}
    public static List<String> argumentsFor(String filename) {
        // Device v49032 report proves the user launched "CarX Street.exe",
        // which was previously missed by the launcher-only rule. For Unity,
        // this command-line option requests D3D11 instead of D3D12.
        if(filename!=null && ("carx street.exe".equals(filename.toLowerCase(Locale.ROOT))
                ||"carx street launcher.exe".equals(filename.toLowerCase(Locale.ROOT))))
            return Collections.singletonList("-force-d3d11");
        return Collections.emptyList();
    }
}
