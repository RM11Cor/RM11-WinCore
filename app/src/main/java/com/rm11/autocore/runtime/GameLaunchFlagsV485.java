package com.rm11.autocore.runtime;

import java.util.Collections;
import java.util.List;

/**
 * Known official Steam Windows launch settings, limited to a validated
 * user-selected EXE basename. Never alter the Wine desktop, other games,
 * game files, registry, Vulkan ICD or wineserver.
 */
public final class GameLaunchFlagsV485 {
    private GameLaunchFlagsV485() {}
    public static List<String> argumentsFor(String filename) {
        if("CarX Street Launcher.exe".equals(filename))
            return Collections.singletonList("-force-d3d11");
        return Collections.emptyList();
    }
}
