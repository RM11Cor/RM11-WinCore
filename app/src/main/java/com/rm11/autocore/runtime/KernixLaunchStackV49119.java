package com.rm11.autocore.runtime;

import java.io.IOException;
import java.util.Map;

/**
 * The authoritative per-process runtime binding. Wine, FEX's ARM64EC DLL
 * loader, X11 and VKD3D must share the same user, prefix and process
 * environment. Graphics drivers must NOT replace the Wine/FEX HOME.
 *
 * This reconciles only the new EXE's ProcessBuilder environment. It does
 * not change the global Android environment, another game, the Wine
 * prefix's contents, GPU drivers or the X11 host.
 */
public final class KernixLaunchStackV49119 {
    private KernixLaunchStackV49119(){}

    // These are identity values from the actual WineExecutionPlan. Do not
    // hardcode paths or versions: every runtime must use its own closure.
    private static final String[] IDENTITY={
        "HOME","USER","WINEPREFIX","WINESERVER",
        "HODLL64","HODLL","WINEDLLPATH","RM11_WINE_PE_DIR",
        "RM11_WINE_DATADIR","RM11_WINE_NTDLL_VIRTUAL_PATH","DISPLAY"
    };

    /** Keep the game/graphics linker closure first. Native Winebus extras
     * are appended, never prepended over private Vulkan or Wine libraries. */
    public static String mergeNativeLibraryPaths(String game,String winebus)
            throws IOException{
        if((game!=null&&game.length()>16384)
                ||(winebus!=null&&winebus.length()>16384))
            throw new IOException("KERNIX_NATIVE_LIBRARY_PATH_TOO_LONG");
        java.util.LinkedHashSet<String> entries=new java.util.LinkedHashSet<>();
        for(String source:new String[]{game,winebus}){
            if(source==null)continue;
            for(String raw:source.split(":",-1)){
                String path=raw.trim();
                if(path.isEmpty())continue;
                // Empty entries evaluate to the current directory with
                // dynamic linkers; never introduce that into the Wine child.
                entries.add(path);
            }
        }
        return String.join(":",entries);
    }

    /** Avoid environment-specific API assumptions: the process includes the
     * renderer chosen after compatibility inspection and the actual staged DLLs. */
    public static String reconcile(Map<String,String> baseline,
          Map<String,String> game,String graphics,boolean signedProbe)
          throws IOException {
        if(baseline==null||game==null)
            throw new IOException("KERNIX_ENGINE_ENV_MISSING");
        // FEX's PE and Unix translation layers must be the SAME pair that
        // WineExecutionPlan assembled, even after downstream graphics stages.
        for(String key:new String[]{"HOME","WINEPREFIX","WINESERVER",
                                    "HODLL64","HODLL","WINEDLLPATH","DISPLAY"}){
            String value=baseline.get(key);
            if(value==null||value.trim().isEmpty())
                throw new IOException("KERNIX_ENGINE_BASELINE_INCOMPLETE:"+key);
        }
        int repaired=0;
        for(String key:IDENTITY){
            String expected=baseline.get(key);
            if(expected!=null && !expected.isEmpty()
                    &&!expected.equals(game.get(key))){
                game.put(key,expected);
                repaired++;
            }
        }
        boolean d3d12=R4GameRuntimeConfigV49066.VKD3D.equals(graphics);
        boolean dxvk=R4GameRuntimeConfigV49066.DXVK.equals(graphics);
        if(d3d12||dxvk)
            WineD3dVulkanRouteV481.clearForcedRenderer(game);
        if(d3d12){
            if(!"sw".equals(game.get("MESA_VK_WSI_DEBUG")))
                throw new IOException("KERNIX_DX12_X11_CLOSURE_NOT_SELECTED");
            if(!game.containsKey("VK_DRIVER_FILES")
                    ||!game.containsKey("VK_ICD_FILENAMES"))
                throw new IOException("KERNIX_DX12_VULKAN_ICD_NOT_BOUND");
            if(!game.get("VK_DRIVER_FILES").equals(game.get("VK_ICD_FILENAMES")))
                throw new IOException("KERNIX_DX12_MIXED_VULKAN_ICD");
        }
        // Keep mini-test environment unchanged; shrink real game stderr,
        // while retaining critical Wine and module-load messages.
        if(!signedProbe)game.put("WINEDEBUG","+err,+warn,+loaddll");
        return "KERNIX_V49119_COHERENT_ENGINE=true\n"
            +"KERNIX_V49119_HOME_PREFIX_IDENTITY_REPAIRED="+repaired+"\n"
            +"KERNIX_V49119_FEX_ARM64EC_PAIR_FROM_BASELINE=true\n"
            +"KERNIX_V49119_GRAPHICS="+graphics+"\n"
            +"KERNIX_V49119_VKD3D_SEPARATE_FROM_WINED3D="+d3d12+"\n"
            +"KERNIX_V49119_DXVK_SEPARATE_FROM_WINED3D="+dxvk+"\n"
            +"KERNIX_V49119_GAME_DEBUG_PRODUCTION_MODE="+(!signedProbe)+"\n"
            +"KERNIX_V49119_GAME_FRAMES_UNVERIFIED=true\n"
            +"KERNIX_V49119_OTHER_GAMES_OR_PREFIX_MODIFIED=false";
    }
}
