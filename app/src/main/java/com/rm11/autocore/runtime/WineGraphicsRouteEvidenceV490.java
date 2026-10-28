package com.rm11.autocore.runtime;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Observes the REAL supervised Wine game child's stdout, plus read-only X11
 * snapshots. Does NOT change DLL overrides, Wine prefix, process env or games.
 *
 * A "native" d3d11.dll load alone is NOT proof of DXVK, a mapped X11
 * root child is NOT attributed to the selected game, and neither one is
 * proof of a Vulkan swapchain or a visible Android game frame.
 */
public final class WineGraphicsRouteEvidenceV490 {
    private static final int MAX_LINE=768;
    private static final Pattern MAPPED=Pattern.compile(
            "(?m)^x11_children_viewable=([0-9]{1,4})$");
    private final StringBuilder pending=new StringBuilder();
    private int lines;
    private boolean oversized;
    private boolean nativeD3d11;
    private boolean builtinD3d11;
    private boolean nativeDxgi;
    private boolean builtinDxgi;
    private boolean explicitDxvkInit;
    private boolean wineVulkanLoaded;
    private boolean wined3dVulkan;
    private boolean swapchainError;
    private boolean vulkanLoaderFailed;
    private boolean x11QueryOk;
    private boolean mappedX11Child;
    private boolean gameWindowOwnerVerified; // Never inferred from X11 root child counts.

    public synchronized void accept(String chunk) {
        if(chunk==null||chunk.isEmpty())return;
        for(int i=0;i<chunk.length();i++){
            char c=chunk.charAt(i);
            if(c=='\n'){
                inspect(pending.toString());
                pending.setLength(0);
            }else if(pending.length()<MAX_LINE)pending.append(c);
            else oversized=true;
        }
    }

    private void inspect(String line) {
        lines++;
        String lower=line.toLowerCase(Locale.ROOT);
        if(lower.contains("loaddll") && lower.contains("loaded")) {
            noteLoad(lower,"d3d11.dll",true);
            noteLoad(lower,"dxgi.dll",false);
            if(lower.contains("winevulkan"))wineVulkanLoaded=true;
        }
        // This indicates a DXVK log line observed in Wine stdout, NOT a
        // validated on-screen frame, correct vendor or real X11 swapchain.
        if((lower.contains("dxvk: v") || lower.contains("dxvk: dxvk") ||
                lower.contains("dxvk version:"))
                && lower.length()<MAX_LINE)explicitDxvkInit=true;
        if(lower.contains("using the vulkan renderer."))wined3dVulkan=true;
        if(lower.contains("vk_error_extension_not_present") ||
                lower.contains("vk_error_initialization_failed") ||
                lower.contains("vk_error_surface_lost_khr"))
            swapchainError=true;
        if(lower.contains("failed to load libvulkan.so.1") ||
                lower.contains("rm11_v479_private_mesa_vulkan_dlopen_failed"))
            vulkanLoaderFailed=true;
    }

    private void noteLoad(String line,String dll,boolean d3d11) {
        int at=line.indexOf(dll);
        if(at<0)return;
        String after=line.substring(at+dll.length());
        // In Wine +loaddll: "Loaded L\"...d3d11.dll\" at ...: native"
        // Test the load KIND, not a native-looking path. Exclude builtin.
        boolean nativeKind=after.matches("(?s).*:\\s*native(?:\\s|$).*");
        boolean builtinKind=after.matches("(?s).*:\\s*builtin(?:\\s|$).*");
        if(d3d11) {
            nativeD3d11|=nativeKind;
            builtinD3d11|=builtinKind;
        }else {
            nativeDxgi|=nativeKind;
            builtinDxgi|=builtinKind;
        }
    }

    /** X11 root-level inventory only; never assign window ownership. */
    public synchronized void acceptX11(String audit) {
        if(audit==null || !audit.contains("RM11_V410_X11_ROOT_WINDOW_QUERY_OK"))
            return;
        x11QueryOk=true;
        Matcher m=MAPPED.matcher(audit);
        if(m.find()){
            try {
                mappedX11Child |= Integer.parseInt(m.group(1))>0;
            }catch(NumberFormatException ignored){}
        }
    }

    public synchronized String snapshot() {
        // Do not count PE DLL load or DXVK log as Vulkan PRESENT success.
        String moduleState=explicitDxvkInit && nativeD3d11 && nativeDxgi
                ?"DXVK_MODULE_INIT_SIGNAL_ONLY_NO_FRAME_PROOF"
                :nativeD3d11 && nativeDxgi
                ?"NATIVE_D3D11_DXGI_LOADED_DXVK_UNCONFIRMED"
                :(builtinD3d11||builtinDxgi)
                ?"WINE_BUILTIN_D3D_MODULE_OBSERVED"
                :"DXVK_MODULE_LOAD_NOT_PROVEN";
        return "RM11_V490_LIVE_GAME_GRAPHICS_PATH_AUDIT\n"
                +"RM11_V490_WINE_OUTPUT_LINES="+lines+"\n"
                +"RM11_V490_OVERSIZED_LINES_TRUNCATED="+oversized+"\n"
                +"RM11_V490_D3D11_NATIVE_MODULE_OBSERVED="+nativeD3d11+"\n"
                +"RM11_V490_D3D11_BUILTIN_MODULE_OBSERVED="+builtinD3d11+"\n"
                +"RM11_V490_DXGI_NATIVE_MODULE_OBSERVED="+nativeDxgi+"\n"
                +"RM11_V490_DXGI_BUILTIN_MODULE_OBSERVED="+builtinDxgi+"\n"
                +"RM11_V490_EXPLICIT_DXVK_INIT_LOG_OBSERVED="+explicitDxvkInit+"\n"
                +"RM11_V490_WINEVULKAN_MODULE_LOAD_OBSERVED="+wineVulkanLoaded+"\n"
                +"RM11_V490_WINED3D_VULKAN_RENDERER_OBSERVED="+wined3dVulkan+"\n"
                +"RM11_V490_VULKAN_LOADER_ERROR_OBSERVED="+vulkanLoaderFailed+"\n"
                +"RM11_V490_VULKAN_SURFACE_OR_INIT_ERROR_OBSERVED="+swapchainError+"\n"
                +"RM11_V490_X11_ROOT_QUERY_OK="+x11QueryOk+"\n"
                +"RM11_V490_X11_VIEWABLE_ROOT_CHILD_OBSERVED="+mappedX11Child+"\n"
                +"RM11_V490_X11_WINDOW_BELONGS_TO_SELECTED_GAME="+gameWindowOwnerVerified+"\n"
                +"RM11_V490_DXVK_MODULE_STATUS="+moduleState+"\n"
                +"RM11_V490_PRIVATE_TURNIP_IN_WINE_PROCESS=NOT_PROVEN\n"
                +"RM11_V490_X11_VULKAN_SWAPCHAIN_PRESENT=NOT_PROVEN\n"
                +"RM11_V490_ANDROID_GAME_FRAME_VISIBLE=NOT_PROVEN\n"
                +"RM11_V490_NO_GAME_FILES_OR_PREFIX_MODIFIED=true\n";
    }
}
