package com.rm11.autocore.runtime;

/**
 * Bounded read-only game log evidence: distinguishes successful loading of an
 * Android Vulkan SONAME from actual X11 presentation, and WineD3D's failed
 * desktop OpenGL initialization. Does NOT infer driver quality or patch WSI.
 */
public final class WineGraphicsBackendEvidence {
    private static final int MAX_LINE=600;
    private final StringBuilder partial=new StringBuilder();
    private boolean linuxVulkanSonameFailed;
    private boolean androidVulkanLoaderSucceeded;
    private boolean androidVulkanLoaderFailed;
    private boolean privateMesaLoaderRequested;
    private boolean privateMesaLoaderSucceeded;
    private boolean privateMesaLoaderFailed;
    private boolean desktopOpenGlMissing;
    private boolean wineOpenGlDisabled;
    private boolean wineD3dContextFailed;
    private boolean wineD3dPixelFormatFailed;
    private boolean nativeAbortObserved;
    private int linesObserved;
    private boolean truncatedLine;

    public synchronized void accept(String chunk) {
        if(chunk==null||chunk.isEmpty())return;
        for(int i=0;i<chunk.length();i++){
            char c=chunk.charAt(i);
            if(c=='\n'){
                inspect(partial.toString());
                partial.setLength(0);
                truncatedLine=false;
            }else if(partial.length()<MAX_LINE)partial.append(c);
            else truncatedLine=true;
        }
    }

    private void inspect(String line){
        linesObserved++;
        if(line.contains("Failed to load libvulkan.so.1"))
            linuxVulkanSonameFailed=true;
        if(line.contains("RM11_V458_ANDROID_VULKAN_DLOPEN_SUCCESS"))
            androidVulkanLoaderSucceeded=true;
        if(line.contains("RM11_V458_ANDROID_VULKAN_DLOPEN_FAILED"))
            androidVulkanLoaderFailed=true;
        if(line.contains("RM11_V479_PRIVATE_MESA_LOADER_REQUESTED"))
            privateMesaLoaderRequested=true;
        if(line.contains("RM11_V479_PRIVATE_MESA_VULKAN_DLOPEN_SUCCESS"))
            privateMesaLoaderSucceeded=true;
        if(line.contains("RM11_V479_PRIVATE_MESA_VULKAN_DLOPEN_FAILED"))
            privateMesaLoaderFailed=true;
        if(line.contains("Failed to load libGL:") && line.contains("libGL.so.1"))
            desktopOpenGlMissing=true;
        if(line.contains("OpenGL support is disabled"))
            wineOpenGlDisabled=true;
        if(line.contains("wined3d_adapter_gl_init Failed to get a GL context"))
            wineD3dContextFailed=true;
        if(line.contains("wined3d_caps_gl_ctx_create Failed to find a suitable pixel format"))
            wineD3dPixelFormatFailed=true;
        if(line.contains("RM11_V465_NATIVE_ABORT_CALLER_SEEN=true"))
            nativeAbortObserved=true;
    }

    public synchronized String snapshot(){
        // A successful dlopen is NOT proof of a working Vulkan device or WSI.
        String status=privateMesaLoaderSucceeded
            ?"PRIVATE_MESA_LOADER_REACHED_WSI_UNVERIFIED"
            :privateMesaLoaderFailed
            ?"PRIVATE_MESA_LOADER_DLOPEN_FAILED"
            :androidVulkanLoaderSucceeded
            ?"ANDROID_VULKAN_LOADER_REACHED_WSI_UNVERIFIED"
            :(linuxVulkanSonameFailed
                && (desktopOpenGlMissing||wineOpenGlDisabled))
                ?"VULKAN_AND_DESKTOP_OPENGL_UNAVAILABLE_IN_WINE_OUTPUT"
                :linuxVulkanSonameFailed?"VULKAN_SONAME_UNAVAILABLE"
                :(desktopOpenGlMissing||wineOpenGlDisabled)
                    ?"DESKTOP_OPENGL_UNAVAILABLE"
                    :"GRAPHICS_BACKEND_UNVERIFIED";
        return "RM11_V471_GRAPHICS_BACKEND_EVIDENCE\n"
            +"RM11_V471_LINES_READ="+linesObserved+"\n"
            +"RM11_V471_LINUX_VULKAN_SONAME_LOAD_FAILED="+linuxVulkanSonameFailed+"\n"
            +"RM11_V471_ANDROID_VULKAN_DLOPEN_SUCCESS="+androidVulkanLoaderSucceeded+"\n"
            +"RM11_V471_ANDROID_VULKAN_DLOPEN_FAILED="+androidVulkanLoaderFailed+"\n"
            +"RM11_V479_PRIVATE_MESA_LOADER_REQUESTED="+privateMesaLoaderRequested+"\n"
            +"RM11_V479_PRIVATE_MESA_DLOPEN_SUCCESS="+privateMesaLoaderSucceeded+"\n"
            +"RM11_V479_PRIVATE_MESA_DLOPEN_FAILED="+privateMesaLoaderFailed+"\n"
            +"RM11_V471_LIBGL_SO1_LOAD_FAILED="+desktopOpenGlMissing+"\n"
            +"RM11_V471_WINE_OPENGL_DISABLED="+wineOpenGlDisabled+"\n"
            +"RM11_V471_WINED3D_GL_CONTEXT_FAILED="+wineD3dContextFailed+"\n"
            +"RM11_V471_WINED3D_PIXEL_FORMAT_FAILED="+wineD3dPixelFormatFailed+"\n"
            +"RM11_V471_NATIVE_ABORT_IN_OUTPUT="+nativeAbortObserved+"\n"
            +"RM11_V471_WSI_PRESENTATION=UNVERIFIED\n"
            +"RM11_V471_DXVK_GAME_RENDERING=UNVERIFIED\n"
            +"RM11_V471_BACKEND_STATUS="+status+"\n";
    }
}
