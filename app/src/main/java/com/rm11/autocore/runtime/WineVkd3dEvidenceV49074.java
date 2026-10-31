package com.rm11.autocore.runtime;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Diagnostic-only: lossless decision markers from a D3D12 Wine process.
 * Keeps first/last ERROR-bearing lines instead of mistaking successful Wine
 * handoff or vkDestroyDevice alone for proof of rendered game frames. */
public final class WineVkd3dEvidenceV49074 {
    private static final int LINE_CAP=1600;
    private final StringBuilder pending=new StringBuilder();
    private final List<String> first=new ArrayList<>();
    private final List<String> recent=new ArrayList<>();
    private final String gameName;
    private int lines,criticalLines,overflow;
    private boolean vkd3dSeen,deviceCreated,deviceDestroyed,d3d12Native,dxgiNative;
    private boolean VulkanInitError,deviceLost,swapchainError,fatalObserved;
    public WineVkd3dEvidenceV49074(String game){
        gameName=game==null?"UNKNOWN":game;
    }
    public synchronized void accept(String chunk){
        if(chunk==null)return;
        for(int i=0;i<chunk.length();i++){
            char c=chunk.charAt(i);
            if(c=='\n'){
                inspect(pending.toString());
                pending.setLength(0);
            }else if(pending.length()<LINE_CAP)pending.append(c);
            else overflow++;
        }
    }
    private void inspect(String line){
        lines++;
        String lower=line.toLowerCase(Locale.ROOT);
        boolean vkd3d=lower.contains("vkd3d-proton");
        vkd3dSeen|=vkd3d;
        if(lower.contains("loaddll")&&lower.contains("native")){
            if(lower.contains("d3d12.dll")||lower.contains("d3d12core.dll"))d3d12Native=true;
            if(lower.contains("dxgi.dll"))dxgiNative=true;
        }
        if(lower.contains("vkcreatedevice")||lower.contains("vkd3d_create_device")
                ||lower.contains("created vulkan device"))deviceCreated=true;
        if(lower.contains("vkdestroydevice"))deviceDestroyed=true;
        if(lower.contains("vk_error_device_lost")||lower.contains("device lost")
                ||lower.contains("device_removed"))deviceLost=true;
        if(lower.contains("vk_error_initialization_failed")
                ||lower.contains("vk_error_extension_not_present")
                ||lower.contains("failed to create vulkan")
                ||lower.contains("vk_error_incompatible_driver"))VulkanInitError=true;
        if(lower.contains("vkcreateswapchain")||lower.contains("swapchain failed")
                ||lower.contains("vk_error_surface_lost"))swapchainError=true;
        boolean serious=(lower.contains("err:")||lower.contains("error:")||
           lower.contains("fatal")||lower.contains("vk_error")||
           lower.contains("exception")||lower.contains("assert")||
           lower.contains("failed to")||lower.contains("unsupported")||
           lower.contains("dxgi_error"));
        // Keep important VKD3D info but avoid swamping error records.
        boolean keep=serious || (vkd3d && (lower.contains("device")
            || lower.contains("adapter") || lower.contains("vulkan")
            || lower.contains("feature") || lower.contains("extension")));
        if(serious)fatalObserved=true; // "important" is NOT proof of a fatal crash.
        if(!keep)return;
        criticalLines++;
        // Single Windows filepath or user ID may appear in Wine text; journal
        // sanitizer redacts it at persist time. Bound line length here first.
        String item=line.length()>700?line.substring(0,700):line;
        if(first.size()<8)first.add(item);
        recent.add(item);
        if(recent.size()>14)recent.remove(0);
    }
    public synchronized String snapshot(){
        StringBuilder b=new StringBuilder();
        b.append("R4_V49074_GAME=").append(gameName).append('\n');
        b.append("R4_V49074_WINE_LINES=").append(lines).append('\n');
        b.append("R4_V49074_OVERFLOW_CHARACTERS=").append(overflow).append('\n');
        b.append("R4_V49074_INTERESTING_LINES=").append(criticalLines).append('\n');
        b.append("R4_V49074_VKD3D_PROTON_LOG_OBSERVED=").append(vkd3dSeen).append('\n');
        b.append("R4_V49074_D3D12_NATIVE_DLL_OBSERVED=").append(d3d12Native).append('\n');
        b.append("R4_V49074_DXGI_NATIVE_DLL_OBSERVED=").append(dxgiNative).append('\n');
        b.append("R4_V49074_VULKAN_DEVICE_CREATE_LOG=").append(deviceCreated).append('\n');
        b.append("R4_V49074_VULKAN_DEVICE_DESTROY_LOG=").append(deviceDestroyed).append('\n');
        b.append("R4_V49074_VULKAN_INIT_ERROR_SIGNAL=").append(VulkanInitError).append('\n');
        b.append("R4_V49074_DEVICE_LOST_SIGNAL=").append(deviceLost).append('\n');
        b.append("R4_V49074_SWAPCHAIN_FAILURE_SIGNAL=").append(swapchainError).append('\n');
        b.append("R4_V49074_ERROR_LINE_SEEN=").append(fatalObserved).append('\n');
        b.append("R4_V49074_ANDROID_FRAME_VISIBLE=NOT_PROVEN\n");
        b.append("R4_V49074_FIRST_CRITICAL_LINES:\n");
        for(String s:first)b.append(s).append('\n');
        b.append("R4_V49074_LAST_CRITICAL_LINES:\n");
        for(String s:recent)b.append(s).append('\n');
        return b.toString();
    }
}
