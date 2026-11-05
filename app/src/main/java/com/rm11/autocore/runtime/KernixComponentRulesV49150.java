package com.rm11.autocore.runtime;

import java.util.Locale;

/** KERNIX component freeze v1. Pure, deterministic choices; never starts Wine.
 * Device proofs and packaged files MUST be supplied separately by the caller.
 */
public final class KernixComponentRulesV49150 {
    private KernixComponentRulesV49150() {}

    public enum State { MISSING, PACKAGED_UNVERIFIED, DEVICE_QUALIFIED }
    public static State state(boolean filesPresent, boolean deviceQualified) {
        if (!filesPresent) return State.MISSING;
        return deviceQualified ? State.DEVICE_QUALIFIED : State.PACKAGED_UNVERIFIED;
    }

    public static final class Plan {
        public final String backend, reason;
        public final boolean attemptAllowed;
        private Plan(String backend,String reason,boolean allowed) {
            this.backend=backend;this.reason=reason;this.attemptAllowed=allowed;
        }
    }
    private static Plan decision(String backend,String reason,boolean allowed) {
        return new Plan(backend,reason,allowed);
    }

    /** A recommendation is not runtime proof, and never changes a game's
     * explicit saved choice. D3D12 never silently falls back to WineD3D.
     * Protected games need an independent compatibility assessment.
     */
    public static Plan recommend(String api,boolean anticheat,
            boolean win32GuiQualified,boolean wineD3dPresent,
            boolean dxvkQualified,boolean vkd3dQualified,
            boolean nativeVulkanQualified) {
        if (anticheat)
            return decision("MANUAL_REVIEW","ANTICHEAT_REQUIRES_COMPATIBILITY_REVIEW",false);
        if (!win32GuiQualified)
            return decision("BLOCKED","WIN32_GUI_NOT_DEVICE_QUALIFIED",false);
        String token=api==null?"":api.toUpperCase(Locale.ROOT);
        if (token.contains("DIRECT3D 12")||token.contains("DIRECTX 12")
                ||token.contains("D3D12")||token.contains("DX12"))
            return vkd3dQualified
                ?decision("VKD3D","DEVICE_VERIFIED_D3D12_ROUTE",true)
                :decision("BLOCKED","D3D12_REQUIRES_VKD3D_DEVICE_PROOF",false);
        if (token.contains("DIRECT3D 11")||token.contains("DIRECTX 11")
                ||token.contains("D3D11")||token.contains("DX11"))
            return dxvkQualified
                ?decision("DXVK","DEVICE_VERIFIED_D3D11_ROUTE",true)
                :wineD3dPresent
                    ?decision("WINED3D","PACKAGED_WINE_FALLBACK_NOT_FRAME_PROOF",true)
                    :decision("BLOCKED","NO_D3D11_BACKEND",false);
        if (token.contains("VULKAN"))
            return nativeVulkanQualified
                ?decision("NATIVE_VULKAN","NATIVE_GPU_WSI_DEVICE_PROOF",true)
                :decision("BLOCKED","NATIVE_VULKAN_WSI_NOT_QUALIFIED",false);
        if (token.contains("DIRECT3D 9")||token.contains("DIRECTX 9")
                ||token.contains("D3D9")||token.contains("DX9")
                ||token.contains("DIRECT3D 10")||token.contains("D3D10"))
            return wineD3dPresent
                ?decision("WINED3D","PACKAGED_D3D9_D3D10_FALLBACK_NOT_PROOF",true)
                :decision("BLOCKED","WINED3D_NOT_PACKAGED",false);
        return decision("AUTO_PROBE","API_UNDETERMINED_NO_FORCED_PROVIDER",true);
    }
}
