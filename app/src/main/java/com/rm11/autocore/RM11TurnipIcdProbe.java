package com.rm11.autocore;

import org.json.JSONObject;
import java.nio.file.Path;

/**
 * Isolated-process JNI dispatch to exactly the APK-native signed Turnip ICD.
 * The caller must verify the signed graphics manifest before this call.
 * No app-wide Vulkan loader replacement or game activation is performed.
 */
public final class RM11TurnipIcdProbe {
    private RM11TurnipIcdProbe(){}
    private static native String nativeInspect(String signedDriverPath);

    public static JSONObject inspect(Path trustedSignedTurnip) throws Exception {
        if(trustedSignedTurnip==null ||
                !"libvulkan_freedreno.so".equals(
                    trustedSignedTurnip.getFileName().toString()))
            throw new IllegalArgumentException("TURNIP_ICD_SIGNED_PATH_REQUIRED");
        System.loadLibrary("rm11_turnip_icd_probe");
        JSONObject result=new JSONObject(nativeInspect(trustedSignedTurnip.toString()));
        if(!"rm11.turnip-icd-device.v1".equals(result.getString("schema"))
                ||result.getBoolean("game_activation")
                ||result.getBoolean("hardware_frame_proof")
                ||result.getBoolean("wine_dxvk_tested")
                ||result.getBoolean("x11_swapchain_tested"))
            throw new IllegalStateException("TURNIP_ICD_DIAGNOSTIC_UNTRUSTED");
        return result;
    }
}
