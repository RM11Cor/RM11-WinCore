package com.rm11.autocore;

import java.nio.file.Path;
import org.json.JSONObject;

/** Only private, signed APK Turnip ICD; never selects a system Vulkan driver. */
public final class RM11TurnipGpuProof {
    private RM11TurnipGpuProof(){}
    private static native String nativeRun(String trustedNativeLibraryPath);

    public static JSONObject run(Path signedDriver) throws Exception {
        if (signedDriver==null ||
                !"libvulkan_freedreno.so".equals(signedDriver.getFileName().toString()))
            throw new IllegalArgumentException("RM11_GPU_PROOF_PINNED_TURNIP_REQUIRED");
        System.loadLibrary("rm11_turnip_gpu_submit");
        JSONObject data=new JSONObject(nativeRun(signedDriver.toString()));
        if (!"rm11.turnip-gpu-transfer.v1".equals(data.getString("schema")) ||
                data.getBoolean("android_display_frame_proven") ||
                data.getBoolean("wine_dxvk_proven") ||
                data.getBoolean("x11_swapchain_proven") ||
                data.getBoolean("game_engine_activated"))
            throw new IllegalStateException("RM11_GPU_PROOF_SCHEMA_REJECTED");
        return data;
    }
}
