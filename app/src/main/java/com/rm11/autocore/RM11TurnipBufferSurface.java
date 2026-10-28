package com.rm11.autocore;

import android.content.Context;
import android.view.Surface;
import com.rm11.autocore.runtime.EngineVNextGraphicsManifestGate;
import org.json.JSONObject;
import java.nio.file.Path;

/** Private Turnip GPU-buffer readback -> CPU Android NativeWindow.
 * This cannot enable Vulkan WSI, DXVK, or render game windows.
 */
public final class RM11TurnipBufferSurface {
    private RM11TurnipBufferSurface(){}
    private static native String nativeRun(Surface surface,String signedDriver,int frames);

    public static JSONObject run(Context context,Surface surface,int frames) throws Exception {
        if(context==null||surface==null||!surface.isValid())
            throw new IllegalArgumentException("RM11_NATIVE_SURFACE_REQUIRED");
        EngineVNextGraphicsManifestGate.Verified verified=
                EngineVNextGraphicsManifestGate.inspect(context);
        if(verified.hashVerifiedComponents!=9)
            throw new IllegalStateException("RM11_PRIVATE_TURNIP_MANIFEST_INVALID");
        Path nativeDriver=verified.signedNativeDirectory.resolve("libvulkan_freedreno.so");
        System.loadLibrary("rm11_turnip_buffer_surface");
        JSONObject data=new JSONObject(nativeRun(surface,nativeDriver.toString(),
                Math.max(6,Math.min(frames,24))));
        if(!"rm11.private-turnip-gpu-cpu-surface.v1".equals(data.getString("schema"))
                ||!data.getBoolean("private_icd")
                ||data.getBoolean("vulkan_swapchain_proven")
                ||data.getBoolean("wine_dxvk_proven")
                ||data.getBoolean("game_engine_activated"))
            throw new IllegalStateException("RM11_GPU_CPU_BRIDGE_REPORT_SCHEMA_REJECTED");
        return data;
    }
}
