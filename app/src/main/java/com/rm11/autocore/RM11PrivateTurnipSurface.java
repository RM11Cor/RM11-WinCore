package com.rm11.autocore;

import android.view.Surface;
import com.rm11.autocore.runtime.EngineVNextGraphicsManifestGate;
import android.content.Context;
import java.nio.file.Path;
import org.json.JSONObject;

/**
 * Never falls back to Android's system Vulkan loader.
 * WSI (even 60 successful frames) is not proof of Wine/DXVK game rendering.
 */
public final class RM11PrivateTurnipSurface {
    private RM11PrivateTurnipSurface() {}
    private static native String nativeRun(Surface surface, String signedICDPath, int frames);

    public static JSONObject run(Context context, Surface surface, int frames) throws Exception {
        if (context==null || surface==null || !surface.isValid())
            throw new IllegalStateException("RM11_PRIVATE_TURNIP_SURFACE_NOT_READY");
        EngineVNextGraphicsManifestGate.Verified proof=
                EngineVNextGraphicsManifestGate.inspect(context);
        Path nativeICD=proof.signedNativeDirectory.resolve("libvulkan_freedreno.so");
        System.loadLibrary("rm11_private_turnip_surface");
        JSONObject result=new JSONObject(nativeRun(surface,nativeICD.toString(),
                Math.min(60,Math.max(12,frames))));
        if(!"rm11.turnip-android-wsi.v1".equals(result.getString("schema")) ||
                !result.getBoolean("private_turnip_icd") ||
                result.getBoolean("wine_dxvk_proven"))
            throw new IllegalStateException("RM11_PRIVATE_TURNIP_WSI_SCHEMA_REJECTED");
        return result;
    }
}
