package com.fh5.port;

import android.view.Surface;
import org.json.JSONObject;

/**
 * Native Vulkan presentation gate, not a Forza game-code runtime.
 * No Bannerlator, Winlator, Wine or external app is launched.
 */
public final class VulkanBridge {
    private VulkanBridge() {}
    private static final boolean READY;
    static {
        boolean loaded;
        try { System.loadLibrary("fh5_renderer"); loaded = true; }
        catch (LinkageError | SecurityException ex) { loaded = false; }
        READY = loaded;
    }
    private static native String nativeRun(Surface surface, int frameCount);

    public static JSONObject test(Surface surface) {
        JSONObject obj = new JSONObject();
        try {
            if (!READY) {
                obj.put("success", false);
                obj.put("stage", "arm64_library_unavailable");
                return obj;
            }
            if (surface == null || !surface.isValid()) {
                obj.put("success", false);
                obj.put("stage", "android_surface_unavailable");
                return obj;
            }
            return new JSONObject(nativeRun(surface, 90));
        } catch (Exception | UnsatisfiedLinkError e) {
            try { obj.put("success", false).put("stage", "bridge_exception"); }
            catch (Exception ignored) { }
            return obj;
        }
    }
}
