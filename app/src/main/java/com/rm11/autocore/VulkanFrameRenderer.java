package com.rm11.autocore;

import android.view.Surface;
import org.json.JSONObject;

/** A real Vulkan swapchain + queue submission + presentation test.
 *  Does not imply shader, DXVK/Turnip, ray-tracing, or EXE compatibility.
 */
public final class VulkanFrameRenderer {
    private VulkanFrameRenderer() {}
    private static final boolean LOADED;
    static {
        boolean ok;
        try { System.loadLibrary("rm11_vulkan_render"); ok = true; }
        catch (LinkageError | SecurityException e) { ok = false; }
        LOADED = ok;
    }
    private static native String nativeRun(Surface surface, int frames);

    public static String run(Surface surface, int frames) {
        if (!LOADED) return "تعذر تحميل مكتبة اختبار الرسم الأصلية arm64-v8a.";
        if (surface == null || !surface.isValid()) return "Surface غير جاهزة؛ انتظر ظهور مساحة الاختبار.";
        try {
            JSONObject data = new JSONObject(nativeRun(surface, Math.max(30, Math.min(frames, 300))));
            StringBuilder out = new StringBuilder("RM11 Vulkan Surface Renderer v2.4.11\n\n")
                .append("الحالة: ").append(data.optBoolean("success") ? "نجاح" : "فشل").append("\n")
                .append("المعالج: ").append(data.optString("gpu", "unknown")).append("\n")
                .append("الدقة: ").append(data.optInt("width")).append(" × ").append(data.optInt("height")).append("\n")
                .append("الإطارات المقدمة: ").append(data.optInt("frames")).append("\n")
                .append("معدل تقديم الإطارات: ").append(data.optDouble("fps")).append(" FPS\n")
                .append("متوسط وقت الإطار: ").append(data.optDouble("frameMs")).append(" ms\n")
                .append("VkResult: ").append(data.optInt("vkResult")).append("\n")
                .append("المرحلة: ").append(data.optString("stage")).append("\n\n")
                .append("هذا اختبار مسح لوني على صور Swapchain وإرسال أوامر Vulkan وعرضها؛ ")
                .append("لا ينفّذ Shaders ولا يقيس زمن GPU الداخلي ولا يثبت تشغيل DXVK أو ألعاب Windows.");
            return out.toString();
        } catch (Exception e) {
            return "تعذر تنفيذ / قراءة اختبار Vulkan: " + e.getClass().getSimpleName();
        }
    }
}
