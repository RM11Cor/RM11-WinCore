package com.rm11.autocore;

import android.view.Surface;
import org.json.JSONObject;

/** One invocation, five distinguishable checks; DXVK is NOT launched by this Android-only app. */
public final class VulkanSuite {
    private VulkanSuite() { }
    private static final boolean LIBRARY_LOADED;
    static {
        boolean ok;
        try { System.loadLibrary("rm11_vulkan_suite"); ok = true; }
        catch (LinkageError | SecurityException exception) { ok = false; }
        LIBRARY_LOADED = ok;
    }
    private static native String nativeRun(Surface surface);

    public static String run(Surface surface) {
        if (!LIBRARY_LOADED) return "RM11 v2.4.12\nفشل تحميل مكتبة Vulkan Suite للمعمارية arm64-v8a.";
        if (surface == null || !surface.isValid()) return "RM11 v2.4.12\nSurface غير جاهزة.";
        final String json;
        try { json = nativeRun(surface); }
        catch (LinkageError | RuntimeException exception) {
            return "RM11 v2.4.12\nخطأ JNI: " + exception.getClass().getSimpleName();
        }
        try {
            JSONObject d = new JSONObject(json);
            boolean modules = d.optBoolean("shaderModules");
            boolean graphics = d.optBoolean("trianglePresented");
            boolean hasCompute = d.optBoolean("computeAvailable");
            boolean computed = d.optBoolean("computeVerified");
            boolean gpuTime = d.optBoolean("timestampMeasured");
            int frames = d.optInt("frames");
            String success = "نجح";
            String unavailable = "غير متوفر / لم يُقَس";
            StringBuilder out = new StringBuilder("RM11-WinCore v2.4.12 — التقرير الموحد\n\n")
                .append("GPU: ").append(d.optString("gpu", "unknown")).append("\n")
                .append("Vulkan API: ").append(d.optInt("apiMajor")).append(".").append(d.optInt("apiMinor")).append("\n")
                .append("الدقة: ").append(d.optInt("width")).append(" × ").append(d.optInt("height")).append("\n\n")
                .append("1) Vertex/Fragment Shader Modules: ").append(modules ? success : "لم ينجح").append("\n")
                .append("2) Graphics Pipeline + Triangle + Present: ").append(graphics ? success : "لم ينجح")
                .append(" (الإطارات ").append(frames).append(" / 240)\n")
                .append("3) Compute Shader (256 نتيجة مع قراءة GPU): ")
                .append(!hasCompute ? unavailable : computed ? success : "فشل / غير متاح")
                .append(" — mismatches: ").append(d.optInt("computeMismatches", -1)).append("\n")
                .append("4) GPU Timestamps: ").append(gpuTime ? success : unavailable).append("\n");
            if (gpuTime) out.append("    متوسط نطاق أوامر GPU: ")
                .append(d.optDouble("gpuAvgMs")).append(" ms (لا يشمل وقت عرض الشاشة)\n");
            out.append("    معدل تقديم الإطارات: ").append(d.optDouble("fps"))
                .append(" FPS ؛ متوسط وقت الإطار: ").append(d.optDouble("frameMs")).append(" ms\n")
                .append("5) DXVK prerequisite inventory (معلومات فقط):\n")
                .append("    Descriptor indexing: ").append(yes(d,"descriptorIndexingAdvertised")).append("\n")
                .append("    Timeline semaphore: ").append(yes(d,"timelineAdvertised")).append("\n")
                .append("    Memory budget: ").append(yes(d,"memoryBudgetAdvertised")).append("\n")
                .append("    DXVK executed: لا — Wine/FEX/DXVK غير مدمجة بهذا الإصدار\n\n")
                .append("VkResult: ").append(d.optInt("vkResult", -999)).append("\n")
                .append("Stage: ").append(d.optString("stage")).append("\n\n")
                .append("مهم: هذه نتائج Vulkan الأصلية. ليست اختبار ألعاب Windows أو FPS ألعاب، ")
                .append("وقيم FPS تشمل انتظار تقديم الإطارات ومزامنة CPU.\n\n")
                .append("Raw JSON:\n").append(json);
            return out.toString();
        } catch (Exception e) {
            return "خطأ تحليل نتائج Vulkan Suite: " + e.getClass().getSimpleName() + "\nRaw:\n" + json;
        }
    }
    private static String yes(JSONObject data, String key) {
        return data.optBoolean(key) ? "معلن/مدعوم بالإصدار الأساسي" : "لم يُثبت / غير معلن";
    }
}
