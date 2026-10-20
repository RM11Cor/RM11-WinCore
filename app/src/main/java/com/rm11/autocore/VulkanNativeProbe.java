package com.rm11.autocore;

import org.json.JSONArray;
import org.json.JSONObject;

/** JNI Vulkan device smoke test: creates and destroys a logical device, no rendering. */
public final class VulkanNativeProbe {
    private VulkanNativeProbe() { }
    private static native String nativeProbe();

    public static final class Result {
        public final String displayText;
        public final String rawJson;
        public final boolean deviceCreated;
        Result(String report, String json, boolean created) {
            displayText=report; rawJson=json; deviceCreated=created;
        }
    }
    public static Result inspect() {
        final String raw;
        try {
            System.loadLibrary("rm11_vulkan_probe");
            raw=nativeProbe();
        } catch (LinkageError | SecurityException e) {
            String message="تعذر تحميل أداة Vulkan الأصلية: " + e.getClass().getSimpleName()
                    + "\nقد يكون APK مبنياً بدون مكتبة arm64-v8a أو ينقص تعريف Vulkan. لا يعني هذا أن الجهاز لا يدعم الرسومات.";
            return new Result(message,"",false);
        }
        try {
            JSONObject root=new JSONObject(raw);
            JSONArray devices=root.optJSONArray("devices");
            StringBuilder out=new StringBuilder("RM11 • اختبار Vulkan الحقيقي v2.4.11\n\n")
                    .append("حالة الفاحص: ").append(root.optString("status","unknown")).append("\n")
                    .append("إنشاء Vulkan Instance: ").append(root.optBoolean("instanceCreated")?"نجح":"فشل").append("\n")
                    .append("عدد أجهزة GPU التي أعلنها Vulkan: ").append(root.optInt("physicalDeviceCount",0)).append("\n");
            boolean anyCreated=false;
            if (devices!=null) for(int i=0;i<devices.length();i++) {
                JSONObject gpu=devices.optJSONObject(i);
                if(gpu==null) continue;
                int code=gpu.optInt("logicalDeviceCreateResult",-999);
                boolean made=code==0;
                anyCreated|=made;
                out.append("\nGPU ").append(i+1).append(": ").append(gpu.optString("name","unknown"))
                   .append("\nVulkan API الفعلية: ").append(gpu.optString("apiVersion","?"))
                   .append("\nVendor ID: ").append(gpu.optLong("vendorId"))
                   .append("\nGraphics Queue Families: ").append(gpu.optInt("graphicsQueueFamilies"))
                   .append("\nCompute Queue Families: ").append(gpu.optInt("computeQueueFamilies"))
                   .append("\nVK_KHR_swapchain: ").append(gpu.optBoolean("swapchainExtension")?"معلنة":"غير معلنة")
                   .append("\nVK_KHR_timeline_semaphore: ").append(gpu.optBoolean("timelineSemaphoreExtension")?"معلنة":"غير معلنة")
                   .append("\nRay tracing pipeline extension: ").append(gpu.optBoolean("rayTracingPipelineExtension")?"معلنة":"غير معلنة")
                   .append("\nAcceleration structure extension: ").append(gpu.optBoolean("accelerationStructureExtension")?"معلنة":"غير معلنة")
                   .append("\nإنشاء Vulkan Logical Device: ").append(made?"نجح":"لم ينجح (VkResult="+code+")")
                   .append("\n");
            }
            if(!root.optBoolean("instanceCreated")) out.append("\nVkResult: ").append(root.optInt("vkResult",-999));
            boolean graphics=false, swapchain=false;
            if(devices!=null) for(int i=0;i<devices.length();i++) {
                JSONObject gpu=devices.optJSONObject(i);
                if(gpu!=null && gpu.optInt("logicalDeviceCreateResult",-1)==0) {
                    graphics|=gpu.optInt("graphicsQueueFamilies",0)>0;
                    swapchain|=gpu.optBoolean("swapchainExtension");
                }
            }
            out.append("\nالنتيجة: ").append(VulkanEvidence.evaluate(root.optBoolean("instanceCreated"),
                root.optInt("physicalDeviceCount",0),anyCreated,graphics?1:0,swapchain));
            out.append("\n\nهذا اختبار للتعريف فقط، وليس اختبار عرض إطارات أو تنفيذ shaders أو DXVK/Turnip أو تشغيل EXE. إعلان الامتداد لا يضمن توافق Ray Tracing.");
            return new Result(out.toString(),raw,anyCreated);
        } catch (Exception e) {
            return new Result("تعذر تحليل نتيجة Vulkan: " + e.getClass().getSimpleName(),raw,false);
        }
    }
}
