package com.rm11.autocore;

/** Pure-Java decision gate. A Vulkan probe is NOT proof of Windows-game compatibility. */
public final class VulkanEvidence {
    private VulkanEvidence() { }
    public static String evaluate(boolean instanceCreated, int physicalDeviceCount,
                                  boolean logicalDeviceCreated, int graphicsQueues,
                                  boolean swapchainExtension) {
        if (!instanceCreated) return "تعذر إنشاء Vulkan Instance؛ يلزم فحص التعريف قبل متابعة المحرك.";
        if (physicalDeviceCount<=0) return "Vulkan Instance نجح لكن لم يتم إيجاد GPU؛ التشغيل الرسومي غير مثبت.";
        if (graphicsQueues<=0) return "تم العثور على GPU، لكن ماكو Graphics Queue مثبتة.";
        if (!logicalDeviceCreated) return "تم اكتشاف GPU ولكن تعذر إنشاء Vulkan Logical Device.";
        if (!swapchainExtension) return "إنشاء الجهاز نجح؛ VK_KHR_swapchain غير معلن، يحتاج تحقق إضافي لعرض الصور.";
        return "نجح اختبار Vulkan الفعلي الأولي (GPU وGraphics Queue وإنشاء الجهاز وامتداد swapchain). لا يوجد اختبار Rendering أو DXVK أو تشغيل EXE بعد.";
    }
}
