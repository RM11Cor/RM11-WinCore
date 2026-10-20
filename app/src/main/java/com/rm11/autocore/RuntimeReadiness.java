package com.rm11.autocore;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Pure-Java interpretation of Android capabilities and trusted installed runtime inventory.
 * No guesses about the presence of Wine/Proton/Turnip. Vulkan system advertisement
 * is only a hint, never a benchmark or confirmation that a Windows title can run.
 */
public final class RuntimeReadiness {
    private RuntimeReadiness() { }

    public static final class Assessment {
        public final boolean arm64Supported;
        public final boolean androidVulkanAdvertised;
        public final boolean executionReady;
        public final String cpu;
        public final String graphics;
        public final String runtime;

        Assessment(boolean arm64Supported, boolean vulkan, boolean ready,
                   String cpu, String graphics, String runtime) {
            this.arm64Supported = arm64Supported;
            this.androidVulkanAdvertised = vulkan;
            this.executionReady = ready;
            this.cpu = cpu;
            this.graphics = graphics;
            this.runtime = runtime;
        }
    }

    /**
     * component flags must come from a verified installed manifest, not user-provided
     * filename strings or mere presence of files in Downloads.
     */
    public static Assessment assess(List<String> supportedAbis, int vulkanVersionPacked,
                                    boolean verifiedTranslator, boolean verifiedWindowsLayer,
                                    boolean verifiedGraphicsRuntime) {
        boolean arm = false;
        if (supportedAbis != null) {
            for (String abi : supportedAbis) {
                if (abi != null && abi.toLowerCase(Locale.ROOT).equals("arm64-v8a")) arm = true;
            }
        }
        boolean vk = vulkanVersionPacked > 0 && (vulkanVersionPacked >>> 22) >= 1;
        boolean ready = arm && vk && verifiedTranslator && verifiedWindowsLayer && verifiedGraphicsRuntime;
        String cpu = !arm ? "بيئة ARM64 غير معلنة ضمن ABI؛ فحص الترجمة معلّق"
                : verifiedTranslator ? "ARM64 متاح، ومكوّن الترجمة موثق كمثبت"
                : "ARM64 متاح؛ لا يوجد مترجم x86 مثبت ومتحقق منه داخل RM11";
        String graphics = !vk ? "لا يوجد إعلان واضح عن Vulkan من Android؛ لا نفترض غياب دعم GPU الفعلي"
                : verifiedGraphicsRuntime ? "Vulkan معلن، ومكوّن الرسومات داخل RM11 موثق"
                : "Vulkan معلن من Android؛ تعريف Turnip/DXVK/VKD3D داخل RM11 غير مثبت أو غير متحقق";
        String runtime = ready ? "المكونات الأساسية متاحة؛ تشغيل الألعاب يحتاج اختباراً مستقلاً"
                : "غير جاهز: بيئة تنفيذ Windows كاملة ومتحقق منها غير مدمجة حالياً";
        return new Assessment(arm, vk, ready, cpu, graphics, runtime);
    }

    public static String vulkanVersionString(int packed) {
        if (packed <= 0) return "غير مُعلَن";
        int major = packed >>> 22;
        int minor = (packed >>> 12) & 0x3ff;
        int patch = packed & 0xfff;
        if (major <= 0) return "غير مُعلَن";
        return major + "." + minor + "." + patch + " (إعلان Android، مو اختبار Turnip)";
    }
}
