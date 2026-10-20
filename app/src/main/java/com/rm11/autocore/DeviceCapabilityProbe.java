package com.rm11.autocore;

import android.app.ActivityManager;
import android.content.Context;
import android.content.pm.FeatureInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.PowerManager;
import android.os.StatFs;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.util.Arrays;

/** Read-only local diagnostics: no root, network, game copies or privileged API. */
public final class DeviceCapabilityProbe {
    private DeviceCapabilityProbe() { }

    public static final class Snapshot {
        public final String model, soc, os, abis;
        public final int vulkanVersion, vulkanLevel, thermalStatus;
        public final long totalRam, availableRam, freeAppStorage;
        public final RuntimeReadiness.Assessment assessment;
        Snapshot(String model, String soc, String os, String abis, int version, int level,
                 int thermal, long totalRam, long availableRam, long freeStorage,
                 RuntimeReadiness.Assessment assessment) {
            this.model=model; this.soc=soc; this.os=os; this.abis=abis;
            this.vulkanVersion=version; this.vulkanLevel=level; this.thermalStatus=thermal;
            this.totalRam=totalRam; this.availableRam=availableRam;
            this.freeAppStorage=freeStorage; this.assessment=assessment;
        }
        public String asDisplayText() {
            StringBuilder b=new StringBuilder("RM11 Device Runtime Audit (تقرير محلي)\n\n");
            b.append("الجهاز: ").append(model).append("\n")
             .append("SoC المعلن: ").append(soc).append("\n")
             .append("Android: ").append(os).append("\n")
             .append("ABI المتاحة: ").append(abis).append("\n")
             .append("Vulkan المعلن: ").append(RuntimeReadiness.vulkanVersionString(vulkanVersion)).append("\n")
             .append("مستوى Vulkan المعلن: ").append(vulkanLevel >= 0 ? vulkanLevel : "غير معلن").append("\n")
             .append("RAM الكلية: ").append(gib(totalRam)).append(" GiB\n")
             .append("RAM المتاحة وقت الفحص: ").append(gib(availableRam)).append(" GiB\n")
             .append("المساحة المتاحة لقسم التطبيق: ").append(gib(freeAppStorage)).append(" GiB\n")
             .append("حالة الحرارة حسب Android: ").append(thermalLabel(thermalStatus)).append("\n\n")
             .append("الترجمة: ").append(assessment.cpu).append("\n")
             .append("الرسومات: ").append(assessment.graphics).append("\n")
             .append("الجاهزية: ").append(assessment.runtime).append("\n\n")
             .append("التحذير: إعلان دعم Vulkan لا يضمن قدرة Turnip على DXVK أو VKD3D؛ ")
             .append("يلزم تعريف فعلي واختبار لعبة. لا يتم تحميل أو تعديل أي ملف.");
            return b.toString();
        }
        public JSONObject toJson() throws JSONException {
            JSONObject json=new JSONObject();
            json.put("model",model);
            json.put("socModelReported",soc);
            json.put("android",os);
            json.put("supportedABIs",abis);
            json.put("vulkanAndroidReported",RuntimeReadiness.vulkanVersionString(vulkanVersion));
            json.put("vulkanHardwareVersionRaw",vulkanVersion);
            json.put("vulkanHardwareLevelRaw",vulkanLevel);
            json.put("totalRamBytes",totalRam);
            json.put("availableRamBytes",availableRam);
            json.put("appVolumeFreeBytes",freeAppStorage);
            json.put("androidThermalStatus",thermalStatus);
            json.put("fexVerifiedInstalled",false);
            json.put("wineOrProtonVerifiedInstalled",false);
            json.put("graphicsRuntimeVerifiedInstalled",false);
            json.put("windowsExeExecutionReady",assessment.executionReady);
            return json;
        }
    }

    public static Snapshot collect(Context context) {
        String model = Build.MANUFACTURER + " " + Build.MODEL;
        String soc = Build.VERSION.SDK_INT >= 31 && Build.SOC_MODEL != null && !Build.SOC_MODEL.trim().isEmpty()
                ? Build.SOC_MODEL : "غير معلن";
        String os = Build.VERSION.RELEASE + " (SDK " + Build.VERSION.SDK_INT + ")";
        String[] abis = Build.SUPPORTED_ABIS == null ? new String[0] : Build.SUPPORTED_ABIS;
        int version=0,level=-1;
        try {
            FeatureInfo[] features=context.getPackageManager().getSystemAvailableFeatures();
            if (features != null) for (FeatureInfo feature:features) {
                if (feature == null || feature.name == null) continue;
                if (PackageManager.FEATURE_VULKAN_HARDWARE_VERSION.equals(feature.name)) version=feature.version;
                if (PackageManager.FEATURE_VULKAN_HARDWARE_LEVEL.equals(feature.name)) level=feature.version;
            }
        } catch (RuntimeException ignored) { /* device may restrict feature queries */ }
        long total=0,available=0,free=0;
        try {
            ActivityManager am=(ActivityManager)context.getSystemService(Context.ACTIVITY_SERVICE);
            if (am != null) {
                ActivityManager.MemoryInfo info=new ActivityManager.MemoryInfo();
                am.getMemoryInfo(info);
                total=info.totalMem; available=info.availMem;
            }
        } catch (RuntimeException ignored) { }
        try { free=new StatFs(context.getFilesDir().getAbsolutePath()).getAvailableBytes(); }
        catch (RuntimeException ignored) { }
        int thermal=-1;
        try {
            PowerManager power=(PowerManager)context.getSystemService(Context.POWER_SERVICE);
            if (power != null && Build.VERSION.SDK_INT >= 29) thermal=power.getCurrentThermalStatus();
        } catch (RuntimeException ignored) { }
        RuntimeReadiness.Assessment assessment=RuntimeReadiness.assess(Arrays.asList(abis), version,
                false, false, false);
        return new Snapshot(model, soc, os, Arrays.toString(abis), version, level,
                thermal,total,available,free,assessment);
    }

    private static String gib(long bytes) {
        return String.format(java.util.Locale.US,"%.2f", bytes / 1073741824.0);
    }
    private static String thermalLabel(int v) {
        switch(v) {
            case 0: return "NONE (0)";
            case 1: return "LIGHT (1)";
            case 2: return "MODERATE (2)";
            case 3: return "SEVERE (3)";
            case 4: return "CRITICAL (4)";
            case 5: return "EMERGENCY (5)";
            case 6: return "SHUTDOWN (6)";
            default: return "غير مُعلنة";
        }
    }
}
