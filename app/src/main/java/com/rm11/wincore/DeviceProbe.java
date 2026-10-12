package com.rm11.wincore;

import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.FeatureInfo;
import android.content.pm.PackageManager;
import android.os.BatteryManager;
import android.os.Build;
import android.os.Environment;
import android.os.PowerManager;
import android.os.StatFs;
import android.util.DisplayMetrics;

import java.text.DateFormat;
import java.util.Date;
import java.util.Locale;

/** Read-only Android system inspection. Never assumes advertised RAM or GPU identity. */
public final class DeviceProbe {
    private DeviceProbe() {}

    private static String gib(long bytes) {
        return String.format(Locale.US, "%.2f GiB", bytes / 1073741824.0);
    }
    private static String thermalName(int value) {
        switch (value) {
            case PowerManager.THERMAL_STATUS_NONE: return "NONE";
            case PowerManager.THERMAL_STATUS_LIGHT: return "LIGHT";
            case PowerManager.THERMAL_STATUS_MODERATE: return "MODERATE";
            case PowerManager.THERMAL_STATUS_SEVERE: return "SEVERE";
            case PowerManager.THERMAL_STATUS_CRITICAL: return "CRITICAL";
            case PowerManager.THERMAL_STATUS_EMERGENCY: return "EMERGENCY";
            case PowerManager.THERMAL_STATUS_SHUTDOWN: return "SHUTDOWN";
            default: return "Unknown " + value;
        }
    }
    private static String featureVersion(Context context, String name) {
        FeatureInfo[] features = context.getPackageManager().getSystemAvailableFeatures();
        if (features == null) return "not reported";
        for (FeatureInfo feature : features) {
            if (name.equals(feature.name)) {
                int v = feature.version;
                if (name.equals(PackageManager.FEATURE_VULKAN_HARDWARE_VERSION)) {
                    return ((v >> 22) & 0x3ff) + "." + ((v >> 12) & 0x3ff) + "." + (v & 0xfff);
                }
                return String.valueOf(v);
            }
        }
        return "not reported";
    }
    public static String inspect(Context context) {
        StringBuilder report = new StringBuilder("RM11 WinCore / Device Probe / 0.2.0\n");
        report.append("Time: ").append(DateFormat.getDateTimeInstance().format(new Date())).append("\n\n");
        report.append("--- Target device ---\n");
        report.append("Target: REDMAGIC 11 Pro (16GB/512GB ONLY)\n");
        report.append("Actual manufacturer: ").append(Build.MANUFACTURER).append('\n');
        report.append("Actual model: ").append(Build.MODEL).append('\n');
        report.append("Device/codename: ").append(Build.DEVICE).append('\n');
        report.append("Hardware: ").append(Build.HARDWARE).append('\n');
        report.append("SoC model: ").append(Build.VERSION.SDK_INT >= 31 ? Build.SOC_MODEL : "API < 31").append('\n');
        report.append("ABIs: ").append(String.join(", ", Build.SUPPORTED_ABIS)).append('\n');
        report.append("Android: ").append(Build.VERSION.RELEASE).append(" / API ").append(Build.VERSION.SDK_INT).append('\n');
        report.append("Build fingerprint: ").append(Build.FINGERPRINT).append('\n');
        boolean likely = (Build.MODEL + " " + Build.DEVICE + " " + Build.PRODUCT).toLowerCase(Locale.ROOT).contains("nx809j")
            || (Build.MODEL + " " + Build.DEVICE).toLowerCase(Locale.ROOT).contains("redmagic 11");
        report.append("Target ID match (informative): ").append(likely ? "LIKELY MATCH" : "NOT CONFIRMED — compare model manually").append("\n\n");

        ActivityManager mgr = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        ActivityManager.MemoryInfo mem = new ActivityManager.MemoryInfo();
        if (mgr != null) {
            mgr.getMemoryInfo(mem);
            report.append("--- Memory ---\n");
            report.append("Total RAM: ").append(gib(mem.totalMem)).append('\n');
            report.append("Available RAM (sample): ").append(gib(mem.availMem)).append('\n');
            report.append("Low-memory state: ").append(mem.lowMemory).append("\n\n");
        }
        StatFs stat = new StatFs(Environment.getDataDirectory().getAbsolutePath());
        report.append("--- Internal storage (/data partition, not marketed capacity) ---\n");
        report.append("Total: ").append(gib(stat.getTotalBytes())).append('\n');
        report.append("Free: ").append(gib(stat.getAvailableBytes())).append("\n\n");
        report.append("--- Android Vulkan features ---\n");
        report.append("Vulkan version declared: ").append(featureVersion(context, PackageManager.FEATURE_VULKAN_HARDWARE_VERSION)).append('\n');
        report.append("Vulkan hardware level: ").append(featureVersion(context, PackageManager.FEATURE_VULKAN_HARDWARE_LEVEL)).append("\n\n");

        PowerManager power = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
        report.append("--- Thermals ---\n");
        if (power != null) report.append("Android thermal status: ").append(thermalName(power.getCurrentThermalStatus())).append('\n');
        Intent battery = context.registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        if (battery != null) {
            int temp = battery.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, Integer.MIN_VALUE);
            if (temp != Integer.MIN_VALUE) report.append("Battery sensor temperature (not CPU temp): ").append(String.format(Locale.US, "%.1f C", temp / 10.0)).append('\n');
        }
        report.append("\n--- Native Vulkan inspection ---\n");
        report.append(VulkanProbe.inspect()).append('\n');
        report.append("\nNotes: Report is read-only. No root or game launcher installed. GPU memory on Android may be shared RAM. Do not share a report publicly if you wish to keep device build details private.\n");
        return report.toString();
    }
}
