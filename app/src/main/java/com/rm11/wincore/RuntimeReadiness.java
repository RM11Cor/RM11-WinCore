package com.rm11.wincore;

import android.app.ActivityManager;
import android.content.Context;
import android.os.Build;
import android.os.Environment;
import android.os.PowerManager;
import android.os.StatFs;

import java.util.Arrays;
import java.util.Locale;

/** A read-only preflight for this single REDMAGIC model. This is NOT a Wine runtime. */
public final class RuntimeReadiness {
    private RuntimeReadiness() {}

    private static String yn(boolean yes) { return yes ? "PASS" : "CHECK"; }
    private static String gib(long bytes) {
        return String.format(Locale.US, "%.2f GiB", bytes / 1073741824.0);
    }

    public static String inspect(Context context) {
        StringBuilder out = new StringBuilder("RM11 WinCore V0.3 / Runtime Preflight\n\n");
        boolean modelMatch = "NX809J".equalsIgnoreCase(Build.MODEL) &&
            "nubia".equalsIgnoreCase(Build.MANUFACTURER);
        boolean arm64 = Arrays.asList(Build.SUPPORTED_ABIS).contains("arm64-v8a");
        boolean os = Build.VERSION.SDK_INT >= 36;
        String soc = Build.VERSION.SDK_INT >= 31 ? Build.SOC_MODEL : "Unknown";
        boolean socMatch = "SM8850".equalsIgnoreCase(soc);
        out.append("[" + yn(modelMatch) + "] REDMAGIC NX809J / nubia: ")
            .append(Build.MODEL).append(" / ").append(Build.MANUFACTURER).append('\n');
        out.append("[" + yn(socMatch) + "] CPU SoC SM8850: ").append(soc).append('\n');
        out.append("[" + yn(arm64) + "] ABI arm64-v8a\n");
        out.append("[" + yn(os) + "] Android API >= 36: ")
            .append(Build.VERSION.SDK_INT).append("\n\n");

        ActivityManager mgr = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        if (mgr != null) {
            ActivityManager.MemoryInfo mem = new ActivityManager.MemoryInfo();
            mgr.getMemoryInfo(mem);
            out.append("Installed RAM: ").append(gib(mem.totalMem)).append('\n');
            out.append("Available RAM (snapshot): ").append(gib(mem.availMem)).append('\n');
            out.append("Memory currently low: ").append(mem.lowMemory).append('\n');
            out.append("[" + yn(mem.availMem >= 4L * 1024 * 1024 * 1024 && !mem.lowMemory) +
                "] Preliminary 4 GiB free RAM threshold (not game requirement)\n\n");
        }
        StatFs disk = new StatFs(Environment.getDataDirectory().getAbsolutePath());
        long free = disk.getAvailableBytes();
        out.append("Free internal storage: ").append(gib(free)).append('\n');
        out.append("[" + yn(free >= 16L * 1024 * 1024 * 1024) +
            "] Preliminary 16 GiB free storage threshold\n");

        PowerManager power = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
        if (power != null) {
            out.append("Android thermal status (0 means NONE): ")
                .append(power.getCurrentThermalStatus()).append("\n");
        }
        String vk = VulkanProbe.inspect();
        boolean gpu = vk.contains("Adreno (TM) 840");
        boolean deviceVk = vk.contains("API version: 1.4.");
        out.append("[" + yn(gpu) + "] Target GPU Adreno 840\n");
        out.append("[" + yn(deviceVk) + "] Vulkan device API 1.4.x\n");
        out.append("\n--- Queried Vulkan feature bits ---\n");
        int begin = vk.indexOf("Feature support (queried from GPU):");
        if (begin >= 0) {
            int end = vk.indexOf("\n\n", begin);
            out.append(vk, begin, end < 0 ? vk.length() : end).append('\n');
        } else {
            out.append("Feature query unavailable; inspect full Device Probe report.\n");
        }
        out.append("\n--- Actual engine status ---\n");
        out.append("Wine: NOT INTEGRATED\n");
        out.append("Box64: NOT INTEGRATED\n");
        out.append("DXVK / VKD3D-Proton: NOT INTEGRATED\n");
        out.append("Windows EXE execution: NOT AVAILABLE\n");
        out.append("Steam/Ubisoft/EA/Rockstar installation: NOT AVAILABLE\n\n");
        out.append("Recommended first graphics test: stock Adreno driver, 1280x720. ")
            .append("This is a starting profile, not measured game performance.\n");
        out.append("Do not confuse available Vulkan capabilities with anti-cheat support.\n");
        return out.toString();
    }
}
