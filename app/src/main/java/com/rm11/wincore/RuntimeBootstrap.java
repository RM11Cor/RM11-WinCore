package com.rm11.wincore;

import android.content.Context;
import android.os.Build;
import android.system.Os;
import android.system.OsConstants;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/**
 * Creates a *placeholder* private runtime workspace and tests an Android OS subprocess.
 * Does not contain or run Box64, Wine, Windows EXEs, a Linux rootfs or a GPU driver.
 */
public final class RuntimeBootstrap {
    private RuntimeBootstrap() {}

    public static boolean correctDevice() {
        return "NX809J".equalsIgnoreCase(Build.MODEL)
            && "nubia".equalsIgnoreCase(Build.MANUFACTURER)
            && Build.VERSION.SDK_INT >= 36
            && Build.SUPPORTED_ABIS.length > 0
            && "arm64-v8a".equals(Build.SUPPORTED_ABIS[0]);
    }

    public static String init(Context ctx) {
        StringBuilder s = new StringBuilder("RM11 WinCore 0.3 / Workspace Init\n");
        s.append("Device: ").append(Build.MANUFACTURER).append(' ').append(Build.MODEL).append('\n');
        if (!correctDevice()) {
            s.append("[STOP] This is not the verified RM11 Pro NX809J ARM64 Android 16 target.\n");
            return s.toString();
        }
        File root = new File(ctx.getFilesDir(), "rm11-runtime");
        for (String relative : new String[]{"logs", "cache", "components", "wine-prefix-placeholder"}) {
            File folder = new File(root, relative);
            if (!folder.isDirectory() && !folder.mkdirs()) {
                s.append("[FAIL] Could not create private folder: ").append(relative).append('\n');
                return s.toString();
            }
        }
        s.append("[PASS] App-private workspace: ").append(root.getAbsolutePath()).append('\n');
        s.append("[PASS] Created folders: logs/cache/components/wine-prefix-placeholder\n");
        try { s.append("System page size: ").append(Os.sysconf(OsConstants._SC_PAGESIZE)).append(" bytes\n"); }
        catch (Exception ex) { s.append("System page size: unavailable\n"); }
        s.append("IMPORTANT: wine-prefix-placeholder is NOT a functional WINEPREFIX.\n");
        s.append("Wine: NOT INSTALLED | Box64: NOT INSTALLED | EXE: NOT RUNNABLE\n");
        return s.toString();
    }

    public static String testSubprocess(Context ctx) {
        StringBuilder s = new StringBuilder("RM11 WinCore 0.3 / Android Process Check\n");
        if (!correctDevice()) return s.append("[STOP] Wrong device.\n").toString();
        Process process = null;
        try {
            // Fixed command, no shell interpolation and no user-controlled input.
            ProcessBuilder pb = new ProcessBuilder("/system/bin/sh", "-c",
                    "printf 'RM11_NATIVE_PROCESS_OK\\n'; /system/bin/uname -m");
            pb.directory(ctx.getFilesDir());
            pb.redirectErrorStream(true);
            process = pb.start();
            boolean done = process.waitFor(8, TimeUnit.SECONDS);
            if (!done) {
                process.destroyForcibly();
                return s.append("[FAIL] Timed out after 8 seconds\n").toString();
            }
            byte[] result = new byte[4096];
            InputStream input = process.getInputStream();
            int n = input.read(result);
            String output = n > 0 ? new String(result, 0, n, StandardCharsets.UTF_8) : "";
            s.append("Exit code: ").append(process.exitValue()).append('\n');
            s.append("Output: ").append(output).append('\n');
            boolean pass = process.exitValue() == 0 && output.contains("RM11_NATIVE_PROCESS_OK");
            s.append(pass ? "[PASS] Android ARM64 OS subprocess works.\n" : "[FAIL] Android subprocess check failed.\n");
            s.append("This checks Android native process launch ONLY, not Wine or Box64.\n");
            File log = new File(new File(ctx.getFilesDir(), "rm11-runtime/logs"), "subprocess-check.txt");
            if (log.getParentFile().isDirectory()) {
                try (FileOutputStream fo = new FileOutputStream(log, false)) {
                    fo.write(s.toString().getBytes(StandardCharsets.UTF_8));
                }
            }
        } catch (Exception e) {
            s.append("[FAIL] ").append(e.getClass().getSimpleName()).append(": ")
                .append(e.getMessage()).append('\n');
        } finally {
            if (process != null && process.isAlive()) process.destroyForcibly();
        }
        return s.toString();
    }
}
