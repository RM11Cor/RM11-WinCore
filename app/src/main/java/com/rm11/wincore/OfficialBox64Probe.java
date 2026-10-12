package com.rm11.wincore;

import android.content.Context;
import android.os.Build;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/** Experimental read-only version probe of genuine upstream Box64, if CI built it.
 * Never accepts user-provided paths, filenames or command arguments.
 */
public final class OfficialBox64Probe {
    private static final String BINARY = "librm11box64.so"; // NDK-built Android PIE, not a JNI DSO
    private OfficialBox64Probe() { }

    public static String inspect(Context context) {
        StringBuilder log = new StringBuilder("RM11 WinCore V1.3 / Upstream Box64 Android experiment\n")
            .append("Box64 upstream v0.4.4; version query only; NO x86 program/EXE launched.\n\n");
        if (Build.SUPPORTED_ABIS.length == 0 || !"arm64-v8a".equals(Build.SUPPORTED_ABIS[0])) {
            return log.append("[STOP] Device must be ARM64.\n").toString();
        }
        File binary = new File(context.getApplicationInfo().nativeLibraryDir, BINARY);
        if (!binary.isFile()) {
            return log.append("[NOT BUILT] Experimental Box64 was not packaged.\n")
                .append("The optional upstream build on GitHub may have failed.\n")
                .append("Check CI log: scripts-check.py / build_official_box64.py.\n")
                .append("The RM11 ARM64 test program remains available in section 11.\n")
                .toString();
        }
        Process process = null;
        try {
            ProcessBuilder builder = new ProcessBuilder(binary.getAbsolutePath(), "--version")
                .redirectErrorStream(true);
            process = builder.start();
            // Drain asynchronously to prevent pipe deadlock even with noisy upstream logs.
            final Process p = process;
            final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            Thread collector = new Thread(() -> {
                try (InputStream stream = p.getInputStream()) {
                    byte[] buffer = new byte[512];
                    int n;
                    while ((n = stream.read(buffer)) != -1) {
                        synchronized (bytes) {
                            if (bytes.size() < 8192) {
                                bytes.write(buffer, 0, Math.min(n, 8192 - bytes.size()));
                            }
                        }
                    }
                } catch (Exception ignored) { }
            }, "rm11-box64-log");
            collector.setDaemon(true);
            collector.start();
            if (!process.waitFor(12, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                collector.join(1000);
                return log.append("[FAIL] Box64 --version exceeded 12-second timeout.\n").toString();
            }
            collector.join(1500);
            String output;
            synchronized (bytes) { output = bytes.toString(StandardCharsets.UTF_8.name()); }
            log.append("Exit code: ").append(process.exitValue()).append("\n")
                .append("Output:\n").append(output).append("\n");
            if (process.exitValue() == 0 && output.toLowerCase(java.util.Locale.ROOT).contains("box64")) {
                log.append("[PASS] Genuine Box64 Android process launched and reported its version.\n");
            } else {
                log.append("[FAIL] Box64 did not report a successful version result.\n");
            }
        } catch (Exception e) {
            log.append("[FAIL] Box64 process start failed: ").append(e.getClass().getSimpleName())
                .append(": ").append(e.getMessage()).append("\n");
        } finally {
            if (process != null && process.isAlive()) process.destroyForcibly();
        }
        log.append("[NOT READY] No Linux/glibc userland, Wine or DXVK.\n")
           .append("Box64 --version success is NOT evidence of Windows game support.\n");
        return log.toString();
    }
}
