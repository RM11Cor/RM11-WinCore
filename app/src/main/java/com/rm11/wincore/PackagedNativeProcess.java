package com.rm11.wincore;

import android.content.Context;
import android.os.Build;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/**
 * Runs ONE named first-party Android PIE executable extracted from our signed APK.
 * Never accepts arbitrary paths, ZIP contents, EXEs or caller-provided commands.
 * This demonstrates the process-launch route necessary before Box64 integration.
 */
public final class PackagedNativeProcess {
    private static final String FILE_NAME = "librm11execprobe.so";
    private static final String SUCCESS = "RM11_ANDROID_ELF_EXEC_OK";
    private PackagedNativeProcess() { }

    public static String runSelfTest(Context context) {
        StringBuilder log = new StringBuilder();
        log.append("RM11 WinCore V1.1 / Packaged executable launch\n");
        log.append("Android ARM64 ELF PIE; not Wine/Box64 or Windows EXE.\n\n");
        if (Build.SUPPORTED_ABIS.length == 0 || !"arm64-v8a".equals(Build.SUPPORTED_ABIS[0])) {
            return log.append("[STOP] Native ARM64 required.\n").toString();
        }
        File executable = new File(context.getApplicationInfo().nativeLibraryDir, FILE_NAME);
        if (!executable.isFile()) {
            return log.append("[FAIL] Missing packaged executable in nativeLibraryDir.\n")
                .append("This may mean the GitHub build did not run scripts-check.py.\n")
                .toString();
        }
        Process process = null;
        try {
            // Absolute signed-APK native library directory; no shell, untrusted args or staged ZIP execution.
            ProcessBuilder builder = new ProcessBuilder(executable.getAbsolutePath(), "--self-test")
                .redirectErrorStream(true);
            process = builder.start();
            if (!process.waitFor(7, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return log.append("[FAIL] Process exceeded 7-second timeout.\n").toString();
            }
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            try (InputStream stream = process.getInputStream()) {
                byte[] buf = new byte[512];
                int total = 0, n;
                while (total < 2048 && (n = stream.read(buf, 0, Math.min(buf.length, 2048 - total))) != -1) {
                    output.write(buf, 0, n);
                    total += n;
                }
            }
            String stdout = output.toString(StandardCharsets.UTF_8.name());
            log.append("Exit code: ").append(process.exitValue()).append("\n");
            log.append("Output:\n").append(stdout).append("\n");
            if (process.exitValue() == 0 && stdout.contains(SUCCESS) && stdout.contains("ARCH=aarch64")) {
                log.append("[PASS] Separate ARM64 Android executable launched from APK.\n");
            } else {
                log.append("[FAIL] Executable ran but output/architecture was unexpected.\n");
            }
        } catch (Exception e) {
            log.append("[FAIL] Could not start packaged process: ")
                .append(e.getClass().getSimpleName()).append(": ")
                .append(e.getMessage()).append("\n");
        } finally {
            if (process != null && process.isAlive()) process.destroyForcibly();
        }
        log.append("[NOT INTEGRATED] Box64, Wine, glibc userland, EXE launch and DXVK.\n");
        return log.toString();
    }
}
