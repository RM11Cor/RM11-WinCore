package com.rm11.wincore;

import android.content.Context;
import android.os.Build;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/** Separate first-party Linux x86-64 ABI capability probes through genuine Box64.
 * No Windows EXE or third-party programs; this is not a Wine compatibility test. */
public final class Box64AbiCompatibilityV19 {
    private static final String ASSET = "box64_test/v19_glibc_compat_x86_64.elf";
    private static final String PREFIX = "RM11_V19_";
    private static final String[] MODES = {"memory", "file", "thread", "dlopen"};
    private static final String[] LABELS = {"malloc/calloc/realloc/free", "open/write/read/unlink", "pthread_create/join", "dlopen/dlsym libm"};
    private static final String[] MARKERS = {"MEMORY", "FILE", "THREAD", "DLOPEN"};
    private static final int MAX_GUEST = 256 * 1024;
    private static final int MAX_LOG = 12 * 1024;
    private static final int TIMEOUT_SECONDS = 10;

    private Box64AbiCompatibilityV19() { }

    static final class ProbeResult {
        final String label;
        final int code;
        final boolean timedOut;
        final String log;
        final String marker;
        final boolean pass;
        ProbeResult(String label, int code, boolean timedOut, String log, String marker) {
            this.label = label;
            this.code = code;
            this.timedOut = timedOut;
            this.log = log;
            this.marker = marker;
            this.pass = !timedOut && code == 0 && containsExactLine(log, PREFIX + marker + "_OK");
        }
    }

    static boolean containsExactLine(String log, String expected) {
        for (String s : log.split("\\r?\\n")) if (expected.equals(s.trim())) return true;
        return false;
    }

    static String summary(ProbeResult[] results) {
        int count = 0;
        StringBuilder report = new StringBuilder();
        for (ProbeResult result : results) {
            if (result.pass) count++;
            report.append("\n--- ").append(result.label).append(" ---\n")
                  .append(result.pass ? "[PASS] " : "[FAIL] ")
                  .append(result.timedOut ? "TIMEOUT" : "Exit: " + result.code).append('\n');
            int shown = 0;
            for (String line : result.log.split("\\r?\\n")) {
                String s = line.toLowerCase(Locale.ROOT);
                if (s.contains("error") || s.contains("not found") || s.contains("symbol")
                        || s.contains("sig") || s.contains("abort") || s.contains("dlopen")
                        || s.contains("_ok") || s.contains("failed") || s.contains("warn")) {
                    if (shown++ < 8) report.append("  ").append(line.length() > 190 ? line.substring(0, 190) + "..." : line).append('\n');
                }
            }
            if (shown == 0) report.append("  (No diagnostic/error lines; inspect Exit and marker.)\n");
        }
        report.append("\n[SUMMARY] ").append(count).append("/4 independent Linux x86-64 ABI probes passed.\n");
        if (count == 4) report.append("[PASS FOUR] Tested ABI operations succeeded in interpreted mode on this build.\n");
        else report.append("[PARTIAL/FAIL] Failed probes identify the next Box64 wrapper/ABI blocker.\n");
        report.append("[LIMIT] No complete glibc rootfs, Wine, Windows EXE, games, graphics, or FPS validated.\n");
        return report.toString();
    }

    private static byte[] guestBytes(Context context) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (InputStream in = context.getAssets().open(ASSET)) {
            byte[] buf = new byte[4096];
            int count;
            while ((count = in.read(buf)) != -1) {
                if (count > MAX_GUEST - bytes.size()) throw new IllegalArgumentException("Guest asset too large");
                bytes.write(buf, 0, count);
            }
        }
        byte[] data = bytes.toByteArray();
        ElfRuntimeInspector.Report elf = ElfRuntimeInspector.analyzeBytes(data);
        String ascii = new String(data, StandardCharsets.ISO_8859_1);
        if (elf.elfClass != 2 || elf.machine != 62 || elf.kind != 3
                || !"/lib64/ld-linux-x86-64.so.2".equals(elf.interpreter)
                || elf.dependenciesUnreadable || !elf.needed.contains("libc.so.6"))
            throw new IllegalArgumentException("Incorrect first-party x86-64 dynamic Linux ELF");
        for (String mark : MARKERS) {
            if (!ascii.contains(PREFIX + mark + "_OK"))
                throw new IllegalArgumentException("Missing marker in ELF: " + mark);
        }
        return data;
    }

    private static ProbeResult runMode(Context context, File box64, File guest,
                                       String label, String mode, String marker) throws Exception {
        File scratch = null;
        Process process = null;
        try {
            ProcessBuilder pb;
            if ("file".equals(mode)) {
                scratch = File.createTempFile("rm11-v19-file-", ".tmp", context.getCacheDir());
                if (!scratch.delete()) throw new IllegalStateException("Cannot prepare test-only file path");
                pb = new ProcessBuilder(box64.getAbsolutePath(), guest.getAbsolutePath(), mode, scratch.getAbsolutePath());
            } else {
                pb = new ProcessBuilder(box64.getAbsolutePath(), guest.getAbsolutePath(), mode);
            }
            pb.directory(context.getCacheDir());
            pb.redirectErrorStream(true);
            pb.environment().put("BOX64_DYNAREC", "0"); // Compare with the proven V1.8 interpreted baseline.
            pb.environment().put("BOX64_LOG", "1");
            pb.environment().remove("LD_PRELOAD");
            process = pb.start();
            final Process running = process;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            Thread drain = new Thread(() -> {
                try (InputStream in = running.getInputStream()) {
                    byte[] part = new byte[1024];
                    int n;
                    while ((n = in.read(part)) != -1) {
                        synchronized (out) {
                            int room = MAX_LOG - out.size();
                            if (room > 0) out.write(part, 0, Math.min(room, n));
                        }
                    }
                } catch (Exception ignored) { }
            }, "rm11-v19-stdout");
            drain.setDaemon(true);
            drain.start();
            boolean finished = process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                process.waitFor(2, TimeUnit.SECONDS);
            }
            drain.join(1100);
            String log;
            synchronized (out) { log = new String(out.toByteArray(), StandardCharsets.UTF_8); }
            return new ProbeResult(label, finished ? process.exitValue() : -1, !finished, log, marker);
        } finally {
            if (process != null && process.isAlive()) process.destroyForcibly();
            if (scratch != null) scratch.delete();
        }
    }

    public static String run(Context ctx) {
        StringBuilder report = new StringBuilder("RM11 WinCore V1.9 / Linux x86-64 Box64 ABI compatibility\n")
            .append("Four offline first-party glibc ELF subprocess tests; BOX64_DYNAREC=0.\n")
            .append("Success = exact guest marker AND exit 0 for each mode.\n");
        if (Build.SUPPORTED_ABIS.length == 0 || !"arm64-v8a".equals(Build.SUPPORTED_ABIS[0]))
            return report.append("[STOP] ARM64 Android required.\n").toString();
        File box64 = new File(ctx.getApplicationInfo().nativeLibraryDir, "librm11box64.so");
        if (!box64.isFile()) return report.append("[NOT BUILT] Real Box64 missing from APK.\n").toString();
        File guest = null;
        try {
            byte[] content = guestBytes(ctx);
            guest = File.createTempFile("rm11-v19-guest-", ".elf", ctx.getCacheDir());
            try (FileOutputStream stream = new FileOutputStream(guest)) {
                stream.write(content);
                stream.getFD().sync();
            }
            if (!guest.setExecutable(true, true) || !guest.canExecute())
                throw new IllegalStateException("Android blocked guest executable permission");
            ProbeResult[] results = new ProbeResult[MODES.length];
            for (int i = 0; i < MODES.length; i++) {
                try {
                    results[i] = runMode(ctx, box64, guest, LABELS[i], MODES[i], MARKERS[i]);
                } catch (Exception modeError) {
                    results[i] = new ProbeResult(LABELS[i], -1, false,
                        "[EXEC ERROR] " + modeError.getClass().getSimpleName() + ": " + modeError.getMessage(), MARKERS[i]);
                }
            }
            report.append(summary(results));
        } catch (Exception e) {
            report.append("[FAIL AUDIT/EXEC] ").append(e.getClass().getSimpleName())
                  .append(": ").append(e.getMessage()).append('\n');
        } finally {
            if (guest != null) guest.delete();
        }
        return report.toString();
    }
}
