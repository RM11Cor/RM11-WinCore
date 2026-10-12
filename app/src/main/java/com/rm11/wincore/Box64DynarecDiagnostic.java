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

/** V1.6: same first-party dynamic guest, with/without Box64 dynarec.
 * Diagnoses failures only. Does NOT ship glibc, invoke Windows EXE, or claim Wine support.
 */
public final class Box64DynarecDiagnostic {
    private static final String ASSET = "box64_test/hello_glibc_x86_64.elf";
    private static final String BOX64 = "librm11box64.so";
    private static final String SUCCESS = "RM11_X86_64_GLIBC_DYNAMIC_OK";
    private static final int MAX_ASSET = 256 * 1024;
    private static final int MAX_OUTPUT = 24 * 1024;
    private static final int TIMEOUT_SECONDS = 13;
    private Box64DynarecDiagnostic() { }

    static final class Trial {
        final boolean dynarec;
        final boolean timedOut;
        final int exitCode;
        final String output;
        Trial(boolean dynarec, boolean timedOut, int exitCode, String output) {
            this.dynarec = dynarec;
            this.timedOut = timedOut;
            this.exitCode = exitCode;
            this.output = output;
        }
        boolean passed() { return !timedOut && exitCode == 0 && output.contains(SUCCESS); }
    }

    static String diagnose(Trial on, Trial off) {
        StringBuilder s = new StringBuilder();
        describe(s, on);
        describe(s, off);
        if (on.passed() && off.passed()) {
            s.append("[PASS BOTH] Dynamic guest succeeded in both modes. No Windows compatibility inferred.\n");
        } else if (on.passed()) {
            s.append("[PASS DYNAREC ONLY] Dynarec ON passed; interpreter OFF failed. Investigate OFF error.\n");
        } else if (off.passed()) {
            s.append("[PASS INTERPRETER ONLY] Dynarec OFF passed; JIT-related issue is POSSIBLE, not proven.\n");
        } else {
            s.append("[FAIL BOTH] Dynamic guest failed in both modes; cannot blame Dynarec alone.\n");
        }
        if (hasNullCrash(on.output) || hasNullCrash(off.output)) {
            s.append("[CRASH SIGNAL] NULL control flow / signal observed. Native glibc wrappers, ABI, loader or other incompatibility may be involved. This is NOT proof that glibc is simply missing.\n");
        }
        if (hasDependencyError(on.output) || hasDependencyError(off.output)) {
            s.append("[DEPENDENCY SIGNAL] Loader/library message found; inspect output for exact dependency.\n");
        }
        s.append("[LIMIT] No glibc rootfs, Linux loader, Wine, DXVK, EXE or Windows games provided.\n");
        return s.toString();
    }

    private static void describe(StringBuilder s, Trial t) {
        String mode = t.dynarec ? "ON" : "OFF";
        s.append("\n--- Dynarec ").append(mode).append(" ---\n")
         .append("Exit: ").append(t.timedOut ? "TIMEOUT" : t.exitCode)
         .append("; Marker: ").append(t.output.contains(SUCCESS) ? "YES" : "NO")
         .append("; Result: ").append(t.passed() ? "PASS" : "FAIL").append('\n');
        if (t.exitCode == 134 || t.output.contains("SIGABRT"))
            s.append("Crash indicator: SIGABRT / exit 134\n");
        if (t.output.contains("SIGSEGV") || t.output.toLowerCase(Locale.ROOT).contains("segfault"))
            s.append("Crash indicator: SIGSEGV / segfault\n");
        // Preserve exact diagnostic lines, but avoid 2 enormous Android log blocks.
        String[] lines = t.output.split("\\r?\\n");
        int shown = 0;
        for (String line : lines) {
            String low = line.toLowerCase(Locale.ROOT);
            if (low.contains("error") || low.contains("warning") || low.contains("segfault")
                    || low.contains("signal") || low.contains("libc.so") || low.contains("ld-linux")
                    || low.contains("null") || low.contains(SUCCESS.toLowerCase(Locale.ROOT))) {
                if (shown < 14) {
                    s.append("  ").append(truncate(line, 190)).append('\n');
                    shown++;
                }
            }
        }
        if (shown == 0)
            s.append("  (No diagnostic keyword found; first output) ")
             .append(truncate(t.output.replace('\n', ' '), 250)).append('\n');
        if (lines.length > shown) s.append("  [LOG FILTERED: ").append(lines.length)
                                   .append(" total lines; report intentionally shortened]\n");
    }

    private static String truncate(String text, int max) {
        return text.length() <= max ? text : text.substring(0, max) + "...";
    }
    private static boolean hasNullCrash(String s) {
        String low = s.toLowerCase(Locale.ROOT);
        return low.contains("run at null") || low.contains("x64pc=0x0")
                || low.contains("sigabrt") || low.contains("sigsegv")
                || low.contains("segfault");
    }
    private static boolean hasDependencyError(String s) {
        String low = s.toLowerCase(Locale.ROOT);
        return low.contains("cannot open shared object") || low.contains("cannot find library")
                || low.contains("library not found") || low.contains("symbol not found")
                || low.contains("missing library");
    }

    private static Trial execute(File box64, File guest, File directory, boolean dynarec) throws Exception {
        ProcessBuilder builder = new ProcessBuilder(box64.getAbsolutePath(), guest.getAbsolutePath());
        builder.directory(directory);
        builder.redirectErrorStream(true);
        builder.environment().put("BOX64_LOG", "1");
        builder.environment().put("BOX64_DYNAREC", dynarec ? "1" : "0");
        Process process = builder.start();
        final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        final Process running = process;
        Thread drain = new Thread(() -> {
            try (InputStream input = running.getInputStream()) {
                byte[] block = new byte[1024];
                int n;
                while ((n = input.read(block)) >= 0) {
                    synchronized (bytes) {
                        if (bytes.size() < MAX_OUTPUT)
                            bytes.write(block, 0, Math.min(n, MAX_OUTPUT - bytes.size()));
                    }
                }
            } catch (Exception ignored) { }
        }, "rm11-v16-box64-log");
        drain.setDaemon(true);
        drain.start();
        boolean finished;
        try {
            finished = process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                process.waitFor(2, TimeUnit.SECONDS);
            }
            drain.join(1200);
            synchronized (bytes) {
                return new Trial(dynarec, !finished, finished ? process.exitValue() : -1,
                        new String(bytes.toByteArray(), StandardCharsets.UTF_8));
            }
        } finally {
            if (process.isAlive()) process.destroyForcibly();
        }
    }

    public static String run(Context context) {
        StringBuilder report = new StringBuilder("RM11 WinCore V1.6 / Box64 Dynarec A/B diagnostic\n")
            .append("Controlled, offline first-party Linux x86-64 dynamic ELF only.\n")
            .append("Box64 ON vs OFF; outputs filtered to keep report readable.\n\n");
        if (Build.SUPPORTED_ABIS.length == 0 || !"arm64-v8a".equals(Build.SUPPORTED_ABIS[0]))
            return report.append("[STOP] Requires ARM64 Android.\n").toString();
        File box64 = new File(context.getApplicationInfo().nativeLibraryDir, BOX64);
        if (!box64.isFile()) return report.append("[NOT BUILT] Box64 missing from this APK.\n").toString();
        File guest = null;
        try {
            byte[] data;
            try (InputStream input = context.getAssets().open(ASSET);
                 ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
                byte[] chunk = new byte[4096];
                int size;
                while ((size = input.read(chunk)) != -1) {
                    if (buffer.size() + size > MAX_ASSET)
                        throw new IllegalArgumentException("Guest too large");
                    buffer.write(chunk, 0, size);
                }
                data = buffer.toByteArray();
            }
            ElfRuntimeInspector.Report audit = Box64DynamicGlibcTest.verifyGuest(data);
            report.append("[AUDIT OK] x86-64 ELF; PT_INTERP=").append(audit.interpreter)
                  .append("; DT_NEEDED=").append(String.join(", ", audit.needed)).append('\n');
            guest = File.createTempFile("rm11-v16-guest-", ".elf", context.getCacheDir());
            try (FileOutputStream out = new FileOutputStream(guest)) {
                out.write(data);
                out.getFD().sync();
            }
            if (!(guest.setExecutable(true, true) && guest.canExecute()))
                return report.append("[BLOCKED] Cannot enable guest X_OK for Box64 file check.\n").toString();
            Trial on = execute(box64, guest, context.getCacheDir(), true);
            Trial off = execute(box64, guest, context.getCacheDir(), false);
            report.append(diagnose(on, off));
        } catch (Exception e) {
            report.append("[FAIL] ").append(e.getClass().getSimpleName())
                  .append(": ").append(e.getMessage()).append('\n');
        } finally {
            if (guest != null) guest.delete();
        }
        return report.toString();
    }
}
