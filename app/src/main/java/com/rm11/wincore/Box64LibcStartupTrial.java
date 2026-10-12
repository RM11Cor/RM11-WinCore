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

/** V1.7 controlled differential: conventional glibc CRT versus libc write@PLT
 * without CRT. Both are first-party Linux x86-64 ELF assets, never Windows EXE.
 * The second program BYPASSES __libc_start_main; it does not patch or supply it.
 */
public final class Box64LibcStartupTrial {
    private static final String BASE = "box64_test/hello_glibc_x86_64.elf";
    private static final String NO_CRT = "box64_test/no_crt_libc_x86_64.elf";
    private static final String BASE_MARK = "RM11_X86_64_GLIBC_DYNAMIC_OK";
    private static final String NO_CRT_MARK = "RM11_X86_64_LIBC_WRITE_OK";
    private static final int MAX_GUEST = 256 * 1024;
    private static final int MAX_LOG = 20 * 1024;
    private static final int TIMEOUT = 12;
    private Box64LibcStartupTrial() { }

    static final class Result {
        final String label;
        final int exit;
        final boolean timeout;
        final String log;
        final boolean passed;
        Result(String label, int exit, boolean timeout, String log, String marker) {
            this.label = label;
            this.exit = exit;
            this.timeout = timeout;
            this.log = log;
            this.passed = !timeout && exit == 0 && log.contains(marker);
        }
    }

    static String compare(Result baseline, Result noCrt) {
        StringBuilder out = new StringBuilder();
        append(out, baseline);
        append(out, noCrt);
        if (!baseline.passed && noCrt.passed) {
            out.append("[ISOLATED] libc write@PLT works WITHOUT glibc CRT; conventional __libc_start_main startup is still broken.\n")
               .append("[NOT FIXED] Normal glibc-linked programs, Wine and Windows EXE still unsupported.\n");
        } else if (baseline.passed && noCrt.passed) {
            out.append("[PASS BOTH] Both tests executed on this build. Does not prove general Linux/Wine compatibility.\n");
        } else if (!baseline.passed && !noCrt.passed) {
            out.append("[FAIL BOTH] Skipping CRT did not resolve the dynamic-link problem. Inspect symbol/loader errors.\n");
        } else {
            out.append("[BASE ONLY] Normal CRT passed but no-CRT failed; inspect write@PLT linkage.\n");
        }
        out.append("[LIMIT] No glibc rootfs, Linux userspace, Wine, DXVK, EXE or game execution provided.\n");
        return out.toString();
    }

    private static void append(StringBuilder out, Result r) {
        out.append("\n--- ").append(r.label).append(" ---\n")
           .append("Exit: ").append(r.timeout ? "TIMEOUT" : r.exit)
           .append("; Result: ").append(r.passed ? "PASS" : "FAIL").append('\n');
        int shown = 0;
        String[] lines = r.log.split("\\r?\\n");
        for (String line : lines) {
            String l = line.toLowerCase(Locale.ROOT);
            if (l.contains("libc_start_main") || l.contains("error") || l.contains("warning")
                    || l.contains("signal") || l.contains("not found")
                    || l.contains("wrapped") || l.contains("write_ok")
                    || l.contains("glibc_dynamic_ok") || l.contains("sigabrt")) {
                if (shown++ < 12) out.append("  ").append(trim(line, 195)).append('\n');
            }
        }
        if (shown == 0) out.append("  ").append(trim(r.log.replace('\n', ' '), 260)).append('\n');
        if (lines.length > 12) out.append("  [LOG REDUCED: ").append(lines.length).append(" lines]\n");
    }

    private static String trim(String s, int n) {
        return s.length() <= n ? s : s.substring(0, n) + "...";
    }

    private static byte[] readAsset(Context ctx, String asset, String marker, boolean noCrt) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (InputStream in = ctx.getAssets().open(asset)) {
            byte[] b = new byte[4096];
            int n;
            while ((n = in.read(b)) != -1) {
                if (bytes.size() + n > MAX_GUEST) throw new IllegalArgumentException("ELF asset too large");
                bytes.write(b, 0, n);
            }
        }
        byte[] data = bytes.toByteArray();
        ElfRuntimeInspector.Report audit = ElfRuntimeInspector.analyzeBytes(data);
        String ascii = new String(data, StandardCharsets.ISO_8859_1);
        if (audit.elfClass != 2 || audit.machine != 62 || audit.kind != 3
                || !"/lib64/ld-linux-x86-64.so.2".equals(audit.interpreter)
                || audit.dependenciesUnreadable || !audit.needed.contains("libc.so.6")
                || !ascii.contains(marker))
            throw new IllegalArgumentException("Expected first-party PIE x86-64 dynamic libc guest");
        if (noCrt && (!ascii.contains("write") || ascii.contains("__libc_start_main")))
            throw new IllegalArgumentException("No-CRT guest contains wrong startup dependency");
        return data;
    }

    private static Result execute(Context ctx, File box64, String label,
                                  String asset, String marker, boolean noCrt) throws Exception {
        byte[] bytes = readAsset(ctx, asset, marker, noCrt);
        File guest = File.createTempFile("rm11-v17-guest-", ".elf", ctx.getCacheDir());
        Process process = null;
        try {
            try (FileOutputStream out = new FileOutputStream(guest)) {
                out.write(bytes);
                out.getFD().sync();
            }
            if (!guest.setExecutable(true, true) || !guest.canExecute())
                throw new IllegalStateException("Android blocked X_OK on guest ELF");
            ProcessBuilder pb = new ProcessBuilder(box64.getAbsolutePath(), guest.getAbsolutePath());
            pb.directory(ctx.getCacheDir());
            pb.redirectErrorStream(true);
            pb.environment().put("BOX64_LOG", "1");
            // Both candidates run in the same interpreted mode to isolate CRT difference.
            pb.environment().put("BOX64_DYNAREC", "0");
            pb.environment().remove("LD_PRELOAD");
            process = pb.start();
            final Process running = process;
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            Thread drain = new Thread(() -> {
                try (InputStream in = running.getInputStream()) {
                    byte[] part = new byte[1024];
                    int n;
                    while ((n = in.read(part)) != -1) {
                        synchronized (buffer) {
                            if (buffer.size() < MAX_LOG)
                                buffer.write(part, 0, Math.min(n, MAX_LOG - buffer.size()));
                        }
                    }
                } catch (Exception ignored) { }
            }, "rm11-v17-drain");
            drain.setDaemon(true);
            drain.start();
            boolean finished = process.waitFor(TIMEOUT, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                process.waitFor(2, TimeUnit.SECONDS);
            }
            drain.join(1100);
            String log;
            synchronized (buffer) { log = new String(buffer.toByteArray(), StandardCharsets.UTF_8); }
            return new Result(label, finished ? process.exitValue() : -1, !finished, log, marker);
        } finally {
            if (process != null && process.isAlive()) process.destroyForcibly();
            guest.delete();
        }
    }

    /** V1.8 regression after the pinned upstream Android startup-source patch.
     * Same real first-party glibc CRT guest that failed on V1.5/V1.6, plus the
     * V1.7 no-CRT libc control. Never infer success from just stderr or a stub.
     */
    public static String runV18Regression(Context ctx) {
        StringBuilder out = new StringBuilder("RM11 WinCore V1.8 / Box64 Android glibc CRT bridge trial\n")
            .append("Box64 upstream v0.4.4; test of real x86-64 Linux ELF startup.\n")
            .append("No Wine, Windows EXE or complete glibc userspace supplied.\n\n");
        if (Build.SUPPORTED_ABIS.length == 0 || !"arm64-v8a".equals(Build.SUPPORTED_ABIS[0]))
            return out.append("[STOP] Android ARM64 required.\n").toString();
        File box64 = new File(ctx.getApplicationInfo().nativeLibraryDir, "librm11box64.so");
        if (!box64.isFile()) return out.append("[NOT BUILT] Box64 is absent from APK.\n").toString();
        // Build receipt is only emitted after successfully packaging a patched Box64 binary.
        try (InputStream receipt = ctx.getAssets().open("third_party/box64/RM11-STARTUP-PATCH.txt")) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] chunk = new byte[256];
            int n;
            while ((n = receipt.read(chunk)) != -1 && bytes.size() <= 1024)
                bytes.write(chunk, 0, n);
            if (!bytes.toString("UTF-8").contains("RM11 V1.8 trial:"))
                return out.append("[NOT PATCHED] Missing expected source-patch build receipt.\n").toString();
        } catch (Exception ex) {
            return out.append("[NOT PATCHED] No verified V1.8 Box64 patch receipt in APK.\n").toString();
        }
        out.append("[PATCH BUILT] Glibc CRT bridge was compiled into this APK's Box64.\n")
            .append("BOX64_DYNAREC=0 for both guests; comparing conventional CRT and no-CRT libc control.\n");
        try {
            Result normal = execute(ctx, box64, "NORMAL glibc CRT", BASE, BASE_MARK, false);
            Result control = execute(ctx, box64, "NO CRT libc write control", NO_CRT, NO_CRT_MARK, true);
            append(out, normal);
            append(out, control);
            if (normal.passed && control.passed) {
                out.append("[PASS CRT] Conventional glibc-linked x86-64 guest executed, as did libc write control.\n");
            } else if (normal.passed) {
                out.append("[PASS CRT] Conventional glibc-linked guest executed; [WARN] no-CRT regression control failed.\n");
            } else if (normal.log.contains("__libc_start_main")) {
                out.append("[STILL BROKEN] __libc_start_main symbol/startup failure observed. Patch alone was insufficient.\n");
            } else {
                out.append("[FAIL CRT] Conventional glibc guest did not complete. Inspect log for the next blocker.\n");
            }
            out.append("[LIMIT] This tests only one first-party Linux x86-64 program. No Wine, DXVK, EXE or gaming guarantee.\n");
        } catch (Exception ex) {
            out.append("[FAIL AUDIT/EXEC] ").append(ex.getClass().getSimpleName())
               .append(": ").append(ex.getMessage()).append('\n');
        }
        return out.toString();
    }

    public static String run(Context ctx) {
        StringBuilder out = new StringBuilder("RM11 WinCore V1.7 / glibc startup isolation\n")
            .append("Offline first-party x86-64 Linux ELF; BOX64_DYNAREC=0 in both cases.\n")
            .append("New guest links libc.so.6 and calls write@PLT, but skips __libc_start_main.\n\n");
        if (Build.SUPPORTED_ABIS.length == 0 || !"arm64-v8a".equals(Build.SUPPORTED_ABIS[0]))
            return out.append("[STOP] Android ARM64 required.\n").toString();
        File box64 = new File(ctx.getApplicationInfo().nativeLibraryDir, "librm11box64.so");
        if (!box64.isFile()) return out.append("[NOT BUILT] Box64 not included in APK.\n").toString();
        try {
            Result baseline = execute(ctx, box64, "NORMAL glibc CRT (old)", BASE, BASE_MARK, false);
            Result isolated = execute(ctx, box64, "NO CRT + libc write@PLT (new)", NO_CRT, NO_CRT_MARK, true);
            out.append(compare(baseline, isolated));
        } catch (Exception ex) {
            out.append("[FAIL AUDIT/EXEC] ").append(ex.getClass().getSimpleName())
               .append(": ").append(ex.getMessage()).append('\n');
        }
        return out.toString();
    }
}
