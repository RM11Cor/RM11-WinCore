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

/** V1.5: controlled test of an in-APK Linux x86-64 ELF with glibc dependencies.
 * Does not ship or install glibc, Linux loader, Wine, or DXVK; no user binaries.
 * Only genuine packaged Box64 is allowed to parse the immutable known guest.
 */
public final class Box64DynamicGlibcTest {
    private static final String ASSET = "box64_test/hello_glibc_x86_64.elf";
    private static final String BOX64 = "librm11box64.so";
    private static final String MARKER = "RM11_X86_64_GLIBC_DYNAMIC_OK";
    private static final int MAX_SIZE = 256 * 1024;
    private static final int MAX_OUTPUT = 12 * 1024;
    private Box64DynamicGlibcTest() { }

    /** The audit is done BEFORE any process starts, including on-device. */
    static ElfRuntimeInspector.Report verifyGuest(byte[] data) throws Exception {
        if (data.length < 64 || data.length > MAX_SIZE)
            throw new IllegalArgumentException("Invalid guest asset size");
        ElfRuntimeInspector.Report r = ElfRuntimeInspector.analyzeBytes(data);
        if (r.elfClass != 2 || r.machine != 62 || (r.kind != 2 && r.kind != 3)
                || !"/lib64/ld-linux-x86-64.so.2".equals(r.interpreter)
                || r.dependenciesUnreadable || !r.needed.contains("libc.so.6")
                || !new String(data, StandardCharsets.ISO_8859_1).contains(MARKER)) {
            throw new IllegalArgumentException("Expected a Linux x86-64 glibc-linked guest with PT_INTERP and DT_NEEDED libc.so.6");
        }
        return r;
    }

    public static String run(Context context) {
        StringBuilder result = new StringBuilder("RM11 WinCore V1.5 / Box64 dynamic Linux x86-64 glibc guest\n")
            .append("EXPERIMENT: known first-party ELF asset only; not Windows EXE.\n")
            .append("No Linux/glibc rootfs, loader, Wine or DXVK is bundled by RM11.\n\n");
        if (Build.SUPPORTED_ABIS.length == 0 || !"arm64-v8a".equals(Build.SUPPORTED_ABIS[0]))
            return result.append("[STOP] Android ARM64 required.\n").toString();
        File executable = new File(context.getApplicationInfo().nativeLibraryDir, BOX64);
        if (!executable.isFile())
            return result.append("[NOT BUILT] Box64 was not packaged in this APK.\n").toString();
        File guest = null;
        Process process = null;
        try {
            byte[] guestBytes;
            try (InputStream input = context.getAssets().open(ASSET);
                 ByteArrayOutputStream bytes = new ByteArrayOutputStream()) {
                byte[] chunk = new byte[4096];
                int n;
                while ((n = input.read(chunk)) != -1) {
                    if (bytes.size() + n > MAX_SIZE)
                        throw new IllegalArgumentException("Guest asset exceeds limit");
                    bytes.write(chunk, 0, n);
                }
                guestBytes = bytes.toByteArray();
            }
            ElfRuntimeInspector.Report audit = verifyGuest(guestBytes);
            result.append("[AUDIT OK] ELF64 x86-64; ")
                  .append(audit.kind == 3 ? "ET_DYN" : "ET_EXEC")
                  .append("; ").append(guestBytes.length).append(" bytes\n")
                  .append("PT_INTERP: ").append(audit.interpreter).append("\n")
                  .append("DT_NEEDED: ").append(String.join(", ", audit.needed)).append("\n")
                  .append("Host Android/Bionic does not itself provide x86-64 glibc.\n\n");
            guest = File.createTempFile("rm11-glibc-guest-", ".elf", context.getCacheDir());
            try (FileOutputStream stream = new FileOutputStream(guest)) {
                stream.write(guestBytes);
                stream.getFD().sync();
            }
            // Box64 checks X_OK; the guest is DATA, never executed directly by Android.
            if (!(guest.setExecutable(true, true) && guest.canExecute()))
                return result.append("[BLOCKED] Unable to set owner X_OK for Box64 ELF inspection.\n").toString();
            ProcessBuilder pb = new ProcessBuilder(executable.getAbsolutePath(), guest.getAbsolutePath());
            pb.directory(context.getCacheDir());
            pb.redirectErrorStream(true);
            pb.environment().put("BOX64_LOG", "1");
            process = pb.start();
            final Process target = process;
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            Thread reader = new Thread(() -> {
                try (InputStream in = target.getInputStream()) {
                    byte[] chunk = new byte[1024];
                    int n;
                    while ((n = in.read(chunk)) != -1) {
                        synchronized (output) {
                            if (output.size() < MAX_OUTPUT) {
                                output.write(chunk, 0, Math.min(n, MAX_OUTPUT - output.size()));
                            }
                        }
                    }
                } catch (Exception ignored) { }
            }, "rm11-dynamic-guest-output");
            reader.setDaemon(true);
            reader.start();
            boolean finished = process.waitFor(20, TimeUnit.SECONDS);
            if (!finished) process.destroyForcibly();
            reader.join(1200);
            String log;
            synchronized (output) {
                log = new String(output.toByteArray(), StandardCharsets.UTF_8);
            }
            result.append("Exit code: ").append(finished ? process.exitValue() : "TIMEOUT").append("\n")
                  .append("Box64 output (bounded):\n").append(log).append("\n");
            if (!finished) {
                result.append("[TIMEOUT] Box64 or guest did not exit within 20 seconds.\n");
            } else if (process.exitValue() == 0 && log.contains(MARKER)) {
                result.append("[PASS] Box64 executed a genuine dynamically glibc-linked x86-64 Linux guest.\n")
                      .append("[LIMIT] This does not mean Wine, EXE, games or FPS are supported.\n");
            } else {
                String lower = log.toLowerCase(Locale.ROOT);
                if (lower.contains("libc.so.6") || lower.contains("ld-linux")
                        || lower.contains("needed lib") || lower.contains("cannot open shared object")
                        || lower.contains("cannot find library") || lower.contains("symbol not found")) {
                    result.append("[DEPENDENCY BLOCKED] Dynamic guest did not start successfully.\n")
                          .append("Box64 may need compatible Linux/glibc runtime or wrappers; read exact error above.\n");
                } else {
                    result.append("[FAIL] No confirmed dynamically-linked x86-64 execution; inspect Box64 output.\n");
                }
                result.append("[NEXT] Investigate a LICENSE-COMPLIANT compatible loader/userland, not an arbitrary APK/ZIP.\n");
            }
        } catch (Exception e) {
            result.append("[FAIL] ").append(e.getClass().getSimpleName())
                  .append(": ").append(e.getMessage()).append("\n");
        } finally {
            if (process != null && process.isAlive()) process.destroyForcibly();
            if (guest != null) guest.delete();
        }
        return result.toString();
    }
}
