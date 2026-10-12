package com.rm11.wincore;

import android.content.Context;
import android.os.Build;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/** First attempt to invoke a genuine, distro-built Linux x86-64 Wine loader via Box64.
 * No libwine, wineserver, glibc filesystem, prefix or Windows program is supplied.
 */
public final class WineLoaderV20 {
    private WineLoaderV20() { }
    private static final String ASSET = "wine_loader/wine64.elf";
    private static final int MAX_WINE_BYTES = 10 * 1024 * 1024;
    private static final int MAX_LOG_BYTES = 12 * 1024;
    private static final int TIMEOUT_SECONDS = 12;

    static boolean validWineCandidate(byte[] data) {
        if (data == null || data.length < 64 || data.length > MAX_WINE_BYTES) return false;
        if (data[0] != 127 || data[1] != 'E' || data[2] != 'L' || data[3] != 'F'
                || data[4] != 2 || data[5] != 1 || data[18] != 62 || data[19] != 0) return false;
        int kind = (data[16] & 255) | ((data[17] & 255) << 8);
        return kind == 2 || kind == 3;
    }

    private static byte[] readWineAsset(Context ctx) throws Exception {
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        try (InputStream stream = ctx.getAssets().open(ASSET)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = stream.read(buf)) != -1) {
                if (n > MAX_WINE_BYTES - data.size()) throw new IllegalArgumentException("Wine ELF too large");
                data.write(buf, 0, n);
            }
        }
        byte[] result = data.toByteArray();
        if (!validWineCandidate(result)) throw new IllegalArgumentException("Wine loader ELF architecture mismatch");
        try (InputStream receiptStream = ctx.getAssets().open("wine_loader/WINE64-PACKAGE-RECEIPT.txt")) {
            ByteArrayOutputStream receiptData = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int count;
            while ((count = receiptStream.read(buffer)) != -1) {
                if (count > 4096 - receiptData.size()) throw new IllegalArgumentException("Wine receipt too large");
                receiptData.write(buffer, 0, count);
            }
            String receipt = new String(receiptData.toByteArray(), StandardCharsets.UTF_8);
            String hash = "";
            for (String line : receipt.split("\\r?\\n")) {
                if (line.startsWith("SHA256: ")) hash = line.substring(8).trim();
            }
            byte[] actual = MessageDigest.getInstance("SHA-256").digest(result);
            StringBuilder hex = new StringBuilder();
            for (byte octet : actual) hex.append(String.format(Locale.ROOT, "%02x", octet & 255));
            if (!hash.matches("[a-f0-9]{64}") || !hash.equals(hex.toString()))
                throw new IllegalArgumentException("Wine ELF hash/receipt mismatch");
        }
        return result;
    }

    static boolean versionSeen(String log) {
        // Wine upstream prints "wine-<number>" for `--version`; other output is NOT proof.
        for (String line : log.split("\\r?\\n")) {
            if (line.trim().matches("wine-[0-9]+(\\.[0-9]+)+(?:[-.][a-zA-Z0-9]+)*(?: \\([^\\r\\n]{1,100}\\))?")) return true;
        }
        return false;
    }

    static String classify(int code, boolean timeout, String log) {
        if (!timeout && code == 0 && versionSeen(log))
            return "[PASS WINE VERSION] Genuine Wine Linux loader reported its version via Box64.\n"
                + "[LIMIT] Only --version was tested; wineserver, Wine DLLs, EXE and games NOT validated.\n";
        if (timeout) return "[TIMEOUT] Wine loader did not finish within 12 seconds. No Windows program launched.\n";
        String lower = log.toLowerCase(Locale.ROOT);
        if (lower.contains("not found") || lower.contains("missing") || lower.contains("cannot open")
                || lower.contains("error while loading") || lower.contains("symbol"))
            return "[DEPENDENCY BLOCKED] Wine loader or Box64 requires additional libraries/loader.\n"
                + "[NEXT] Assemble tested license-compliant runtime dependencies, not a random APK.\n";
        return "[FAIL WINE VERSION] No verified Wine version returned; exit code " + code + ".\n";
    }

    public static String run(Context ctx) {
        StringBuilder report = new StringBuilder("RM11 WinCore V2.0 / Genuine Wine loader via Box64\n")
            .append("Experiment ONLY: `wine64 --version`. No Windows EXE launched.\n")
            .append("Ubuntu/Debian x86-64 Wine package loader; not an Android Wine build.\n\n");
        if (Build.SUPPORTED_ABIS.length == 0 || !"arm64-v8a".equals(Build.SUPPORTED_ABIS[0]))
            return report.append("[STOP] Android ARM64 device required.\n").toString();
        File box = new File(ctx.getApplicationInfo().nativeLibraryDir, "librm11box64.so");
        if (!box.isFile()) return report.append("[NOT BUILT] Genuine Box64 missing from APK.\n").toString();
        File guest = null;
        Process process = null;
        try {
            byte[] binary;
            try {
                binary = readWineAsset(ctx);
            } catch (java.io.FileNotFoundException absent) {
                return report.append("[WINE NOT PACKAGED] APT Wine loader was not included at CI build.\n")
                    .append("No dummy binary substituted. Box64 tests remain usable.\n").toString();
            }
            guest = File.createTempFile("rm11-wine64-", ".elf", ctx.getCacheDir());
            try (FileOutputStream output = new FileOutputStream(guest)) {
                output.write(binary);
                output.getFD().sync();
            }
            if (!guest.setExecutable(true, true) || !guest.canExecute())
                throw new IllegalStateException("Android denied Wine loader executable permission");
            ProcessBuilder pb = new ProcessBuilder(box.getAbsolutePath(), guest.getAbsolutePath(), "--version");
            pb.directory(ctx.getCacheDir());
            pb.redirectErrorStream(true);
            // Restrict run to one harmless version probe: no client file, shell, Wine prefix or GUI.
            pb.environment().put("BOX64_DYNAREC", "0");
            pb.environment().put("BOX64_LOG", "1");
            pb.environment().remove("LD_PRELOAD");
            pb.environment().remove("WINEPREFIX");
            pb.environment().remove("WINEDLLOVERRIDES");
            process = pb.start();
            final Process running = process;
            final ByteArrayOutputStream capture = new ByteArrayOutputStream();
            Thread drain = new Thread(() -> {
                try (InputStream input = running.getInputStream()) {
                    byte[] buf = new byte[2048];
                    int n;
                    while ((n = input.read(buf)) != -1) {
                        synchronized (capture) {
                            int room = MAX_LOG_BYTES - capture.size();
                            if (room > 0) capture.write(buf, 0, Math.min(room, n));
                        }
                    }
                } catch (Exception ignored) { }
            }, "rm11-v20-wine-log");
            drain.setDaemon(true);
            drain.start();
            boolean finished = process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                process.waitFor(2, TimeUnit.SECONDS);
            }
            drain.join(1200);
            String out;
            synchronized (capture) { out = new String(capture.toByteArray(), StandardCharsets.UTF_8); }
            int code = finished ? process.exitValue() : -1;
            report.append("Exit code: ").append(code).append(finished ? "" : " / TIMEOUT")
                .append("\nOutput (bounded):\n").append(out).append('\n')
                .append(classify(code, !finished, out));
        } catch (Exception failure) {
            report.append("[EXECUTION ERROR] ").append(failure.getClass().getSimpleName())
                .append(": ").append(failure.getMessage()).append('\n');
        } finally {
            if (process != null && process.isAlive()) process.destroyForcibly();
            if (guest != null) guest.delete();
        }
        return report.toString();
    }
}
