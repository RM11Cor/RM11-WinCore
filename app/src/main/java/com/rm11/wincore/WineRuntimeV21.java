package com.rm11.wincore;

import android.content.Context;
import android.os.Build;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/** Experimental x86-64 Linux Wine startup layout, NOT Windows program execution.
 * Distro Wine version test uses Box64; Wine, ntdll and wineserver are from
 * matched signed-distribution packages. No arbitrary user EXE accepted.
 */
public final class WineRuntimeV21 {
    private WineRuntimeV21() { }
    private static final String ASSETS = "wine_runtime_v21/";
    private static final String[] FILES = {
        "usr/lib/wine/wine64",
        "usr/lib/wine/wineserver64",
        "usr/lib/x86_64-linux-gnu/wine/x86_64-unix/ntdll.so",
        "usr/lib/x86_64-linux-gnu/wine/x86_64-windows/ntdll.dll",
        "usr/lib/x86_64-linux-gnu/libunwind.so.8",
        "usr/lib/x86_64-linux-gnu/libunwind-x86_64.so.8",
        "usr/lib/x86_64-linux-gnu/liblzma.so.5"
    };
    private static final int MAX_FILE_BYTES = 24 * 1024 * 1024;
    private static final int MAX_MANIFEST_BYTES = 8192;
    private static final int MAX_LOG_BYTES = 16384;
    private static final int TIMEOUT_SECONDS = 18;

    static Map<String, String> parseManifest(String manifest) {
        Map<String, String> checksums = new HashMap<>();
        for (String line : manifest.split("\\r?\\n")) {
            if (line.startsWith("#") || line.startsWith("Version: ") || line.startsWith("Source: ") || line.startsWith("Use: ") || line.startsWith("Libunwind-Version: ") || line.startsWith("Liblzma-Version: ") || line.isEmpty()) continue;
            String[] parts = line.split("\\t", -1);
            if (parts.length != 3 || !parts[1].matches("[0-9a-f]{64}") || !parts[2].matches("[0-9]{1,10}"))
                throw new IllegalArgumentException("Invalid Wine runtime manifest entry");
            if (checksums.put(parts[0], parts[1]) != null)
                throw new IllegalArgumentException("Duplicate Wine asset");
        }
        if (checksums.size() != FILES.length) throw new IllegalArgumentException("Incomplete Wine runtime manifest");
        for (String file : FILES) if (!checksums.containsKey(file)) throw new IllegalArgumentException("Missing Wine asset: " + file);
        return checksums;
    }

    private static String hexDigest(byte[] data) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
        StringBuilder result = new StringBuilder(64);
        for (byte b : digest) result.append(String.format(Locale.ROOT, "%02x", b & 0xff));
        return result.toString();
    }

    private static byte[] readAsset(Context ctx, String asset, int max) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (InputStream input = ctx.getAssets().open(asset)) {
            byte[] bytes = new byte[8192];
            int n;
            while ((n = input.read(bytes)) != -1) {
                if (n > max - out.size()) throw new IllegalArgumentException("Asset too large: " + asset);
                out.write(bytes, 0, n);
            }
        }
        return out.toByteArray();
    }

    static String classify(int code, boolean timedOut, String text) {
        if (timedOut) return "[TIMEOUT] Wine startup did not finish in 18 seconds. No EXE launched.\n";
        String lower = text.toLowerCase(Locale.ROOT);
        if (lower.contains("error loading needed lib") || lower.contains("error initializing needed lib")
                || lower.contains("could not load ntdll.so") || lower.contains("cannot dlopen") || lower.contains("cannot open shared object")
                || lower.contains("symbol not found") || lower.contains("error while loading"))
            return "[DEPENDENCY BLOCKED] Wine/Box64 library or symbol is unresolved. Read the first actual missing symbol/library above.\n";
        if (code == 0 && WineLoaderV20.versionSeen(text))
            return "[PASS WINE VERSION] Wine Linux loader reported its version via Box64 with staged startup libraries.\n"
                + "[LIMIT] No Windows EXE, prefix, display, wineserver integration, DXVK or game tested.\n";
        return "[FAIL WINE VERSION] Exit code: " + code + ". Inspect exact Wine/Box64 logs.\n";
    }

    /** Reuse the verified V2.1.4 Wine/ntdll/unwind binaries for the V2.2 EXE test. */
    static void stageTo(Context ctx, File root) throws Exception {
            String manifest = new String(readAsset(ctx, ASSETS + "COMPONENTS.tsv", MAX_MANIFEST_BYTES), StandardCharsets.UTF_8);
            Map<String, String> sums = parseManifest(manifest);
            // Use a controlled fixed path tree to preserve Wine's relative ntdll location.
            for (String rel : FILES) {
                byte[] raw = readAsset(ctx, ASSETS + rel, MAX_FILE_BYTES);
                if (!hexDigest(raw).equals(sums.get(rel))) throw new IllegalArgumentException("SHA256 mismatch: " + rel);
                File target = new File(root, rel);
                if (!target.getParentFile().isDirectory() && !target.getParentFile().mkdirs())
                    throw new IllegalStateException("Could not create Wine runtime directory");
                try (FileOutputStream output = new FileOutputStream(target)) {
                    output.write(raw);
                    output.getFD().sync();
                }
                if (rel.endsWith("/wine64") || rel.endsWith("/wineserver64")) {
                    if (!target.setExecutable(true, true) || !target.canExecute())
                        throw new IllegalStateException("Executable permission denied: " + rel);
                }
            }
    }

    public static String run(Context ctx) {
        StringBuilder report = new StringBuilder("RM11 WinCore V2.1.4 / Box64 Android glibc compatibility bridges + Wine diagnostic\n")
                .append("Offline Wine --version experiment; no Windows EXE or game launched.\n");
        if (Build.SUPPORTED_ABIS.length == 0 || !"arm64-v8a".equals(Build.SUPPORTED_ABIS[0]))
            return report.append("[STOP] Android ARM64 required.\n").toString();
        File box = new File(ctx.getApplicationInfo().nativeLibraryDir, "librm11box64.so");
        if (!box.isFile()) return report.append("[NOT BUILT] Genuine Box64 absent.\n").toString();
        Process process = null;
        try {
            File root = new File(ctx.getCacheDir(), "rm11-wine-v214");
            stageTo(ctx, root);
            File wine = new File(root, FILES[0]);
            File ntdll = new File(root, FILES[2]);
            if (!wine.canExecute() || !ntdll.isFile()) throw new IllegalStateException("Wine runtime staging incomplete");
            report.append("[STAGED] Wine loader, ntdll, wineserver64, libunwind.so.8, libunwind-x86_64.so.8 and liblzma.so.5\n")
                  .append("[SHA256 OK] all 7 packaged components verified\n")
                  .append("[PATH] ").append(ntdll.getAbsolutePath()).append("\n");
            ProcessBuilder pb = new ProcessBuilder(box.getAbsolutePath(), wine.getAbsolutePath(), "--version");
            pb.directory(wine.getParentFile());
            pb.redirectErrorStream(true);
            pb.environment().put("BOX64_DYNAREC", "0");
            pb.environment().put("BOX64_LOG", "1");
            String wineLibs = new File(root, "usr/lib/x86_64-linux-gnu/wine/x86_64-unix").getAbsolutePath();
            String supportLibs = new File(root, "usr/lib/x86_64-linux-gnu").getAbsolutePath();
            pb.environment().put("BOX64_LD_LIBRARY_PATH", wineLibs + ":" + supportLibs);
            pb.environment().put("WINEDLLPATH", new File(root, "usr/lib/x86_64-linux-gnu/wine").getAbsolutePath());
            pb.environment().put("WINESERVER", new File(root, "usr/lib/wine/wineserver64").getAbsolutePath());
            pb.environment().remove("LD_PRELOAD");
            // These x86-64 libraries are guest data, not Android ARM64 shared objects.
            // Do not set the Android process LD_LIBRARY_PATH to this guest directory.
            pb.environment().remove("WINEPREFIX");
            pb.environment().remove("WINEDLLOVERRIDES");
            process = pb.start();
            final Process active = process;
            final ByteArrayOutputStream logs = new ByteArrayOutputStream();
            Thread reader = new Thread(() -> {
                try (InputStream stream = active.getInputStream()) {
                    byte[] buf = new byte[2048];
                    int n;
                    while ((n = stream.read(buf)) != -1) {
                        synchronized (logs) {
                            int space = MAX_LOG_BYTES - logs.size();
                            if (space > 0) logs.write(buf, 0, Math.min(space, n));
                        }
                    }
                } catch (Exception ignored) { }
            }, "rm11-wine-v21-drain");
            reader.setDaemon(true);
            reader.start();
            boolean finished = process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                process.waitFor(2, TimeUnit.SECONDS);
            }
            reader.join(1200);
            String output;
            synchronized (logs) { output = new String(logs.toByteArray(), StandardCharsets.UTF_8); }
            int code = finished ? process.exitValue() : -1;
            report.append("Exit code: ").append(code).append(finished ? "" : " / TIMEOUT")
                .append("\nOutput (bounded):\n").append(output).append('\n')
                .append(classify(code, !finished, output));
        } catch (java.io.FileNotFoundException missing) {
            report.append("[NOT PACKAGED] Missing Wine V2.1 asset: ").append(missing.getMessage()).append('\n');
        } catch (Exception e) {
            report.append("[RUNTIME ERROR] ").append(e.getClass().getSimpleName()).append(": ")
                  .append(e.getMessage()).append('\n');
        } finally {
            if (process != null && process.isAlive()) process.destroyForcibly();
            // Keep staged components in private cache for diagnostics; never execute unknown inputs.
        }
        return report.toString();
    }
}
