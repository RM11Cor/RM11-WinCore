package com.rm11.autocore;

import android.content.Context;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** v2.4.20 device-side experiment. Never claims that Windows EXEs are supported. */
public final class WineSmokeV2417 {
    private static final String ASSET = "runtime/rm11-wine-stack.zip";
    private static final long MAX_EXPANDED = 3L * 1024 * 1024 * 1024;
    private static final int MAX_FILES = 25000;

    private WineSmokeV2417() {}

    public static String run(Context context) {
        StringBuilder log = new StringBuilder("RM11 v2.4.20 Wine process smoke test\n");
        File root = new File(context.getFilesDir(), "runtime-v2417");
        File tmp = new File(context.getFilesDir(), "runtime-v2417.partial");
        File executable = new File(context.getApplicationInfo().nativeLibraryDir, "libwineprobe.so");
        try {
            if (!executable.isFile()) {
                return log.append("FAIL: APK-native Wine launcher not extracted: ")
                        .append(executable.getAbsolutePath()).toString();
            }
            log.append("APK-native Wine bridge: ").append(executable.length()).append(" bytes\n");
            File nativeNtdll = new File(context.getApplicationInfo().nativeLibraryDir, "libwine_ntdll.so");
            log.append("APK-native NTDLL: ").append(nativeNtdll.isFile())
                    .append("; bytes: ").append(nativeNtdll.isFile() ? nativeNtdll.length() : 0)
                    .append("\n");
            if (!nativeNtdll.isFile()) return log.append("BLOCKED: packaged libwine_ntdll.so missing").toString();

            if (!isReady(root)) {
                // Never mutate games. Only work under this app's private directory.
                if (context.getFilesDir().getUsableSpace() < 900L * 1024 * 1024) {
                    return log.append("BLOCKED: less than 900 MiB free for staging.\n")
                            .append("No game files were touched.").toString();
                }
                erase(tmp);
                if (!tmp.mkdirs()) throw new IllegalStateException("Cannot create staging directory");
                log.append("Provisioning runtime ZIP in app-private storage...\n");
                long total = 0;
                int entries = 0;
                byte[] buffer = new byte[65536];
                try (InputStream asset = context.getAssets().open(ASSET);
                     ZipInputStream zin = new ZipInputStream(new BufferedInputStream(asset))) {
                    ZipEntry entry;
                    String base = tmp.getCanonicalPath() + File.separator;
                    while ((entry = zin.getNextEntry()) != null) {
                        if (++entries > MAX_FILES) throw new IllegalStateException("Too many entries");
                        String name = entry.getName();
                        if (name.startsWith("/") || name.indexOf('\\') >= 0)
                            throw new IllegalStateException("Unsafe ZIP entry");
                        File dest = new File(tmp, name);
                        String canonical = dest.getCanonicalPath();
                        if (!canonical.startsWith(base) && !canonical.equals(tmp.getCanonicalPath()))
                            throw new IllegalStateException("ZIP traversal rejected");
                        if (entry.isDirectory()) {
                            if (!dest.isDirectory() && !dest.mkdirs())
                                throw new IllegalStateException("Cannot create directory");
                        } else {
                            File parent = dest.getParentFile();
                            if (!parent.isDirectory() && !parent.mkdirs())
                                throw new IllegalStateException("Cannot create parent");
                            try (OutputStream out = new FileOutputStream(dest)) {
                                int n;
                                while ((n = zin.read(buffer)) != -1) {
                                    total += n;
                                    if (total > MAX_EXPANDED) throw new IllegalStateException("Expansion budget exceeded");
                                    out.write(buffer, 0, n);
                                }
                            }
                        }
                        zin.closeEntry();
                    }
                }
                if (!isPayloadPresent(tmp)) throw new IllegalStateException("Missing Wine/FEX payload files");
                if (root.exists()) erase(root);
                if (!tmp.renameTo(root)) throw new IllegalStateException("Staging rename failed");
                try (OutputStream marker = new FileOutputStream(new File(root, ".ready"))) {
                    marker.write("v2.4.20\n".getBytes(StandardCharsets.UTF_8));
                }
                log.append("ZIP expanded: ").append(total).append(" bytes; entries: ").append(entries).append("\n");
            } else {
                log.append("Runtime already provisioned.\n");
            }
            // Android target 35 prevents ordinary execution from writable app-data.
            // Execute ONLY the packaged, read-only APK nativeLibraryDir copy.
            File prefix = new File(context.getFilesDir(), "wineprefix-v2417");
            if (!prefix.exists() && !prefix.mkdirs()) throw new IllegalStateException("Cannot create WINEPREFIX");
            ProcessBuilder pb = new ProcessBuilder(executable.getAbsolutePath(), "--version");
            pb.redirectErrorStream(true);
            pb.environment().put("HOME", context.getFilesDir().getAbsolutePath());
            pb.environment().put("WINEPREFIX", prefix.getAbsolutePath());
            pb.environment().put("WINEDEBUG", "-all");
            // Wine loader searches for native ntdll.so in WINEDLLPATH.
            // Base lib/wine is needed because Wine appends its /aarch64-unix suffix.
            File wineBase = new File(root, "lib/wine");
            File wineUnix = new File(wineBase, "aarch64-unix");
            File wineWindows = new File(wineBase, "aarch64-windows");
            File ntdll = new File(wineUnix, "ntdll.so");
            log.append("ntdll.so present: ").append(ntdll.isFile())
                    .append("; bytes: ").append(ntdll.isFile() ? ntdll.length() : 0)
                    .append("\n");
            if (!ntdll.isFile()) return log.append("FAIL: native ntdll.so missing from provisioned runtime").toString();
            String wineDllPath = wineBase.getAbsolutePath() + ":"
                    + wineUnix.getAbsolutePath() + ":" + wineWindows.getAbsolutePath();
            pb.environment().put("WINEDLLPATH", wineDllPath);
            log.append("WINEDLLPATH: ").append(wineDllPath).append("\n");
            pb.environment().put("LD_LIBRARY_PATH", new File(root, "lib").getAbsolutePath() + ":"
                    + new File(root, "lib/wine/aarch64-unix").getAbsolutePath() + ":"
                    + context.getApplicationInfo().nativeLibraryDir);
            log.append("Attempting actual Wine process: --version\n");
            Process process = pb.start();
            if (!process.waitFor(15, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                process.waitFor(3, TimeUnit.SECONDS);
                return log.append("TIMEOUT after 15 seconds; Wine process terminated.\n")
                        .append("Windows EXE integration: NOT VERIFIED").toString();
            }
            ByteArrayOutputStream stdout = new ByteArrayOutputStream();
            try (InputStream input = process.getInputStream()) {
                byte[] buffer = new byte[2048];
                int n;
                while (stdout.size() < 8192 && (n = input.read(buffer)) != -1)
                    stdout.write(buffer, 0, Math.min(n, 8192 - stdout.size()));
            }
            String output = stdout.toString("UTF-8").trim();
            int exit = process.exitValue();
            log.append("Exit code: ").append(exit).append("\nOutput: ").append(output).append("\n");
            if (exit == 0 && output.toLowerCase(java.util.Locale.ROOT).contains("wine")) {
                log.append("Wine --version: PASS (process started)\n");
            } else {
                log.append("Wine --version: NOT PASSED\n");
            }
            log.append("Windows EXE / graphics / display: NOT VERIFIED");
            return log.toString();
        } catch (Throwable error) {
            return log.append("BLOCKED / FAILED: ").append(error.getClass().getSimpleName())
                    .append(": ").append(error.getMessage())
                    .append("\nWindows EXE launch: NOT VERIFIED").toString();
        }
    }

    private static boolean isPayloadPresent(File root) {
        return new File(root, "bin/wine").isFile()
                && new File(root, "lib/wine/aarch64-unix/ntdll.so").isFile()
                && new File(root, "lib/wine/aarch64-windows/libarm64ecfex.dll").isFile()
                && new File(root, "lib/wine/aarch64-windows/libwow64fex.dll").isFile();
    }

    private static boolean isReady(File root) {
        return new File(root, ".ready").isFile() && isPayloadPresent(root);
    }

    private static void erase(File file) {
        if (!file.exists()) return;
        if (file.isDirectory()) {
            File[] entries = file.listFiles();
            if (entries == null) throw new IllegalStateException("Cannot inspect staging directory");
            for (File child : entries) erase(child);
        }
        if (!file.delete()) throw new IllegalStateException("Cannot clean staging entry");
    }
}
