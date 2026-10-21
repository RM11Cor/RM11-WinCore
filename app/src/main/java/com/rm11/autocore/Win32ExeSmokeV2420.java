package com.rm11.autocore;

import android.content.Context;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/** Diagnostics: uses one bundled Windows test EXE, NEVER a user game. */
public final class Win32ExeSmokeV2420 {
    private static final String ASSET = "rm11-win32-smoke-v2420.exe";
    private static final String EXPECTED_SHA256 = "3bbe50165aa735bc54b5e647861cf192ed603468fea89024f563de9be6547fe9";
    private Win32ExeSmokeV2420() {}

    public static String run(Context context) {
        StringBuilder result = new StringBuilder("RM11 v2.4.24: Windows PE32+ x86-64 loader re-exec diagnostic\n");
        Process proc = null;
        try {
            File root = new File(context.getFilesDir(), "runtime-v2417");
            File nativeDir = new File(context.getApplicationInfo().nativeLibraryDir);
            File bridge = new File(nativeDir, "libwineprobe.so");
            File ntdll = new File(nativeDir, "libwine_ntdll.so");
            if (!new File(root, ".ready").isFile()) {
                return result.append("BLOCKED: first run the Wine --version test to provision the runtime.").toString();
            }
            if (!bridge.isFile() || !ntdll.isFile()) {
                return result.append("BLOCKED: native Wine bridge or NTDLL missing from APK.").toString();
            }
            File pe = new File(context.getFilesDir(), ASSET);
            if (!pe.isFile() || !EXPECTED_SHA256.equalsIgnoreCase(sha256(pe))) {
                try (InputStream in = context.getAssets().open(ASSET);
                     FileOutputStream out = new FileOutputStream(pe, false)) {
                    byte[] buffer = new byte[32768];
                    int n;
                    while ((n=in.read(buffer))!=-1) out.write(buffer,0,n);
                }
            }
            if (!EXPECTED_SHA256.equalsIgnoreCase(sha256(pe))) {
                return result.append("FAIL: bundled Windows EXE SHA256 mismatch.").toString();
            }
            File prefix = new File(context.getFilesDir(), "wineprefix-v2421");
            if (!prefix.isDirectory() && !prefix.mkdirs()) {
                return result.append("FAIL: cannot create isolated smoke-test WINEPREFIX.").toString();
            }
            result.append("Bundled Windows EXE verified: ").append(pe.length()).append(" bytes\n");
            result.append("Native Wine bridge: ").append(bridge.length()).append(" bytes\n");
            ProcessBuilder pb = new ProcessBuilder(bridge.getAbsolutePath(), pe.getAbsolutePath());
            pb.redirectErrorStream(true);
            pb.environment().put("HOME", context.getFilesDir().getAbsolutePath());
            pb.environment().put("TMPDIR", context.getCacheDir().getAbsolutePath());
            pb.environment().put("WINEPREFIX", prefix.getAbsolutePath());
            // Pinned Wine 11 loader.c: __wine_main() re-execs the native Wine
            // launcher for a program but the APK-native ntdll computes a
            // non-existent `<nativeLibraryDir>/wine` path. Skip ONLY this
            // initial re-exec in this isolated smoke test. Do not treat it
            // as proof of a complete Windows runtime.
            pb.environment().put("WINEDEBUG", "-all,+err,+warn");
            pb.environment().put("WINELOADERNOEXEC", "1");
            pb.environment().put("XDG_DATA_DIRS", new File(root,"share").getAbsolutePath());
            pb.environment().put("WINE_DATADIR", new File(root,"share/wine").getAbsolutePath());

            result.append("Wine loader re-exec bypass: ENABLED (diagnostic only)\n");
            File nativeWineServer = new File(nativeDir, "libwineserverrm11.so");
            result.append("APK-native wineserver: ")
                    .append(nativeWineServer.isFile() ? "AVAILABLE" : "NOT PACKAGED")
                    .append("\n");
            if (nativeWineServer.isFile()) {
                pb.environment().put("WINESERVER", nativeWineServer.getAbsolutePath());
                result.append("WINESERVER: native APK executable\n");
            }
            File wine = new File(root, "lib/wine");
            pb.environment().put("WINEDLLPATH", wine.getAbsolutePath() + ":"
                    + new File(wine,"aarch64-unix").getAbsolutePath() + ":"
                    + new File(wine,"aarch64-windows").getAbsolutePath());
            pb.environment().put("LD_LIBRARY_PATH", new File(root,"lib").getAbsolutePath() + ":"
                    + new File(root,"lib/wine/aarch64-unix").getAbsolutePath() + ":"
                    + nativeDir.getAbsolutePath());
            result.append("Launching Windows EXE through Wine native bridge...\n");
            proc = pb.start();
            final Process current = proc;
            final ByteArrayOutputStream captured = new ByteArrayOutputStream();
            final boolean[] truncated = {false};
            Thread pump = new Thread(() -> {
                try (InputStream in=current.getInputStream()) {
                    byte[] chunk=new byte[2048]; int n;
                    while ((n=in.read(chunk))!=-1) {
                        synchronized (captured) {
                            int available=32768-captured.size();
                            if (available>0) captured.write(chunk,0,Math.min(n,available));
                            if (n>available) truncated[0]=true;
                        }
                    }
                } catch (Exception ignored) { }
            },"rm11-wine-output-pump");
            pump.setDaemon(true);
            pump.start();
            boolean ended = proc.waitFor(90,TimeUnit.SECONDS);
            if (!ended) {
                proc.destroyForcibly();
                proc.waitFor(3,TimeUnit.SECONDS);
            }
            pump.join(1500);
            String log;
            synchronized (captured) { log = captured.toString("UTF-8"); }
            if (log.length()>20000) log = log.substring(0,20000);
            result.append("Wine output:\n").append(log).append("\n");
            if (truncated[0]) result.append("[Output truncated to 32 KiB]\n");
            if (!ended) return result.append("TIMEOUT after 90 s: Windows EXE NOT VERIFIED.\n")
                    .append("Wine child processes might need additional lifecycle integration.").toString();
            int exit=proc.exitValue();
            result.append("Wine exit code: ").append(exit).append("\n");
            boolean marker=log.contains("RM11_WIN32_EXE_EXECUTED_OK");
            result.append("Win32 stdout marker: ").append(marker ? "YES" : "NO").append("\n");
            if (exit==42 && marker) {
                result.append("PASS: real x86-64 Windows EXE used Win32 WriteFile and ExitProcess.\n");
            } else {
                result.append("NOT PASSED: Windows EXE execution is not verified; inspect Wine output.\n");
            }
            return result.append("Games, display, DirectX, Turnip, DXVK and VKD3D: NOT VERIFIED").toString();
        } catch (Exception error) {
            return result.append("ERROR: ").append(error.getClass().getSimpleName())
                    .append(": ").append(error.getMessage())
                    .append("\nWindows EXE execution: NOT VERIFIED").toString();
        }
    }
    private static String sha256(File file) throws Exception {
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        try (java.io.FileInputStream in=new java.io.FileInputStream(file)) {
            byte[] b=new byte[65536]; int n;
            while ((n=in.read(b))!=-1) digest.update(b,0,n);
        }
        StringBuilder hex=new StringBuilder();
        for (byte b:digest.digest()) hex.append(String.format(Locale.ROOT,"%02x",b & 255));
        return hex.toString();
    }
}
