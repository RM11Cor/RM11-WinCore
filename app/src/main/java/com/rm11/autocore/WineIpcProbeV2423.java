package com.rm11.autocore;

import android.content.Context;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/** Bounded diagnostic of an actual foreground wineserver + PE64 test EXE. */
public final class WineIpcProbeV2423 {
    private static final String ASSET = "rm11-win32-smoke-v2420.exe";
    private static final String HASH = "3bbe50165aa735bc54b5e647861cf192ed603468fea89024f563de9be6547fe9";
    private WineIpcProbeV2423() {}

    private static final class Capture implements Runnable {
        private final Process process;
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        private volatile boolean truncated;
        Capture(Process p) { process = p; }
        @Override public void run() {
            try (InputStream in = process.getInputStream()) {
                byte[] b = new byte[2048]; int n;
                while ((n = in.read(b)) != -1) {
                    synchronized (bytes) {
                        int room = 14000 - bytes.size();
                        if (room > 0) bytes.write(b, 0, Math.min(room, n));
                        if (room < n) truncated = true;
                    }
                }
            } catch (Exception ignored) { }
        }
        String report() {
            synchronized (bytes) {
                try { return bytes.toString("UTF-8") + (truncated ? "\n[output truncated]\n" : ""); }
                catch (Exception e) { return "Output decode error: " + e.getMessage(); }
            }
        }
    }

    private static String sha256(File file) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (FileInputStream in = new FileInputStream(file)) {
            byte[] b = new byte[16384]; int n;
            while ((n = in.read(b)) != -1) md.update(b, 0, n);
        }
        StringBuilder s = new StringBuilder();
        for (byte b : md.digest()) s.append(String.format(Locale.ROOT, "%02x", b & 255));
        return s.toString();
    }

    public static String run(Context context) {
        StringBuilder r = new StringBuilder("RM11 v2.4.24: REAL wineserver IPC and Windows EXE diagnostic\n");
        Process server = null;
        Process wine = null;
        Thread serverReader = null;
        Capture serverCapture = null;
        try {
            File root = new File(context.getFilesDir(), "runtime-v2417");
            File nativeDir = new File(context.getApplicationInfo().nativeLibraryDir);
            File exe = new File(context.getFilesDir(), ASSET);
            File serverBin = new File(nativeDir, "libwineserverrm11.so");
            File bridge = new File(nativeDir, "libwineprobe.so");
            File ntdll = new File(nativeDir, "libwine_ntdll.so");
            File prefix = new File(context.getFilesDir(), "wineprefix-v2423-ipc");
            File prefixPack = new File(root, "prefixPack.txz");
            r.append("Wine runtime ready: ").append(new File(root, ".ready").isFile()).append("\n");
            r.append("prefixPack.txz present (NOT automatically installed): ").append(prefixPack.isFile()).append("\n");
            r.append("Server / bridge / ntdll present: ").append(serverBin.isFile()).append(" / ")
             .append(bridge.isFile()).append(" / ").append(ntdll.isFile()).append("\n");
            if (!new File(root, ".ready").isFile() || !serverBin.isFile() || !bridge.isFile() || !ntdll.isFile())
                return r.append("BLOCKED: Run Wine --version test first or check APK native components.").toString();
            if (!exe.isFile() || !HASH.equalsIgnoreCase(sha256(exe))) {
                try (InputStream in = context.getAssets().open(ASSET);
                     FileOutputStream out = new FileOutputStream(exe, false)) {
                    byte[] b = new byte[16384]; int n;
                    while ((n = in.read(b)) != -1) out.write(b, 0, n);
                }
            }
            if (!HASH.equalsIgnoreCase(sha256(exe))) return r.append("FAIL: Windows EXE hash mismatch").toString();
            if (!prefix.isDirectory() && !prefix.mkdirs()) return r.append("FAIL: cannot create isolated WINEPREFIX").toString();
            r.append("Windows EXE: PE64 AMD64 / hash OK / ").append(exe.length()).append(" bytes\n");
            File nls = new File(root,"share/wine/nls/l_intl.nls");
            r.append("NLS table present: ").append(nls.isFile()).append("; bytes: ").append(nls.isFile()?nls.length():0).append("\n");
            if (!nls.isFile()) return r.append("BLOCKED: run Wine --version first to refresh NLS data.\n").toString();
            r.append("Starting wineserver in FOREGROUND debug mode (-f -d1 -p)...\n");
            ProcessBuilder spb = new ProcessBuilder(serverBin.getAbsolutePath(), "-f", "-d1", "-p");
            spb.redirectErrorStream(true);
            spb.environment().put("HOME", context.getFilesDir().getAbsolutePath());
            spb.environment().put("TMPDIR", context.getCacheDir().getAbsolutePath());
            spb.environment().put("WINEPREFIX", prefix.getAbsolutePath());
            spb.environment().put("LD_LIBRARY_PATH", nativeDir.getAbsolutePath());
            spb.environment().put("XDG_DATA_DIRS", new File(root,"share").getAbsolutePath());
            spb.environment().put("WINE_DATADIR", new File(root,"share/wine").getAbsolutePath());

            server = spb.start();
            serverCapture = new Capture(server);
            serverReader = new Thread(serverCapture, "rm11-wineserver-foreground-log");
            serverReader.setDaemon(true); serverReader.start();
            Thread.sleep(1300);
            if (!server.isAlive()) {
                return r.append("SERVER EARLY EXIT: ").append(server.exitValue()).append("\nSERVER LOG:\n")
                    .append(serverCapture.report()).append("\nEXE NOT ATTEMPTED\n").toString();
            }
            r.append("Foreground wineserver alive after startup: YES\n");
            ProcessBuilder pb = new ProcessBuilder(bridge.getAbsolutePath(), exe.getAbsolutePath());
            pb.redirectErrorStream(true);
            pb.environment().put("HOME", context.getFilesDir().getAbsolutePath());
            pb.environment().put("TMPDIR", context.getCacheDir().getAbsolutePath());
            pb.environment().put("WINEPREFIX", prefix.getAbsolutePath());
            pb.environment().put("WINELOADERNOEXEC", "1");
            pb.environment().put("XDG_DATA_DIRS", new File(root,"share").getAbsolutePath());
            pb.environment().put("WINE_DATADIR", new File(root,"share/wine").getAbsolutePath());

            pb.environment().put("WINESERVER", serverBin.getAbsolutePath());
            pb.environment().put("WINEDEBUG", "+err,+warn,+server,+process,+module,+loaddll");
            File wineLib = new File(root, "lib/wine");
            pb.environment().put("WINEDLLPATH", wineLib.getAbsolutePath()+":"
                +new File(wineLib,"aarch64-unix").getAbsolutePath()+":"
                +new File(wineLib,"aarch64-windows").getAbsolutePath());
            pb.environment().put("LD_LIBRARY_PATH", new File(root,"lib").getAbsolutePath()+":"
                +new File(root,"lib/wine/aarch64-unix").getAbsolutePath()+":"+nativeDir.getAbsolutePath());
            r.append("Launching Windows EXE with live wineserver...\n");
            wine = pb.start();
            Capture wineCapture = new Capture(wine);
            Thread wineReader = new Thread(wineCapture, "rm11-wine-ipc-log");
            wineReader.setDaemon(true); wineReader.start();
            boolean completed = wine.waitFor(35, TimeUnit.SECONDS);
            if (!completed) { wine.destroyForcibly(); wine.waitFor(3, TimeUnit.SECONDS); }
            wineReader.join(1800);
            String wineLog = wineCapture.report();
            r.append("Wine completed: ").append(completed).append("\n");
            if (completed) r.append("Wine exit: ").append(wine.exitValue()).append("\n");
            r.append("Win32 marker: ").append(wineLog.contains("RM11_WIN32_EXE_EXECUTED_OK") ? "YES" : "NO").append("\n");
            r.append("Foreground wineserver still alive: ").append(server.isAlive()).append("\n");
            r.append("WINE OUTPUT:\n").append(wineLog).append("\n");
            r.append("SERVER OUTPUT:\n").append(serverCapture.report()).append("\n");
            boolean passed = completed && wine.exitValue()==42 && wineLog.contains("RM11_WIN32_EXE_EXECUTED_OK");
            r.append(passed ? "RESULT: PASS actual Windows EXE Win32 calls\n" : "RESULT: NOT PASSED; inspect server and Wine logs\n");
            r.append("Graphics / FEX full game compatibility: NOT VERIFIED");
            return r.toString();
        } catch (Exception e) {
            return r.append("ERROR: ").append(e.getClass().getSimpleName()).append(": ")
                .append(e.getMessage()).append("\nEXE NOT VERIFIED").toString();
        } finally {
            if (wine != null && wine.isAlive()) wine.destroyForcibly();
            if (server != null && server.isAlive()) server.destroyForcibly();
            if (serverReader != null) try { serverReader.join(500); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
        }
    }
}

