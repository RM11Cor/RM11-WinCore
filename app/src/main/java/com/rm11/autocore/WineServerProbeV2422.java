package com.rm11.autocore;

import android.content.Context;
import java.io.File;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.util.concurrent.TimeUnit;

/** Diagnostic only: verifies Android can launch the packaged wineserver ELF. */
public final class WineServerProbeV2422 {
    private WineServerProbeV2422() {}

    public static String run(Context context) {
        StringBuilder result = new StringBuilder("RM11 v2.4.24 — isolated wineserver process probe\n");
        File nativeDir = new File(context.getApplicationInfo().nativeLibraryDir);
        File server = new File(nativeDir, "libwineserverrm11.so");
        result.append("APK-native wineserver exists: ").append(server.isFile()).append("\n");
        result.append("Bytes: ").append(server.isFile() ? server.length() : 0).append("\n");
        result.append("Can execute (file flag): ").append(server.canExecute()).append("\n");
        if (!server.isFile()) return result.append("BLOCKED: Wine server not packaged.").toString();

        Process child = null;
        try {
            ProcessBuilder pb = new ProcessBuilder(server.getAbsolutePath(), "--version");
            pb.redirectErrorStream(true);
            pb.environment().put("HOME", context.getFilesDir().getAbsolutePath());
            pb.environment().put("TMPDIR", context.getCacheDir().getAbsolutePath());
            pb.environment().put("WINEPREFIX", new File(context.getFilesDir(), "wineserver-probe-v2422").getAbsolutePath());
            pb.environment().put("LD_LIBRARY_PATH", nativeDir.getAbsolutePath());
            pb.environment().put("WINEDEBUG", "+err,+warn");
            result.append("Launching APK-native wineserver --version...\n");
            child = pb.start();
            final Process process = child;
            final ByteArrayOutputStream collected = new ByteArrayOutputStream();
            Thread reader = new Thread(() -> {
                try (InputStream input=process.getInputStream()) {
                    byte[] chunk = new byte[2048]; int n;
                    while ((n=input.read(chunk))!=-1) {
                        synchronized (collected) {
                            int space = 16384-collected.size();
                            if (space>0) collected.write(chunk,0,Math.min(space,n));
                        }
                    }
                } catch (Exception ignored) { }
            }, "rm11-server-probe-output");
            reader.setDaemon(true);
            reader.start();
            boolean finished=child.waitFor(12,TimeUnit.SECONDS);
            if (!finished) {
                child.destroyForcibly();
                child.waitFor(3,TimeUnit.SECONDS);
            }
            reader.join(1600);
            String output;
            synchronized(collected) { output=collected.toString("UTF-8"); }
            result.append("Output: ").append(output.isEmpty()?"<empty>":output).append("\n");
            if (!finished) return result.append("SERVER PROCESS TIMEOUT (12 s).\nWindows EXE: NOT VERIFIED").toString();
            int exit=child.exitValue();
            result.append("wineserver --version exit code: ").append(exit).append("\n");
            result.append(exit==0 ? "SERVER SELF-TEST: PASS\n" : "SERVER SELF-TEST: FAILED\n");
            return result.append("Windows EXE: NOT VERIFIED by this test").toString();
        } catch (Exception e) {
            return result.append("SERVER EXECUTION ERROR: ").append(e.getClass().getSimpleName())
                    .append(": ").append(e.getMessage())
                    .append("\nWindows EXE: NOT VERIFIED").toString();
        } finally {
            if (child!=null && child.isAlive()) child.destroyForcibly();
        }
    }
}
