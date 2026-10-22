package com.rm11.autocore;

import android.content.Context;
import com.rm11.autocore.runtime.RuntimeLayout;
import com.rm11.autocore.runtime.WineExecutionPlan;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/** Executes ONE verified bundled Win32 smoke EXE with the committed ImageFs prefix.
 * Success requires the real PE64 process exit 42 AND its Win32 stdout marker.
 * This is intentionally NOT an arbitrary game loader or a graphics implementation.
 */
public final class UnifiedWineRunnerV255 {
    private static final String NAME = "rm11-win32-smoke-v2420.exe";
    private static final String SHA = "3bbe50165aa735bc54b5e647861cf192ed603468fea89024f563de9be6547fe9";
    private static final String MARKER = "RM11_WIN32_EXE_EXECUTED_OK";
    private UnifiedWineRunnerV255() {}

    /** Thread-safe bounded output pump. Never leaves the child blocked on a full pipe. */
    private static final class Capture implements Runnable {
        private final Process process;
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        private boolean truncated;
        Capture(Process process) { this.process = process; }
        public void run() {
            try (InputStream input = process.getInputStream()) {
                byte[] chunk = new byte[4096]; int n;
                while ((n = input.read(chunk)) != -1) {
                    synchronized (buffer) {
                        int room = 32768 - buffer.size();
                        if (room > 0) buffer.write(chunk, 0, Math.min(n, room));
                        if (room < n) truncated = true;
                    }
                }
            } catch (IOException ex) {
                synchronized (buffer) {
                    if (buffer.size() < 30000) {
                        byte[] error = ("\n[read error: " + ex.getClass().getSimpleName() + "]").getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        buffer.write(error, 0, error.length);
                    }
                }
            }
        }
        String text() {
            synchronized (buffer) {
                return new String(buffer.toByteArray(), java.nio.charset.StandardCharsets.UTF_8)
                        + (truncated ? "\n[LOG TRUNCATED after 32768 bytes]" : "");
            }
        }
    }

    private static final class Running {
        final Process process; final Capture capture; final Thread reader;
        Running(ProcessBuilder builder, String name) throws IOException {
            builder.redirectErrorStream(true);
            process = builder.start();
            capture = new Capture(process);
            reader = new Thread(capture, name);
            reader.setDaemon(true);
            reader.start();
        }
        void stopAndDrain() {
            if (process.isAlive()) {
                process.destroy();
                try {
                    if (!process.waitFor(2, TimeUnit.SECONDS)) process.destroyForcibly();
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt(); process.destroyForcibly();
                }
            }
            try { reader.join(1700); } catch (InterruptedException ex) { Thread.currentThread().interrupt(); }
        }
    }

    private static String hexSha256(Path file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream in = new FileInputStream(file.toFile())) {
            byte[] b = new byte[32768]; int n;
            while ((n = in.read(b)) != -1) digest.update(b, 0, n);
        }
        StringBuilder s = new StringBuilder();
        for (byte value : digest.digest()) s.append(String.format(java.util.Locale.ROOT, "%02x", value & 255));
        return s.toString();
    }

    private static void ensureVerifiedSmoke(Context ctx, Path exe) throws Exception {
        if (Files.exists(exe) && !Files.isSymbolicLink(exe) && SHA.equals(hexSha256(exe))) return;
        if (Files.isSymbolicLink(exe)) throw new IOException("Refusing symlink for test EXE");
        Path staged = exe.resolveSibling(NAME + ".pending");
        if (Files.exists(staged)) throw new IOException("Pending EXE staging preserved; review required");
        try (InputStream in = ctx.getAssets().open(NAME); OutputStream out = Files.newOutputStream(staged)) {
            byte[] b = new byte[16384]; int n; while ((n = in.read(b)) != -1) out.write(b, 0, n);
        }
        if (!SHA.equals(hexSha256(staged))) throw new IOException("Bundled test EXE SHA256 mismatch");
        Files.move(staged, exe, StandardCopyOption.REPLACE_EXISTING);
        if (!SHA.equals(hexSha256(exe))) throw new IOException("Test EXE integrity mismatch after staging");
    }

    private static ProcessBuilder processBuilder(java.util.List<String> argv, WineExecutionPlan plan) {
        ProcessBuilder pb = new ProcessBuilder(argv);
        pb.directory(plan.workingDirectory.toFile());
        Map<String, String> dst = pb.environment();
        dst.putAll(plan.environment);
        return pb;
    }

    public static String run(Context ctx) {
        StringBuilder result = new StringBuilder("RM11 v2.5.5 - WineServer + Wine client IPC bring-up\n");
        Running server = null, wine = null;
        try {
            RuntimeLayout layout = new RuntimeLayout(ctx.getFilesDir().toPath(),
                    new File(ctx.getApplicationInfo().nativeLibraryDir).toPath());
            Path exe = layout.appFiles.resolve(NAME);
            ensureVerifiedSmoke(ctx, exe);
            WineExecutionPlan plan = WineExecutionPlan.forBundledSmokeExe(layout, exe);
            result.append("WINEPREFIX: ").append(plan.environment.get("WINEPREFIX")).append("\n")
                  .append("WINESERVER: APK-native signed library\n")
                  .append("Wine/FEX path: ImageFs provisioned\n")
                  .append("Smoke EXE SHA256: VERIFIED\n")
                  .append("XDG_DATA_DIRS: ").append(plan.environment.get("XDG_DATA_DIRS")).append("\n")
                  .append("Native child re-exec shim: NOT INTEGRATED (diagnostic only)\n")
                  .append("Starting native wineserver with committed prefix...\n");
            server = new Running(processBuilder(plan.serverCommand, plan), "rm11-55-wineserver");
            result.append("Starting verified Wine client immediately for IPC handshake...\n");
            wine = new Running(processBuilder(plan.wineCommand, plan), "rm11-55-wine");
            boolean completed = wine.process.waitFor(40, TimeUnit.SECONDS);
            if (!completed) {
                wine.stopAndDrain();
                return result.append("RESULT: WINE_TIMEOUT\nWINE LOG:\n")
                        .append(wine.capture.text()).append("\nSERVER LOG:\n")
                        .append(server.capture.text()).toString();
            }
            wine.reader.join(1700);
            int exit = wine.process.exitValue();
            String wineLog = wine.capture.text();
            boolean marker = wineLog.contains(MARKER);
            result.append("Wine exit: ").append(exit)
                  .append("\nWin32 stdout marker: ").append(marker ? "YES" : "NO")
                  .append("\nRESULT: ").append(exit == 42 && marker ? "PASS_WIN32_EXECUTION" : "NOT_PASSED")
                  .append("\nWINE LOG:\n").append(wineLog)
                  .append("\nSERVER LOG:\n").append(server.capture.text())
                  .append("\nServer at client exit: " + (server.process.isAlive() ? "ALIVE" : ("EXIT=" + server.process.exitValue())) + "\nFEX/child re-exec, display, games: NOT VERIFIED unless separately demonstrated.");
            return result.toString();
        } catch (Exception ex) {
            result.append("RESULT: PRECHECK_OR_PROCESS_ERROR\n")
                  .append(ex.getClass().getSimpleName()).append(": ").append(ex.getMessage());
            if (wine != null) result.append("\nWINE LOG:\n").append(wine.capture.text());
            if (server != null) result.append("\nSERVER LOG:\n").append(server.capture.text());
            return result.toString();
        } finally {
            if (wine != null) wine.stopAndDrain();
            if (server != null) server.stopAndDrain();
        }
    }
}
