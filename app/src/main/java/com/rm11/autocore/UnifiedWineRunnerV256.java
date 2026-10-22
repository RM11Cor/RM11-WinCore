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
public final class UnifiedWineRunnerV256 {
    private static final String NAME = "rm11-win32-smoke-v2420.exe";
    private static final String SHA = "3bbe50165aa735bc54b5e647861cf192ed603468fea89024f563de9be6547fe9";
    private static final String MARKER = "RM11_WIN32_EXE_EXECUTED_OK";
    private UnifiedWineRunnerV256() {}

    /**
     * Bounded output pump. Keeps the first 8 KiB and the LAST 64 KiB, so a
     * verbose Wine trace cannot hide the terminal failure as it did in v2.5.6.
     * This never blocks the child on a full stdout/stderr pipe.
     */
    private static final class Capture implements Runnable {
        private static final int HEAD_BYTES = 8192;
        private static final int TAIL_BYTES = 65536;
        private final Process process;
        private final ByteArrayOutputStream head = new ByteArrayOutputStream();
        private final byte[] tail = new byte[TAIL_BYTES];
        private long total;
        private int tailCount;
        private int tailNext;

        Capture(Process process) { this.process = process; }

        private synchronized void accept(byte[] bytes, int n) {
            int available = Math.max(0, HEAD_BYTES - head.size());
            if (available > 0) head.write(bytes, 0, Math.min(n, available));
            for (int i = 0; i < n; ++i) {
                tail[tailNext] = bytes[i];
                tailNext = (tailNext + 1) % TAIL_BYTES;
                if (tailCount < TAIL_BYTES) ++tailCount;
            }
            total += n;
        }

        public void run() {
            try (InputStream input = process.getInputStream()) {
                byte[] chunk = new byte[4096];
                int n;
                while ((n = input.read(chunk)) != -1) accept(chunk, n);
            } catch (IOException ex) {
                byte[] error = ("\n[read error: " + ex.getClass().getSimpleName() + "]")
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8);
                accept(error, error.length);
            }
        }

        synchronized String text() {
            byte[] last = new byte[tailCount];
            int first = total >= TAIL_BYTES ? tailNext : 0;
            for (int i = 0; i < tailCount; ++i) last[i] = tail[(first + i) % TAIL_BYTES];
            String recent = new String(last, java.nio.charset.StandardCharsets.UTF_8);
            if (total <= TAIL_BYTES) return recent;
            return new String(head.toByteArray(), java.nio.charset.StandardCharsets.UTF_8)
                    + "\n[LOG MIDDLE OMITTED; last 65536 bytes preserved]\n" + recent;
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
        StringBuilder result = new StringBuilder("RM11 v2.5.6 - APK Wine NLS data redirect + IPC\n");
        Running server = null, wine = null;
        try {
            RuntimeLayout layout = new RuntimeLayout(ctx.getFilesDir().toPath(),
                    new File(ctx.getApplicationInfo().nativeLibraryDir).toPath());
            Path exe = layout.appFiles.resolve(NAME);
            ensureVerifiedSmoke(ctx, exe);
            Path nlsFolder = layout.wineShare.resolve("wine/nls");
            for (String name : new String[]{"locale.nls", "l_intl.nls"}) {
                Path candidate = nlsFolder.resolve(name);
                if (!Files.isRegularFile(candidate) || Files.size(candidate) < 1024)
                    throw new IOException("Required NLS data is missing/too small: " + candidate);
            }
            Path redirect = layout.apkNativeLibs.resolve("librm11_wine_data_redirect.so");
            if (!Files.isRegularFile(redirect))
                throw new IOException("Signed APK native NLS redirection library missing: " + redirect);
            WineExecutionPlan plan = WineExecutionPlan.forBundledSmokeExe(layout, exe);
            if (!redirect.toString().equals(plan.environment.get("LD_PRELOAD")))
                throw new IOException("Native NLS preload path mismatch");
            result.append("NLS source: ").append(nlsFolder).append(" (locale.nls + l_intl.nls verified)\n")
                  .append("NLS preload: ").append(redirect).append("\n");
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
            boolean nlsRedirect = wineLog.contains("RM11_NLS_REDIRECT_ACTIVE") || server.capture.text().contains("RM11_NLS_REDIRECT_ACTIVE");
            result.append("Native NLS redirect observed: ").append(nlsRedirect ? "YES" : "NO").append("\n");
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
