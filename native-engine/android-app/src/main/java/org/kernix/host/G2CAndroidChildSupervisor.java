package org.kernix.host;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * G2-C Android child-supervision contract, deliberately NOT enabled in UI.
 *
 * An Android/Bionic AArch64 FEX guest runner is NOT yet source-qualified or
 * distributed. Its expected exact SHA-256 must be populated by a separate
 * successful NDK + signed-APK gate before this class can spawn it.
 *
 * This host can only launch a fixed signed-APK native library executable,
 * never a guest x86 binary, downloaded EXE, shell or arbitrary user path.
 * The x86 guest image is DATA ONLY and must be independently rechecked by
 * the future native child using owned FDs (Java path preflight is insufficient
 * against TOCTOU mutations). No Linux loader/Wine claim.
 */
public final class G2CAndroidChildSupervisor {
    static final String RUNNER = "libkernix_g2c_android_direct_pie_probe.so";
    static final String CORE = "libFEXCore.so";
    // GATE CLOSED by design: fill only with SHA-256 of independently audited
    // Android/Bionic ELF after signed APK packages the exact bytes.
    static final String QUALIFIED_RUNNER_SHA256 = "";
    static final String PASS_STDOUT =
        "KERNIX_G2C_ANDROID_FEX_DIRECT_PIE_ENTRY_PASS_NOT_GLIBC_V1\n" +
        "GUEST_RAX=0x4b45524e49584732\n";
    static final String DATA_ONLY_PASS_STDOUT =
        "KERNIX_G2C_NATIVE_CHILD_GUEST_BYTES_SHA256_PTLOAD_AUXV_DATA_ONLY_PASS\n";
    static final String DATA_ONLY_PASS_STDERR =
        "KERNIX_G2C_NATIVE_CHILD_NO_FEX_NO_GUEST_EXECUTION_NOT_ANDROID_DEVICE_PROOF\n";
    static final String GATE_CLOSED =
        "KERNIX_G2C_ANDROID_EXECUTION_GATE_CLOSED: verified Android runner, " +
        "native FD-pinned fixture and device qualification not yet available.";
    private static final int TIMEOUT_SECONDS = 8;
    private static final int OUTPUT_LIMIT = 2048;

    private G2CAndroidChildSupervisor() {}

    static boolean approved() {
        return QUALIFIED_RUNNER_SHA256.matches("[0-9a-f]{64}");
    }

    static boolean verified(int exit, boolean timedOut, String stdout, String stderr) {
        return !timedOut && exit == 0 && PASS_STDOUT.equals(stdout) &&
               stderr != null && !stderr.contains("KERNIX_G2C_UNEXPECTED_GUEST_SYSCALL") &&
               !stderr.contains("KERNIX_G2C_FATAL");
    }

    static File exactNative(File apkNativeDir, String fileName) throws IOException {
        if (!(RUNNER.equals(fileName) || CORE.equals(fileName)) || apkNativeDir == null)
            throw new IOException("Not an allowlisted signed native component");
        Path dir = apkNativeDir.toPath().toRealPath();
        Path path = dir.resolve(fileName);
        if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS) ||
            Files.isSymbolicLink(path) ||
            !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) ||
            !path.toRealPath().getParent().equals(dir))
            throw new IOException("Native APK component missing or redirected");
        return path.toFile().getCanonicalFile();
    }

    private static String sha256(Path file) throws IOException {
        final MessageDigest hash;
        try {
            hash = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException error) {
            throw new IOException("SHA-256 unavailable", error);
        }
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buffer = new byte[8192];
            int n;
            while ((n = in.read(buffer)) != -1) hash.update(buffer, 0, n);
        }
        StringBuilder out = new StringBuilder(64);
        for (byte b : hash.digest()) {
            out.append(Character.forDigit((b & 0xff) >>> 4, 16));
            out.append(Character.forDigit(b & 15, 16));
        }
        return out.toString();
    }

    private static String readBounded(InputStream stream) throws IOException {
        try (InputStream in = stream) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[256];
            int n;
            while ((n = in.read(buffer)) != -1) {
                if (out.size() + n > OUTPUT_LIMIT)
                    throw new IOException("Child output exceeded 2048-byte cap");
                out.write(buffer, 0, n);
            }
            return out.toString(StandardCharsets.UTF_8.name());
        }
    }

    // Package-private so JVM tests can supervise fake processes without any
    // guest execution or arbitrary host binary invocation.
    static String supervise(Process child) throws InterruptedException {
        return superviseExpected(child, PASS_STDOUT, null,
               "KERNIX_G2C_ANDROID_CHILD_EXACT_MARKER_PASS");
    }

    // CI-only contract for a real separate data-preflight child. It can never
    // produce a FEX execution pass because stdout AND stderr are exact and
    // different from the original guest RAX marker. Not exposed in the UI.
    static String superviseDataOnly(Process child) throws InterruptedException {
        return superviseExpected(child, DATA_ONLY_PASS_STDOUT,
                DATA_ONLY_PASS_STDERR,
                "KERNIX_G2C_ANDROID_CHILD_DATA_ONLY_WATCHDOG_PASS_NOT_FEX");
    }

    private static String superviseExpected(
            Process child, String expectedOut, String expectedErr,
            String successMarker) throws InterruptedException {
        ExecutorService drain = Executors.newFixedThreadPool(2, runnable -> {
            Thread thread = new Thread(runnable, "kernix-g2c-child-output");
            thread.setDaemon(true);
            return thread;
        });
        Future<String> out = drain.submit((Callable<String>) () ->
            readBounded(child.getInputStream()));
        Future<String> err = drain.submit((Callable<String>) () ->
            readBounded(child.getErrorStream()));
        try {
            if (!child.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                child.destroyForcibly();
                child.waitFor(1, TimeUnit.SECONDS);
                return "KERNIX_G2C_ANDROID_CHILD_TIMEOUT_8S_NO_GUEST_PASS";
            }
            int code = child.exitValue();
            String stdout = out.get(1, TimeUnit.SECONDS);
            String stderr = err.get(1, TimeUnit.SECONDS);
            boolean accepted = expectedErr == null
                ? verified(code, false, stdout, stderr)
                : code == 0 && expectedOut.equals(stdout) && expectedErr.equals(stderr);
            return accepted ? successMarker
                : "KERNIX_G2C_ANDROID_CHILD_REJECTED_EXIT_OR_MARKER";
        } catch (ExecutionException | TimeoutException error) {
            child.destroyForcibly();
            return "KERNIX_G2C_ANDROID_CHILD_OUTPUT_OR_PIPE_REJECTED";
        } finally {
            child.destroyForcibly();
            out.cancel(true);
            err.cancel(true);
            drain.shutdownNow();
        }
    }

    public static String run(File appPrivateFilesDir, File apkNativeDir) {
        // This gate is intentionally closed even if someone writes a fake
        // native runner file into app data. Cannot be opened by filesystem
        // content or an existing Linux CI PASS.
        if (!approved()) return GATE_CLOSED;
        Process child = null;
        try {
            G2CFixedGuestFixture.attestAppPrivate(appPrivateFilesDir);
            File runner = exactNative(apkNativeDir, RUNNER);
            File core = exactNative(apkNativeDir, CORE);
            if (!runner.canExecute() || !core.canRead() ||
                !sha256(runner.toPath()).equals(QUALIFIED_RUNNER_SHA256))
                throw new IOException("G2-C signed APK binary identity rejected");
            File root = new File(appPrivateFilesDir,
                    "kernix/runtime-v1/guest-rootfs/g2c-fixed-v1");
            ProcessBuilder pb = new ProcessBuilder(runner.getAbsolutePath(),
                                                  root.getCanonicalPath());
            pb.directory(appPrivateFilesDir);
            pb.environment().clear();
            pb.environment().put("LD_LIBRARY_PATH", apkNativeDir.getCanonicalPath());
            child = pb.start();
            return supervise(child);
        } catch (IOException | SecurityException error) {
            return "KERNIX_G2C_ANDROID_CHILD_BLOCKED: " + error.getClass().getSimpleName();
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            return "KERNIX_G2C_ANDROID_CHILD_INTERRUPTED";
        } finally {
            if (child != null) child.destroyForcibly();
        }
    }
}
