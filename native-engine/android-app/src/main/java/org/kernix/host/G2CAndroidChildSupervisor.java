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
import java.util.regex.Pattern;

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
    static final String CANDIDATE_FLAG =
        "--kernix-g2c-execute-fixed-snapshot-direct-entry-v1";
    static final String CORE = "libFEXCore.so";
    // GATE CLOSED by design: fill only with SHA-256 of independently audited
    // Android/Bionic ELF after signed APK packages the exact bytes.
    static final String QUALIFIED_RUNNER_SHA256 = "";
    static final String PASS_STDOUT =
        "KERNIX_G2C_ANDROID_FEX_DIRECT_PIE_ENTRY_PASS_NOT_GLIBC_V1\n" +
        "GUEST_RAX=0x4b45524e49584732\n";
    static final String MIT_16K_PASS_STDOUT =
        "KERNIX_G2C_ANDROID_FEX_MIT_ONLY_PINNED_DYNAMIC_PIE_EXEC_PASS_V1\n" +
        "GUEST_RAX=0x4b45524e49584732\n";
    static final String G2D_MIT_IMPORT_PASS_STDOUT =
        "KERNIX_G2D_ANDROID_FEX_MIT_PINNED_PLT_CROSS_DSO_CALL_RETURN_PASS_V1\n" +
        "GUEST_RAX=0x4b45524e49584731\n";
    static final String G2E_DATA_ONLY_PASS_STDOUT =
        "KERNIX_G2E_ANDROID_PINNED_GLIBC_SNAPSHOT_CLOSURE_DATA_ONLY_PASS_V1\n";
    static final String G2E_DATA_ONLY_PASS_STDERR =
        "GUEST_EXECUTED=0\nDYNAMIC_LINKER_EXECUTED=0\nFEX_EXECUTED=0\nWINE_EXECUTED=0\n";
    static final String DATA_ONLY_PASS_STDOUT =
        "KERNIX_G2C_NATIVE_CHILD_GUEST_BYTES_SHA256_PTLOAD_AUXV_DATA_ONLY_PASS\n";
    static final String DATA_ONLY_PASS_STDERR =
        "KERNIX_G2C_NATIVE_CHILD_NO_FEX_NO_GUEST_EXECUTION_NOT_ANDROID_DEVICE_PROOF\n";
    static final Pattern PAGE_ONLY_MARKER = Pattern.compile(
        "\\AKERNIX_G2C_ANDROID_PAGE_PREFLIGHT_V1\\n" +
        "ABI=(aarch64|linux-host-ci)\\nHOST_PAGE_BYTES=(4096|16384)\\n" +
        "PROT_NONE_RESERVATION=1\\nPROT_READ_TRANSITION=1\\n" +
        "GUEST_EXECUTED=0\\nFEX_EXECUTED=0\\nWINE_EXECUTED=0\\n\\z");
    static final String GATE_CLOSED =
        "KERNIX_G2C_ANDROID_EXECUTION_GATE_CLOSED: verified Android runner, " +
        "native FD-pinned fixture and device qualification not yet available.";
    private static final int TIMEOUT_SECONDS = 8;
    private static final int OUTPUT_LIMIT = 2048;

    private G2CAndroidChildSupervisor() {}

    static boolean approved() {
        return QUALIFIED_RUNNER_SHA256.matches("[0-9a-f]{64}");
    }

    private static boolean verifiedExpected(int exit, boolean timedOut,
                                             String stdout, String stderr,
                                             String expected) {
        return !timedOut && exit == 0 && expected.equals(stdout) &&
               stderr != null && !stderr.contains("KERNIX_G2C_UNEXPECTED_GUEST_SYSCALL") &&
               !stderr.contains("KERNIX_G2C_FATAL");
    }
    static boolean verified(int exit, boolean timedOut, String stdout, String stderr) {
        return verifiedExpected(exit,timedOut,stdout,stderr,PASS_STDOUT);
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

    // Opt-in future original FEX MIT-only child. Exactly two output lines
    // are accepted, and the same eight-second watchdog applies. No UI
    // or runtime is enabled by merely adding this output classifier.
    static String superviseMit16k(Process child) throws InterruptedException {
        return superviseExpected(child,MIT_16K_PASS_STDOUT,null,
                "KERNIX_G2C_ANDROID_MIT16K_FEX_CHILD_VERIFIED_EXACT_RAX");
    }

    // Signed v0.23 only. This is NOT G2-C's direct x86 _start proof.
    // It requires a genuine x86 PLT CALL into a different SHA-pinned
    // guest ELF shared library, RET, exact guest RAX and child exit 0.
    // Parent enforces the same 8-second watchdog and bounded stdio.
    static String superviseG2DMitImport(Process child) throws InterruptedException {
        return superviseExpected(child,G2D_MIT_IMPORT_PASS_STDOUT,null,
                "KERNIX_G2D_ANDROID_FEX_EXTERNAL_DSO_CALL_RET_VERIFIED_EXACT_RAX");
    }

    // G2-E/B: signed version 25 only. This proves bounded original x86
    // ELF+glibc data integrity on Android/Bionic. No FEX guest execution.
    static String superviseG2EDataOnly(Process child) throws InterruptedException {
        return superviseExpected(child,G2E_DATA_ONLY_PASS_STDOUT,
                G2E_DATA_ONLY_PASS_STDERR,
                "KERNIX_G2E_ANDROID_SIGNED_GLIBC_DATA_ONLY_VERIFIED_NO_FEX");
    }

    // CI-only contract for a real separate data-preflight child. It can never
    // produce a FEX execution pass because stdout AND stderr are exact and
    // different from the original guest RAX marker. Not exposed in the UI.
    static String superviseDataOnly(Process child) throws InterruptedException {
        return superviseExpected(child, DATA_ONLY_PASS_STDOUT,
                DATA_ONLY_PASS_STDERR,
                "KERNIX_G2C_ANDROID_CHILD_DATA_ONLY_WATCHDOG_PASS_NOT_FEX");
    }

    static String supervisePageOnly(Process child) throws InterruptedException {
        return superviseExpected(child, null, "",
                "KERNIX_G2C_ANDROID_PAGE_CHILD_8S_PASS_NO_FEX");
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
                ? verifiedExpected(code, false, stdout, stderr, expectedOut)
                : code == 0 && expectedErr.equals(stderr) &&
                    (expectedOut == null ? PAGE_ONLY_MARKER.matcher(stdout).matches()
                                         : expectedOut.equals(stdout));
            if (accepted && expectedOut == null)
                return successMarker + "\n" + stdout;
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
            // The candidate takes an exact fixed flag and the application
            // FILES directory, not the guest rootfs. Native code independently
            // opens SHA-pinned guest files under that directory before FEX.
            ProcessBuilder pb = new ProcessBuilder(
                    runner.getAbsolutePath(), CANDIDATE_FLAG,
                    appPrivateFilesDir.getCanonicalPath());
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
