package org.kernix.host;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

/**
 * Fixed, zero-argument Bionic PIE exec proof, NOT an arbitrary EXE launcher.
 * Runs only an executable shipped as a signed APK native library file.
 * No root, shell commands, Linux glibc payloads or writable-data execve.
 */
public final class NativeProcessProbe {
    static final String FILE_NAME = "libkernix_android_exec_probe.so";
    static final String EXPECTED =
        "KERNIX_ANDROID_BIONIC_PIE_PROCESS_PROOF_V1 arch=aarch64";
    private static final int MAX_OUTPUT = 2048;
    private NativeProcessProbe() {}

    static File resolve(File libraryDirectory) throws IOException {
        if (libraryDirectory == null || !libraryDirectory.isDirectory())
            throw new IOException("Native APK library directory missing");
        Path base = libraryDirectory.toPath().toRealPath();
        Path candidate = base.resolve(FILE_NAME);
        if (Files.isSymbolicLink(candidate) ||
            !Files.isRegularFile(candidate, LinkOption.NOFOLLOW_LINKS))
            throw new IOException("APK native executable missing or redirected");
        File proof = candidate.toFile().getCanonicalFile();
        if (!proof.getParentFile().equals(base.toFile()) || !proof.canExecute())
            throw new IOException("APK native executable not accessible");
        return proof;
    }

    static boolean verified(int exit, String stdout) {
        // Exit 0 AND exact one-line marker are required; stderr / partial
        // phrases / shell output do not count as Android native execution.
        return exit == 0 && (EXPECTED + "\n").equals(stdout);
    }

    public static String run(File nativeLibraryDirectory) {
        final File binary;
        try {
            binary = resolve(nativeLibraryDirectory);
        } catch (IOException | SecurityException error) {
            return "ANDROID_NATIVE_PROCESS_FAIL: " + error.getMessage();
        }
        Process process = null;
        try {
            process = new ProcessBuilder(binary.getAbsolutePath())
                    .redirectErrorStream(true).start();
            if (!process.waitFor(5, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return "ANDROID_NATIVE_PROCESS_TIMEOUT (5 seconds); no Wine/FEX tested";
            }
            final int code = process.exitValue();
            ByteArrayOutputStream limited = new ByteArrayOutputStream();
            try (InputStream data = process.getInputStream()) {
                byte[] buffer = new byte[256];
                int n;
                while ((n = data.read(buffer)) != -1 && limited.size() < MAX_OUTPUT) {
                    int allowed = Math.min(n, MAX_OUTPUT - limited.size());
                    limited.write(buffer, 0, allowed);
                }
            }
            String output = limited.toString(StandardCharsets.UTF_8.name());
            if (verified(code, output)) {
                return "ANDROID_NATIVE_PROCESS_PASS: real APK-packaged ARM64 "
                        + "Bionic PIE exited 0 with its own marker.\n"
                        + "FEX/Wine and Windows games: NOT TESTED.";
            }
            return "ANDROID_NATIVE_PROCESS_FAIL: exit=" + code + " stdout="
                    + output.replace('\n', ' ').substring(0, Math.min(180, output.length()));
        } catch (IOException error) {
            return "ANDROID_NATIVE_PROCESS_FAIL: execve/loader denied: "
                    + error.getMessage();
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            return "ANDROID_NATIVE_PROCESS_INTERRUPTED";
        } catch (SecurityException error) {
            return "ANDROID_NATIVE_PROCESS_FAIL: security policy denied execution";
        } finally {
            if (process != null) process.destroyForcibly();
        }
    }
}
