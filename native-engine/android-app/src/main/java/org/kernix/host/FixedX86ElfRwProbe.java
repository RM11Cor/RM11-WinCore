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
 * Bounded actual upstream FEXCore guest x86-64 execution proof.
 * Fixed APK-shipped ARM64 PIE only; only exact signed-APK embedded ELF64 x86-64 PIE with write(1) and getpid(39). No user EXE files.
 * The isolated process must return a real CPU register value to pass.
 */
public final class FixedX86ElfRwProbe {
    static final String BINARY = "libkernix_fexcore_elf64_rw_exec_probe.so";
    static final String CORE = "libFEXCore.so";
    static final String SUCCESS =
        "KERNIX_ELF_RW_MEMORY_PASS\n" +
        "KERNIX_FEXCORE_ANDROID_ELF64_X86_RW_GUEST_MEMORY_PROOF_V1\n";
    private static final int LIMIT = 2048;

    private FixedX86ElfRwProbe() {}

    static File resolve(File directory, String file) throws IOException {
        if (directory == null || !directory.isDirectory()
                || !(file.equals(BINARY) || file.equals(CORE)))
            throw new IOException("Invalid native library directory or binary name");
        Path parent = directory.toPath().toRealPath();
        Path candidate = parent.resolve(file);
        if (Files.isSymbolicLink(candidate)
                || !Files.isRegularFile(candidate, LinkOption.NOFOLLOW_LINKS)
                || !candidate.toRealPath().getParent().equals(parent))
            throw new IOException("Signed-APK FEXCore guest runner missing or redirected");
        return candidate.toFile().getCanonicalFile();
    }

    static boolean verified(int exitCode, String stdout) {
        return exitCode == 0 && SUCCESS.equals(stdout);
    }

    private static String boundedRead(InputStream stream) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (InputStream input = stream) {
            byte[] bytes = new byte[128];
            int n;
            while ((n = input.read(bytes)) != -1 && output.size() < LIMIT)
                output.write(bytes, 0, Math.min(n, LIMIT - output.size()));
        }
        return output.toString(StandardCharsets.UTF_8.name());
    }

    public static String run(File nativeLibraryDirectory) {
        Process p = null;
        try {
            File core = resolve(nativeLibraryDirectory, CORE);
            File child = resolve(nativeLibraryDirectory, BINARY);
            if (!core.canRead() || !child.canExecute())
                throw new IOException("Signed native libraries cannot be accessed");
            ProcessBuilder pb = new ProcessBuilder(child.getAbsolutePath());
            // Only the application's verified native library directory, not
            // external storage or arbitrary paths. No dynamic code ingestion.
            pb.environment().put("LD_LIBRARY_PATH", nativeLibraryDirectory.getCanonicalPath());
            p = pb.start();
            if (!p.waitFor(12, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return "KERNIX_X86_ELF64_RW_TIMEOUT (12 seconds); execution not proven";
            }
            int result = p.exitValue();
            String out = boundedRead(p.getInputStream());
            String err = boundedRead(p.getErrorStream()).replace('\n',' ');
            if (verified(result, out))
                return "KERNIX_X86_ELF64_RW_EXEC_PASS: genuine FEXCore loaded and executed "
                     + "independently assembled x86-64 ELF64 PIE with W^X read-only/read-write segments, "
                     + "guest REP MOVSB copy from .rodata to .data; write/getpid syscalls and RAX=PID+26.\n"
                     + "Wine, DirectX and Windows games: NOT TESTED.";
            return "KERNIX_X86_ELF64_RW_EXEC_FAIL: exit=" + result
                 + ", stdout=" + out.replace('\n',' ').substring(0,Math.min(100,out.length()))
                 + ", stage=" + err.substring(0,Math.min(240,err.length()));
        } catch (IOException | SecurityException error) {
            return "KERNIX_X86_ELF64_RW_EXEC_FAIL: loader or permission: " + error.getMessage();
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            return "KERNIX_X86_ELF64_RW_EXEC_INTERRUPTED";
        } finally {
            if (p != null) p.destroyForcibly();
        }
    }
}
