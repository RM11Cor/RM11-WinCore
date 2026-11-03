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
import java.util.regex.Pattern;

/** Bounded actual Android/Bionic FEXCore loader preflight, never Wine/PE. */
public final class G2HostBoundaryProbe {
    static final String BINARY = "libkernix_android_g2_host_boundary.so";
    static final String CORE = "libFEXCore.so";
    private static final Pattern EXPECTED = Pattern.compile(
        "\\AKERNIX_G2_BIONIC_HOST_BOUNDARY_V1\n" +
        "ABI=aarch64\nPAGE_BYTES=(4096|16384|65536)\n" +
        "SECCOMP_MODE=(0|1|2|unknown)\n" +
        "NO_NEW_PRIVS=(0|1|unknown)\n" +
        "FEX_CORE_LOAD=1\nFEX_CONFIG_SYMBOL=1\nWINE_PE_EXECUTED=0\n\\z"
    );
    private static final int MAX_OUTPUT = 1536;
    private G2HostBoundaryProbe() {}

    static File resolve(File nativeDir, String name) throws IOException {
        if (nativeDir == null || !nativeDir.isDirectory()
                || !(BINARY.equals(name) || CORE.equals(name)))
            throw new IOException("Invalid native library directory or component");
        Path base = nativeDir.toPath().toRealPath();
        Path path = base.resolve(name);
        if (Files.isSymbolicLink(path) ||
            !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) ||
            !path.toRealPath().getParent().equals(base))
            throw new IOException("Signed G2 ELF library missing or redirected");
        return path.toFile().getCanonicalFile();
    }
    static boolean verified(int code, String stdout) {
        return code == 0 && stdout != null && EXPECTED.matcher(stdout).matches();
    }
    private static String bounded(InputStream stream) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (InputStream input = stream) {
            byte[] buffer = new byte[128];
            int count;
            while ((count = input.read(buffer)) != -1 && bytes.size() < MAX_OUTPUT)
                bytes.write(buffer, 0, Math.min(count, MAX_OUTPUT - bytes.size()));
        }
        return bytes.toString(StandardCharsets.UTF_8.name());
    }
    public static String run(File nativeLibraryDirectory) {
        Process child = null;
        try {
            File runner = resolve(nativeLibraryDirectory, BINARY);
            File core = resolve(nativeLibraryDirectory, CORE);
            if (!runner.canExecute() || !core.canRead())
                throw new IOException("Signed G2 binary/library inaccessible");
            ProcessBuilder pb = new ProcessBuilder(
                runner.getAbsolutePath(), core.getAbsolutePath());
            pb.environment().put("LD_LIBRARY_PATH",
                nativeLibraryDirectory.getCanonicalPath());
            child = pb.start();
            if (!child.waitFor(8, TimeUnit.SECONDS)) {
                child.destroyForcibly();
                return "KERNIX_G2_HOST_BOUNDARY_TIMEOUT (8s): no Wine or PE tested.";
            }
            int code = child.exitValue();
            String out = bounded(child.getInputStream());
            String err = bounded(child.getErrorStream());
            if (verified(code, out)) {
                return "KERNIX_G2_HOST_BOUNDARY_PASS\n" + out +
                    "Bionic/FEX dynamic-load preflight only; " +
                    "Wine, Windows PE, DirectX and games: NOT TESTED.";
            }
            return "KERNIX_G2_HOST_BOUNDARY_FAIL: exit=" + code +
                ", stdout=" + out.replace('\n', ' ').substring(0, Math.min(out.length(), 170)) +
                ", stderr=" + err.replace('\n', ' ').substring(0, Math.min(err.length(), 170));
        } catch (IOException | SecurityException e) {
            return "KERNIX_G2_HOST_BOUNDARY_FAIL: " + e.getMessage();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "KERNIX_G2_HOST_BOUNDARY_INTERRUPTED";
        } finally {
            if (child != null) child.destroyForcibly();
        }
    }
}
