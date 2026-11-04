package org.kernix.host;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/**
 * User-initiated, DATA-ONLY page/PROT_NONE/PROT_READ preflight of one exact
 * Android/Bionic PIE packaged by the signed APK. No guest filesystem,
 * original FEX JIT, memory PROT_EXEC, Wine or game ever enters this probe.
 */
public final class G2CAndroidPageProbe {
    static final String BINARY = "libkernix_g2c_data_only_child.so";

    private G2CAndroidPageProbe() {}

    static File resolve(File nativeLibraryDirectory) throws IOException {
        if (nativeLibraryDirectory == null ||
            !nativeLibraryDirectory.isDirectory())
            throw new IOException("Native APK library directory unavailable");
        Path base = nativeLibraryDirectory.toPath().toRealPath();
        if (Files.isSymbolicLink(base))
            throw new IOException("Native APK directory redirected");
        Path candidate = base.resolve(BINARY);
        if (Files.isSymbolicLink(candidate) ||
            !Files.isRegularFile(candidate, LinkOption.NOFOLLOW_LINKS) ||
            !candidate.toRealPath().getParent().equals(base) ||
            !Files.isExecutable(candidate))
            throw new IOException("Signed G2-C native page child missing or linked");
        return candidate.toFile().getCanonicalFile();
    }

    public static String run(File nativeLibraryDirectory) {
        Process child = null;
        try {
            File binary = resolve(nativeLibraryDirectory);
            ProcessBuilder pb = new ProcessBuilder(
                binary.getAbsolutePath(),"--android-host-page-preflight");
            pb.directory(nativeLibraryDirectory);
            pb.environment().clear();
            // Static-libstdc++ Bionic PIE, no guest files or LD_LIBRARY_PATH.
            child = pb.start();
            String marker = G2CAndroidChildSupervisor.supervisePageOnly(child);
            if (marker.startsWith("KERNIX_G2C_ANDROID_PAGE_CHILD_8S_PASS_NO_FEX\n") &&
                marker.contains("ABI=aarch64\n"))
                return "KERNIX_G2C_ANDROID_DEVICE_PAGE_PREFLIGHT_PASS_NO_FEX\n"
                    + marker + "No x86 guest, dynamic loader, Wine or game executed.";
            // Host-CI ABI is never a valid Android-device pass.
            return "KERNIX_G2C_ANDROID_DEVICE_PAGE_PREFLIGHT_NOT_PASSED: " + marker;
        } catch (IOException | SecurityException error) {
            return "KERNIX_G2C_ANDROID_PAGE_CHILD_BLOCKED: " +
                   error.getClass().getSimpleName() + ": " + error.getMessage();
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            return "KERNIX_G2C_ANDROID_PAGE_CHILD_INTERRUPTED";
        } finally {
            if (child != null) child.destroyForcibly();
        }
    }
}
