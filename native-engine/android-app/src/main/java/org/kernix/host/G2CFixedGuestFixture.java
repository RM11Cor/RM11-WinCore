package org.kernix.host;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Read-only Android-side byte verifier for the immutable CI G2-C x86 fixture.
 *
 * Never installs, loads, maps, executes, trusts caller-controlled ELF content,
 * creates rootfs files, or promotes Wine/game support. The caller must provide
 * an already app-private, independently populated rootfs named g2c-fixed-v1.
 */
public final class G2CFixedGuestFixture {
    private G2CFixedGuestFixture() {}

    private static final String[] DIRS = {
        "", "bin", "lib", "lib/x86_64-linux-gnu", "lib64"
    };
    private static final String[] PATHS = {
        "bin/kernix-dynamic-app",
        "lib/x86_64-linux-gnu/libc.so.6",
        "lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        "lib64/ld-linux-x86-64.so.2",
        "manifest.json",
        "PROVENANCE.json"
    };
    private static final long[] SIZES = {
        13344L, 2118168L, 235408L, 235408L, 1276L, 361L
    };
    private static final String[] SHA256 = {
        "e54a92cf77d1453c86b70accfd949b9e4521ddd5d629ba09c0dcac07a1397b4a",
        "7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906",
        "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae",
        "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae",
        "79d744c5a05a38fa0c6978b5af41fe88f32b5be259285478498c153bd5afa3d0",
        "f94b975a06577b39cc18ddff8f02dc33fcddf932982d3ed02148ab731340a501"
    };

    private static String digest(Path file) throws IOException {
        final MessageDigest hash;
        try {
            hash = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException err) {
            throw new IOException("Required SHA-256 unavailable", err);
        }
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buffer = new byte[8192];
            int n;
            while ((n = in.read(buffer)) != -1) hash.update(buffer, 0, n);
        }
        StringBuilder hex = new StringBuilder(64);
        for (byte b : hash.digest()) {
            int v = b & 0xff;
            hex.append(Character.forDigit(v >>> 4, 16));
            hex.append(Character.forDigit(v & 15, 16));
        }
        return hex.toString();
    }

    /**
     * Entry for the Android host: accepts only the exact app-owned runtime-v1
     * location. The legacy attest(File) remains a pure byte validator for CI.
     * This is a preflight, not a race-free file-descriptor handoff to FEX;
     * future native guest execution must independently pin/revalidate its FDs.
     */
    public static String attestAppPrivate(File appFilesDir) throws IOException {
        if (appFilesDir == null) throw new IOException("App files root unavailable");
        Path base = appFilesDir.toPath().toAbsolutePath().normalize();
        if (Files.isSymbolicLink(base) ||
                !Files.isDirectory(base, LinkOption.NOFOLLOW_LINKS))
            throw new IOException("Invalid application-private files root");

        Path current = base;
        for (String name : new String[]{"kernix", "runtime-v1", "guest-rootfs", "g2c-fixed-v1"}) {
            current = current.resolve(name);
            if (Files.isSymbolicLink(current) ||
                    !Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS))
                throw new IOException("Redirected or missing app-private G2-C folder");
        }
        if (!current.toRealPath().startsWith(base.toRealPath()) ||
                !current.toRealPath().equals(base.toRealPath().resolve(
                    "kernix/runtime-v1/guest-rootfs/g2c-fixed-v1")))
            throw new IOException("G2-C fixture escaped application-private root");
        return attest(current.toFile());
    }

    public static String attest(File existingAppPrivateRoot) throws IOException {
        if (existingAppPrivateRoot == null) throw new IOException("No rootfs supplied");
        Path root = existingAppPrivateRoot.toPath().toAbsolutePath().normalize();
        if (!root.getFileName().toString().equals("g2c-fixed-v1") ||
                Files.isSymbolicLink(root) ||
                !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS))
            throw new IOException("Untrusted fixed-fixture root");

        Set<String> allowed = new HashSet<>(Arrays.asList(DIRS));
        allowed.addAll(Arrays.asList(PATHS));
        try (Stream<Path> entries = Files.walk(root)) {
            for (Path file : (Iterable<Path>) entries::iterator) {
                String relative = root.relativize(file).toString().replace(File.separatorChar, '/');
                if (!allowed.contains(relative) ||
                        Files.isSymbolicLink(file) ||
                        (!Files.isDirectory(file, LinkOption.NOFOLLOW_LINKS) &&
                         !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)))
                    throw new IOException("Unexpected file or symlink in fixed fixture");
            }
        }
        for (String name : DIRS) {
            Path dir = name.isEmpty() ? root : root.resolve(name);
            if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(dir))
                throw new IOException("Missing or linked rootfs directory");
        }
        for (int i = 0; i < PATHS.length; ++i) {
            Path file = root.resolve(PATHS[i]);
            if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) ||
                    Files.isSymbolicLink(file) || Files.size(file) != SIZES[i] ||
                    !digest(file).equals(SHA256[i]))
                throw new IOException("G2-C immutable fixture checksum/size rejected: " + PATHS[i]);
        }
        return "KERNIX_G2C_ANDROID_FIXED_FIXTURE_BYTES_VERIFIED_NOT_DEVICE_EXECUTED";
    }
}
