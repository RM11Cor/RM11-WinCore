package org.kernix.host;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.stream.Stream;

/**
 * Build/test-only G2-C fixed data handoff. Copies one *previously verified*
 * immutable six-file fixture into the app-private root; NEVER executes any
 * ELF or FEX code, invokes Wine, or installs assets from the network.
 *
 * Not linked to the release APK UI or to guest execution while LGPL/source
 * distribution review and qualified signed native runner gate are CLOSED.
 */
final class G2CPrivateFixtureStager {
    static final String STAGED_PASS =
        "KERNIX_G2C_APP_PRIVATE_FIXED_GUEST_DATA_STAGED_NOT_EXECUTED";
    static final String ALREADY_PASS =
        "KERNIX_G2C_APP_PRIVATE_FIXED_GUEST_ALREADY_VERIFIED_NOT_EXECUTED";
    private static final LinkOption[] NO_LINKS = {LinkOption.NOFOLLOW_LINKS};

    private G2CPrivateFixtureStager() {}

    private static void requireActualDirectory(Path path) throws IOException {
        if (Files.isSymbolicLink(path) || !Files.isDirectory(path, NO_LINKS))
            throw new IOException("G2-C expected app-private directory, never symlink");
    }

    private static Path ensurePrivateParent(File appFilesDir) throws IOException {
        if (appFilesDir == null) throw new IOException("Missing app-private root");
        Path current = appFilesDir.toPath().toAbsolutePath().normalize();
        requireActualDirectory(current);
        // Guard every intermediate folder before creating any missing one.
        for (String name : new String[]{"kernix","runtime-v1","guest-rootfs"}) {
            current = current.resolve(name);
            if (!Files.exists(current, NO_LINKS)) Files.createDirectory(current);
            requireActualDirectory(current);
        }
        return current;
    }

    private static void clearOwnedTemporaryTree(Path temp) throws IOException {
        if (temp == null || !Files.exists(temp, NO_LINKS)) return;
        try (Stream<Path> entries=Files.walk(temp)) {
            Path[] paths=entries.sorted((a,b)->Integer.compare(
                                  b.getNameCount(),a.getNameCount()))
                                  .toArray(Path[]::new);
            for (Path path : paths) Files.deleteIfExists(path);
        }
    }

    /**
     * Intended only for a future signature-attested APK asset source.
     * Caller is responsible for supplying its trusted, already-unpacked
     * source root. Stager performs a full independent fixed SHA verifier both
     * before and AFTER the private copy. No unsafe unzip/extractall.
     */
    static String stageVerifiedOnly(File sourceRoot, File appFilesDir)
            throws IOException {
        if (sourceRoot == null) throw new IOException("Missing pinned source");
        G2CFixedGuestFixture.attest(sourceRoot);
        Path parent=ensurePrivateParent(appFilesDir);
        Path destination=parent.resolve("g2c-fixed-v1");
        if (Files.exists(destination,NO_LINKS)) {
            G2CFixedGuestFixture.attestAppPrivate(appFilesDir);
            return ALREADY_PASS;
        }
        Path temporary=null;
        try {
            temporary=Files.createTempDirectory(parent,".kernix-g2c-private-stage-");
            requireActualDirectory(temporary);
            Path staged=temporary.resolve("g2c-fixed-v1");
            Files.createDirectory(staged);
            for (String relativeDir : G2CFixedGuestFixture.exactDirs()) {
                if (relativeDir.isEmpty()) continue;
                Path created=staged.resolve(relativeDir);
                Files.createDirectories(created);
                requireActualDirectory(created);
            }
            for (String name : G2CFixedGuestFixture.exactPaths()) {
                Path original=sourceRoot.toPath().resolve(name);
                if (Files.isSymbolicLink(original) ||
                    !Files.isRegularFile(original,NO_LINKS))
                    throw new IOException("Unexpected original fixed ELF input");
                Path destinationFile=staged.resolve(name);
                Files.copy(original,destinationFile,LinkOption.NOFOLLOW_LINKS);
                Files.setPosixFilePermissions(destinationFile,EnumSet.of(
                    PosixFilePermission.OWNER_READ,PosixFilePermission.GROUP_READ,
                    PosixFilePermission.OTHERS_READ));
            }
            G2CFixedGuestFixture.attest(staged.toFile());
            // A same-filesystem, non-replacing move. Another installer cannot
            // silently replace an already present rootfs. No fallback copy of
            // partially staged files is allowed after validation.
            if (Files.exists(destination,NO_LINKS))
                throw new FileAlreadyExistsException(destination.toString());
            Files.move(staged,destination);
            G2CFixedGuestFixture.attestAppPrivate(appFilesDir);
            return STAGED_PASS;
        } finally {
            clearOwnedTemporaryTree(temporary);
        }
    }
}
