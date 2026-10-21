package com.rm11.autocore.runtime;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Objects;

/** Transactional installer for an ALREADY UNPACKED, TRUSTED Wine prefix tree.
 *  Does not interpret prefixPack.txz; do not assume that .txz is a ZIP.
 *  Never deletes or overwrites an existing user's Wine prefix.
 */
public final class PrefixInstaller {
    private PrefixInstaller() {}

    public static void installPreparedPrefix(Path prepared, RuntimeLayout layout, String identity) throws IOException {
        Objects.requireNonNull(prepared);
        if (identity == null || !identity.matches("[A-Za-z0-9._-]{1,96}"))
            throw new IOException("Invalid prefix identity");
        Path source = prepared.toAbsolutePath().normalize();
        Path target = layout.winePrefix;
        if (!Files.isDirectory(source) || Files.isSymbolicLink(source)) throw new IOException("Prepared prefix missing or symlink");
        // Never assume an existing directory is disposable. Protect saves and registry.
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Existing prefix preserved; use explicit migration");
        if (!Files.isDirectory(source.resolve("drive_c/windows/system32")) ||
            !Files.isRegularFile(source.resolve("system.reg")) ||
            !Files.isRegularFile(source.resolve("user.reg")) ||
            !Files.isDirectory(source.resolve("dosdevices")))
            throw new IOException("Prepared prefix is incomplete");
        Files.createDirectories(target.getParent());
        Path stage = target.resolveSibling(".wine.rm11-staging");
        if (Files.exists(stage, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Staging area already exists; manual review required");
        Files.createDirectory(stage);
        try {
            Files.walkFileTree(source, new SimpleFileVisitor<Path>() {
                @Override public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                    Path rel = source.relativize(dir);
                    if (!rel.toString().isEmpty()) Files.createDirectory(stage.resolve(rel));
                    return FileVisitResult.CONTINUE;
                }
                @Override public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    Path rel = source.relativize(file);
                    Path dst = stage.resolve(rel);
                    if (Files.isSymbolicLink(file)) {
                        Path link = Files.readSymbolicLink(file);
                        // Only keep relative links whose resolved target stays inside the staged prefix.
                        Path resolved = file.getParent().resolve(link).normalize();
                        if (link.isAbsolute() || !resolved.startsWith(source))
                            throw new IOException("Unsafe symlink in prefix: " + rel);
                        Files.createSymbolicLink(dst, link);
                    } else if (attrs.isRegularFile()) {
                        Files.copy(file, dst, StandardCopyOption.COPY_ATTRIBUTES);
                    } else {
                        throw new IOException("Unexpected prefix entry: " + rel);
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
            // Marker is made in staging before atomic publication.
            Files.write(stage.resolve(".rm11-prefix-complete"), identity.getBytes(StandardCharsets.UTF_8),
                        StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            try { Files.move(stage, target, StandardCopyOption.ATOMIC_MOVE); }
            catch (AtomicMoveNotSupportedException ex) {
                // Fail closed; copy+delete would expose half-committed Windows registry state.
                throw new IOException("Atomic prefix publishing unavailable on this filesystem", ex);
            }
        } catch (IOException | RuntimeException err) {
            // Do not automatically remove partial data; keep it for diagnosis.
            throw err;
        }
    }
}
