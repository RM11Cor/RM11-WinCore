package com.rm11.autocore.runtime;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Safe, one-time materialization of the existing pinned Wine runtime into ImageFs.
 * No native executables are launched. APK-native entries remain the only execve targets.
 * Pre-built prefix ZIP is derived from the Wine-11 prefixPack.txz in the signed runtime.
 */
public final class ImageFsProvisioner {
    private static final long MAX_PREFIX_BYTES = 2L * 1024 * 1024 * 1024;
    private static final int MAX_PREFIX_FILES = 45000;
    private ImageFsProvisioner() {}

    public static String provision(RuntimeLayout layout, InputStream prefixZip) throws IOException {
        if (prefixZip == null) throw new IOException("Prepared prefix stream is absent");
        Path root = layout.appFiles.resolve("runtime-v2417");
        requireFile(root.resolve(".ready"));
        String version = new String(Files.readAllBytes(root.resolve(".ready")), StandardCharsets.UTF_8).trim();
        if (!"v2.4.24".equals(version)) throw new IOException("Unrecognized Wine bundle marker: " + version);
        for (String s : new String[]{"bin/wine", "bin/wineserver", "lib/wine/aarch64-unix/ntdll.so",
                "lib/wine/aarch64-windows/libarm64ecfex.dll", "lib/wine/aarch64-windows/libwow64fex.dll",
                "share/wine/nls/l_intl.nls", "prefixPack.txz"}) requireFile(root.resolve(s));
        NativeProcessPolicy.requireApkNativeEntrypoint(layout, layout.nativeWineLauncher);
        NativeProcessPolicy.requireApkNativeEntrypoint(layout, layout.nativeWineServer);

        if (AppPrivateStorage.usableBytes(layout.appFiles) < 700L * 1024 * 1024)
            throw new IOException("Insufficient free space (<700 MiB) for safe Wine prefix staging");
        Files.createDirectories(layout.imageFs);
        Files.createDirectories(layout.imageFs.resolve("opt"));
        linkOrValidate(layout.wineRoot, root);
        Files.createDirectories(layout.imageFs.resolve("usr"));
        linkOrValidate(layout.imageFs.resolve("usr/bin"), root.resolve("bin"));
        linkOrValidate(layout.imageFs.resolve("usr/lib"), root.resolve("lib"));
        linkOrValidate(layout.imageFs.resolve("usr/share"), root.resolve("share"));
        Files.createDirectories(layout.imageFs.resolve("usr/tmp"));
        Files.createDirectories(layout.imageFs.resolve("home/xuser"));

        Path dst = layout.winePrefix;
        if (Files.exists(dst, LinkOption.NOFOLLOW_LINKS)) {
            if (Files.isRegularFile(layout.winePrefixMarker(), LinkOption.NOFOLLOW_LINKS)) {
                return "ImageFs links valid; existing committed prefix preserved. Layout-only structural assessment: "
                        + RuntimeAssessment.inspect(layout).state();
            }
            throw new IOException("Existing Wine prefix is uncommitted: will NOT overwrite user data: " + dst);
        }

        Path stage = dst.resolveSibling(".wine.rm11-staging");
        if (Files.exists(stage, LinkOption.NOFOLLOW_LINKS))
            throw new IOException("Unfinished staging area retained for safety: " + stage);
        Files.createDirectory(stage);
        long expanded = 0L;
        int files = 0;
        String symlinks = null;
        try (ZipInputStream zin = new ZipInputStream(prefixZip)) {
            ZipEntry entry;
            byte[] buffer = new byte[65536];
            while ((entry = zin.getNextEntry()) != null) {
                if (++files > MAX_PREFIX_FILES) throw new IOException("Prefix file-count budget exceeded");
                String name = entry.getName();
                if (!isSafeRelative(name) || name.equals(".rm11-prefix-complete"))
                    throw new IOException("Unsafe prefix entry: " + name);
                Path out = stage.resolve(name).normalize();
                if (!out.startsWith(stage) || out.equals(stage)) throw new IOException("Prefix escape attempt: " + name);
                if (name.equals("_rm11_symlinks.tsv")) {
                    java.io.ByteArrayOutputStream manifest = new java.io.ByteArrayOutputStream();
                    int n;
                    while ((n = zin.read(buffer)) != -1) {
                        expanded += n;
                        if (manifest.size() + n > 4 * 1024 * 1024 || expanded > MAX_PREFIX_BYTES)
                            throw new IOException("Oversized prefix symlink manifest");
                        manifest.write(buffer, 0, n);
                    }
                    symlinks = manifest.toString("UTF-8");
                } else if (entry.isDirectory()) {
                    Files.createDirectories(out);
                } else {
                    Files.createDirectories(out.getParent());
                    try (java.io.OutputStream file = Files.newOutputStream(out, StandardOpenOption.CREATE_NEW)) {
                        int n;
                        while ((n = zin.read(buffer)) != -1) {
                            expanded += n;
                            if (expanded > MAX_PREFIX_BYTES) throw new IOException("Prefix expansion budget exceeded");
                            file.write(buffer, 0, n);
                        }
                    }
                }
                zin.closeEntry();
            }
        }
        if (symlinks == null) throw new IOException("The pinned prefix symlink manifest is missing");
        installSymlinks(stage, symlinks);
        for (String path : new String[]{"system.reg", "user.reg"}) requireFile(stage.resolve(path));
        for (String path : new String[]{"drive_c/windows/system32", "dosdevices"})
            if (!Files.isDirectory(stage.resolve(path))) throw new IOException("Uninitialized prefix directory: " + path);
        Files.write(stage.resolve(".rm11-prefix-complete"), "RM11-prefixed-Wine11-v2.5.1\n".getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE_NEW);
        try { Files.move(stage, dst, StandardCopyOption.ATOMIC_MOVE); }
        catch (AtomicMoveNotSupportedException ex) { throw new IOException("Atomic Wine prefix publication is unavailable", ex); }
        return "ImageFs prepared from existing v2.4.24 runtime without duplicating its Wine tree. Prefix: "
                + files + " entries, " + expanded + " bytes. Structural assessment: "
                + RuntimeAssessment.inspect(layout).state() + ". Minimal /usr aliases only (full Bionic sysroot not installed). "
                + "Win32/IPC/FEX execution: NOT VERIFIED.";
    }

    private static void installSymlinks(Path stage, String manifest) throws IOException {
        Base64.Decoder decoder = Base64.getDecoder();
        List<String> seen = new ArrayList<>();
        for (String line : manifest.split("\\r?\\n")) {
            if (line.isEmpty()) continue;
            String[] parts = line.split("\\t", -1);
            if (parts.length != 2) throw new IOException("Invalid symlink manifest entry");
            String name = new String(decoder.decode(parts[0]), StandardCharsets.UTF_8);
            String target = new String(decoder.decode(parts[1]), StandardCharsets.UTF_8);
            if (!isSafeRelative(name) || target.indexOf('\0') >= 0 || target.contains("\\"))
                throw new IOException("Unsafe prefix symlink: " + name);
            if (seen.contains(name)) throw new IOException("Duplicate prefix symlink: " + name);
            seen.add(name);
            Path path = stage.resolve(name).normalize();
            Path link = Paths.get(target);
            // z: is Wine's intentionally sandboxed drive mapping to host /.
            boolean wineZRoot = "dosdevices/z:".equals(name) && "/".equals(target);
            if (!wineZRoot && (link.isAbsolute() || !path.getParent().resolve(link).normalize().startsWith(stage)))
                throw new IOException("Prefix symlink target escapes the extracted prefix: " + name);
            if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Duplicate prefix path: " + name);
            Files.createDirectories(path.getParent());
            Files.createSymbolicLink(path, link);
        }
    }

    private static void requireFile(Path path) throws IOException {
        if (!Files.isRegularFile(path)) throw new IOException("Required runtime input is absent: " + path);
    }
    private static boolean isSafeRelative(String name) {
        if (name == null || name.isEmpty() || name.startsWith("/") || name.indexOf('\\') >= 0 || name.indexOf('\0') >= 0)
            return false;
        if (java.util.Arrays.asList(name.split("/", -1)).contains("..")) return false;
        Path p = Paths.get(name).normalize();
        return !p.isAbsolute() && !p.startsWith("..") && !p.toString().equals(".");
    }
    private static void linkOrValidate(Path at, Path target) throws IOException {
        if (Files.exists(at, LinkOption.NOFOLLOW_LINKS)) {
            if (!Files.isSymbolicLink(at) || !Files.readSymbolicLink(at).toAbsolutePath().normalize().equals(target.toAbsolutePath().normalize()))
                throw new IOException("Existing ImageFs location preserved; incompatible directory: " + at);
            return;
        }
        Files.createSymbolicLink(at, target.toAbsolutePath().normalize());
    }
}

