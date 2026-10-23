package com.rm11.autocore.runtime;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Wine ARM64EC built-in module resolution bridge for one pinned emulator DLL.
 *
 * The Wine runtime PE module stays in app-private ImageFs. The one alias in the
 * existing Windows prefix is a symlink, never a copied or overwritten DLL.
 * Creation is restricted to RM11's own prefix; unrelated paths, games and
 * pre-existing user files remain unchanged.
 */
public final class WineFexAliasBridge {
    private static final String MODULE = "libarm64ecfex.dll";
    private WineFexAliasBridge() {}

    public static String prepare(RuntimeLayout layout) {
        try {
            final Path appRoot = layout.appFiles.toRealPath();
            final Path original = layout.wineDllRoot.resolve("aarch64-windows").resolve(MODULE);
            final Path originalReal = original.toRealPath();
            if (!originalReal.startsWith(appRoot))
                return "BLOCKED_UNTRUSTED_MODULE_LOCATION";
            if (!Files.isRegularFile(original, LinkOption.NOFOLLOW_LINKS) ||
                    Files.size(original) <= 4096)
                return "BLOCKED_MODULE_MISSING_OR_TOO_SMALL";
            try (InputStream in = Files.newInputStream(original)) {
                if (in.read() != 'M' || in.read() != 'Z')
                    return "BLOCKED_INVALID_PE_HEADER";
            }

            final Path prefixRoot = layout.winePrefix.toRealPath();
            if (!prefixRoot.startsWith(appRoot))
                return "BLOCKED_PREFIX_OUTSIDE_APP";
            final Path system32 = layout.winePrefix.resolve("drive_c/windows/system32");
            if (!Files.isDirectory(system32, LinkOption.NOFOLLOW_LINKS) ||
                    !system32.toRealPath().startsWith(prefixRoot))
                return "BLOCKED_UNTRUSTED_SYSTEM32";
            final Path alias = system32.resolve(MODULE);

            // Never modify any pre-existing file (even an unexpected symlink).
            if (Files.exists(alias, LinkOption.NOFOLLOW_LINKS)) {
                if (Files.isSymbolicLink(alias) && alias.toRealPath().equals(originalReal))
                    return "READY_ALREADY_LINKED";
                return "BLOCKED_EXISTING_SYSTEM32_ENTRY";
            }
            Files.createSymbolicLink(alias, originalReal);
            if (Files.isRegularFile(alias) && alias.toRealPath().equals(originalReal))
                return "READY_NEW_LINK";
            return "LINK_CREATED_BUT_NOT_READABLE";
        } catch (Exception e) {
            // Diagnostic status only; no destructive fallback or silent file copies.
            return "FAILED_" + e.getClass().getSimpleName();
        }
    }

    public static String status(RuntimeLayout layout) {
        final Path original = layout.wineDllRoot.resolve("aarch64-windows").resolve(MODULE);
        final Path alias = layout.winePrefix.resolve("drive_c/windows/system32").resolve(MODULE);
        StringBuilder text = new StringBuilder();
        text.append("RM11_ARM64EC_FEX_MODULE_CHECK\n");
        text.append("Wine PE module: ").append(fileStatus(original)).append('\n');
        text.append("Windows System32 alias: ").append(fileStatus(alias)).append('\n');
        try {
            if (Files.isSymbolicLink(alias))
                text.append("Alias resolves to bundled Wine module: ")
                    .append(alias.toRealPath().equals(original.toRealPath()))
                    .append('\n');
        } catch (Exception e) {
            text.append("Alias resolution: ").append(e.getClass().getSimpleName()).append('\n');
        }
        return text.toString();
    }

    private static String fileStatus(Path file) {
        try {
            return (Files.isRegularFile(file) ? "READABLE" : "NOT_REGULAR")
                    + " symlink=" + Files.isSymbolicLink(file)
                    + " size=" + (Files.isRegularFile(file) ? Files.size(file) : 0);
        } catch (Exception e) {
            return "UNAVAILABLE_" + e.getClass().getSimpleName();
        }
    }
}
