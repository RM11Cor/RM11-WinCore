package com.rm11.autocore.runtime;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/**
 * Non-destructive discovery of two pinned Wine PE builtins.
 *
 * Installs only symlink aliases in RM11's app-private System32, never DLL
 * copies, replacements, user paths or game files. Does not claim that Wine
 * child re-execution has been implemented.
 */
public final class WineBuiltinAliasBridge {
    private static final String[] MODULES = {"kernel32.dll", "kernelbase.dll"};
    private WineBuiltinAliasBridge() {}

    public static String prepare(RuntimeLayout p) {
        StringBuilder report = new StringBuilder("RM11_WIN32_BUILTIN_DISCOVERY_V267\n");
        for (String name : MODULES) {
            report.append(name).append(": ").append(prepareOne(p, name)).append('\n');
        }
        return report.toString();
    }

    private static String prepareOne(RuntimeLayout p, String name) {
        try {
            Path trusted = p.appFiles.toRealPath();
            Path source = p.wineDllRoot.resolve("aarch64-windows").resolve(name);
            Path real = source.toRealPath();
            if (!real.startsWith(trusted) ||
                    !Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS) ||
                    Files.size(source) < 4096)
                return "BLOCKED_MISSING_OR_UNTRUSTED_SOURCE";
            try (InputStream in = Files.newInputStream(source)) {
                if (in.read() != 'M' || in.read() != 'Z')
                    return "BLOCKED_INVALID_PE_HEADER";
            }

            Path root = p.winePrefix.toRealPath();
            if (!root.startsWith(trusted) || !Files.isRegularFile(p.winePrefixMarker()))
                return "BLOCKED_UNTRUSTED_PREFIX";
            Path sys32 = p.winePrefix.resolve("drive_c/windows/system32");
            if (!Files.isDirectory(sys32, LinkOption.NOFOLLOW_LINKS) ||
                    !sys32.toRealPath().startsWith(root))
                return "BLOCKED_UNTRUSTED_SYSTEM32";
            Path alias = sys32.resolve(name);
            if (Files.exists(alias, LinkOption.NOFOLLOW_LINKS)) {
                if (Files.isSymbolicLink(alias)) {
                    try {
                        if (alias.toRealPath().equals(real)) return "READY_ALREADY_LINKED";
                    } catch (Exception ignored) { }
                }
                return "BLOCKED_EXISTING_ENTRY_PRESERVED";
            }

            Files.createSymbolicLink(alias, real);
            return Files.isRegularFile(alias) && alias.toRealPath().equals(real)
                    ? "READY_NEW_LINK" : "LINK_CREATED_BUT_UNRESOLVED";
        } catch (Exception e) {
            return "UNMODIFIED_" + e.getClass().getSimpleName();
        }
    }
}
