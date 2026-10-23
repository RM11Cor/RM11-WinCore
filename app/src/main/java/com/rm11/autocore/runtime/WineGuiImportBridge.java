package com.rm11.autocore.runtime;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/**
 * Win64 GUI import prerequisite, not an X11 server or Android renderer.
 * Non-destructive, fixed allowlist of bundled Wine aarch64-windows PE DLLs.
 * Only a user-initiated GUI EXE pilot calls prepare(). Never replace prefix
 * files, follow external prefix roots or copy native ELF into writable paths.
 */
public final class WineGuiImportBridge {
    private static final String[] MODULES = {"user32.dll", "gdi32.dll", "win32u.dll"};

    private WineGuiImportBridge() { }

    public static String prepare(RuntimeLayout layout) {
        StringBuilder result = new StringBuilder("RM11_GUI_IMPORTS_V272\n");
        for (String module : MODULES) {
            result.append(module).append(": ")
                  .append(prepareOne(layout, module)).append('\n');
        }
        return result.toString();
    }

    private static String prepareOne(RuntimeLayout layout, String module) {
        try {
            Path trusted = layout.appFiles.toRealPath();
            Path imagefsDll = layout.wineDllRoot.resolve("aarch64-windows").resolve(module);
            Path actual = imagefsDll.toRealPath();
            if (!actual.startsWith(trusted)
                    || !Files.isRegularFile(imagefsDll, LinkOption.NOFOLLOW_LINKS)
                    || Files.size(imagefsDll) < 4096)
                return "SOURCE_NOT_BUNDLED";
            try (InputStream input = Files.newInputStream(imagefsDll)) {
                if (input.read() != 'M' || input.read() != 'Z')
                    return "SOURCE_NOT_PE";
            }
            Path prefix = layout.winePrefix.toRealPath();
            Path system32 = layout.winePrefix.resolve("drive_c/windows/system32");
            if (!prefix.startsWith(trusted)
                    || !Files.isRegularFile(layout.winePrefixMarker())
                    || !Files.isDirectory(system32, LinkOption.NOFOLLOW_LINKS)
                    || !system32.toRealPath().startsWith(prefix))
                return "UNTRUSTED_PREFIX";
            Path alias = system32.resolve(module);
            if (Files.exists(alias, LinkOption.NOFOLLOW_LINKS)) {
                if (Files.isSymbolicLink(alias)) {
                    try {
                        if (alias.toRealPath().equals(actual))
                            return "READY_EXISTING_TRUSTED_LINK";
                    } catch (Exception ignored) { }
                }
                return "EXISTING_ENTRY_NOT_REPLACED";
            }
            Files.createSymbolicLink(alias, actual);
            return Files.isRegularFile(alias) && alias.toRealPath().equals(actual)
                    ? "READY_NEW_SYMLINK" : "CREATED_BUT_NOT_READABLE";
        } catch (Exception ex) {
            return "UNMODIFIED_" + ex.getClass().getSimpleName();
        }
    }
}
