package com.rm11.autocore.runtime;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/** One-file Wineboot PE alias into existing app-private prefix; never overwrites. */
public final class WinebootAliasBridge {
    private WinebootAliasBridge() {}

    public static String prepare(RuntimeLayout p) {
        try {
            Path trusted=p.appFiles.toRealPath();
            Path source=p.wineDllRoot.resolve("aarch64-windows/wineboot.exe");
            Path real=source.toRealPath();
            if (!real.startsWith(trusted) || !Files.isRegularFile(source) ||
                    Files.size(source) < 10000)
                return "WINEBOOT_SOURCE_INVALID";
            try (InputStream in=Files.newInputStream(source)) {
                if (in.read()!='M' || in.read()!='Z') return "WINEBOOT_SOURCE_NOT_PE";
            }
            Path root=p.winePrefix.toRealPath();
            Path sys32=p.winePrefix.resolve("drive_c/windows/system32");
            if (!root.startsWith(trusted) || !Files.isDirectory(sys32) ||
                    !sys32.toRealPath().startsWith(root))
                return "WINEBOOT_SYSTEM32_UNTRUSTED";
            Path dest=sys32.resolve("wineboot.exe");
            if (Files.exists(dest, LinkOption.NOFOLLOW_LINKS)) {
                if (Files.isSymbolicLink(dest) && dest.toRealPath().equals(real))
                    return "WINEBOOT_ALIAS_ALREADY_PRESENT";
                return "WINEBOOT_EXISTING_FILE_PRESERVED";
            }
            Files.createSymbolicLink(dest, real);
            return Files.isRegularFile(dest) && dest.toRealPath().equals(real)
                    ? "WINEBOOT_ALIAS_CREATED" : "WINEBOOT_ALIAS_UNRESOLVED";
        } catch (Exception e) {
            return "WINEBOOT_ALIAS_UNCHANGED_" + e.getClass().getSimpleName();
        }
    }
}
