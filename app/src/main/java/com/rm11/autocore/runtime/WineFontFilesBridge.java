package com.rm11.autocore.runtime;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/**
 * Opt-in embedded Wine display font fallback, not a font installer.
 *
 * On-device diagnostics show an empty C:/windows/Fonts while bundled Wine's
 * trusted share/wine/fonts contains Wine-provided Tahoma regular/bold fonts.
 * Link only these two Wine originals when missing. Never overwrite, copy
 * user files, follow a prefix directory outside the app or modify registry.
 */
public final class WineFontFilesBridge {
    private static final String[] FONT_FILES = {"tahoma.ttf","tahomabd.ttf"};
    private WineFontFilesBridge() {}

    public static String prepare(RuntimeLayout p) {
        StringBuilder summary=new StringBuilder("RM11_V298_WINE_TAHOMA_FONT_ALIASES\n");
        try {
            Path files=p.appFiles.toRealPath();
            Path sourceDir=p.wineShare.resolve("wine/fonts");
            Path fontDir=p.winePrefix.resolve("drive_c/windows/Fonts");
            if (!Files.isDirectory(fontDir, LinkOption.NOFOLLOW_LINKS) ||
                !fontDir.toRealPath().startsWith(files) ||
                !Files.isDirectory(sourceDir, LinkOption.NOFOLLOW_LINKS) ||
                !sourceDir.toRealPath().startsWith(files)) {
                return summary.append("BLOCKED_PREFIX_OR_SOURCE_DIR\n").toString();
            }
            for(String name:FONT_FILES) {
                Path source=sourceDir.resolve(name);
                Path dest=fontDir.resolve(name);
                if (!Files.isRegularFile(source,LinkOption.NOFOLLOW_LINKS) ||
                    Files.size(source)<10000 || !source.toRealPath().startsWith(files)) {
                    summary.append(name).append(": NO_TRUSTED_BUNDLED_FONT\n");
                    continue;
                }
                Path original=source.toRealPath();
                if (Files.exists(dest, LinkOption.NOFOLLOW_LINKS)) {
                    if (Files.isSymbolicLink(dest)) {
                        try {
                            if (dest.toRealPath().equals(original)) {
                                summary.append(name).append(": EXISTING_TRUSTED_LINK\n");
                                continue;
                            }
                        } catch(Exception ignored) { }
                    }
                    summary.append(name).append(": EXISTING_FILE_PRESERVED\n");
                    continue;
                }
                Files.createSymbolicLink(dest, original);
                if (Files.isSymbolicLink(dest) && dest.toRealPath().equals(original))
                    summary.append(name).append(": READY_NEW_TRUSTED_LINK\n");
                else summary.append(name).append(": LINK_UNVERIFIED\n");
            }
        } catch(Exception e) {
            summary.append("NO_MODIFICATION_")
                   .append(e.getClass().getSimpleName()).append('\n');
        }
        return summary.toString();
    }
}
