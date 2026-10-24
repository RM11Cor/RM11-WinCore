package com.rm11.autocore.runtime;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/** Read-only desktop diagnostics: never creates paths, follows untrusted drive targets
 * for mutations, or changes the existing Wine prefix. */
public final class WineDesktopPathAudit {
    private WineDesktopPathAudit() {}

    private static void entry(StringBuilder out,Path path,String label) {
        out.append("RM11_V310_PATH ").append(label).append(": ");
        try {
            if (!Files.exists(path,LinkOption.NOFOLLOW_LINKS)) {
                out.append("MISSING");
            } else if (Files.isSymbolicLink(path)) {
                Path target=Files.readSymbolicLink(path);
                out.append("SYMLINK target=").append(target)
                   .append(" resolved=").append(Files.exists(path)?"YES":"NO");
            } else if (Files.isDirectory(path,LinkOption.NOFOLLOW_LINKS)) {
                out.append("DIRECTORY readable=").append(Files.isReadable(path)?"YES":"NO");
            } else {
                out.append("FILE readable=").append(Files.isReadable(path)?"YES":"NO");
            }
        } catch (Exception e) {
            out.append("ERROR_").append(e.getClass().getSimpleName());
        }
        out.append('\\n');
    }

    public static String inspect(RuntimeLayout layout) {
        StringBuilder out=new StringBuilder("RM11_V310_READ_ONLY_DESKTOP_PATH_AUDIT\\n");
        Path prefix=layout.winePrefix;
        entry(out,prefix,"PREFIX");
        entry(out,prefix.resolve("drive_c"),"DRIVE_C");
        entry(out,prefix.resolve("drive_c/windows/Fonts"),"C_FONTS");
        entry(out,prefix.resolve("drive_c/windows/Fonts/tahoma.ttf"),"TAHOMA");
        entry(out,prefix.resolve("drive_c/windows/Fonts/tahomabd.ttf"),"TAHOMA_BOLD");
        entry(out,layout.wineShare.resolve("wine/fonts/tahoma.ttf"),"WINE_SHARE_TAHOMA");
        entry(out,prefix.resolve("dosdevices/c:"),"DOSDEVICE_C");
        entry(out,prefix.resolve("dosdevices/z:"),"DOSDEVICE_Z");
        entry(out,prefix.resolve("dosdevices/d:"),"DOSDEVICE_D");
        entry(out,prefix.resolve("dosdevices/e:"),"DOSDEVICE_E");
        out.append("RM11_V310_ANDROID_SHARED_STORAGE_NOT_AUTOMATICALLY_MOUNTED\\n");
        return out.toString();
    }
}
