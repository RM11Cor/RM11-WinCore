package com.rm11.autocore.runtime;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/**
 * Fixed, minimal Wine PE forwarded-export prerequisite. In v2.7.4 Wine logs:
 *   advapi32.dll -> cryptbase.SystemFunction036
 * even when the static import dependency graph has reached its end.
 *
 * Only the pinned Wine cryptbase.dll bundled under aarch64-windows may be
 * linked inside the app-owned Windows System32. No user DLLs or arbitrary
 * redirect destinations; never replace existing links or files.
 */
public final class WineForwardedExportBridge {
    private static final String MODULE="cryptbase.dll";
    private WineForwardedExportBridge() {}

    public static String prepare(RuntimeLayout p) {
        StringBuilder out=new StringBuilder("RM11_FORWARDED_EXPORT_V275\n");
        out.append("Observed Wine forwarder: advapi32.SystemFunction036 -> cryptbase.SystemFunction036\n");
        try {
            Path trusted=p.appFiles.toRealPath();
            Path dll=p.wineDllRoot.resolve("aarch64-windows").resolve(MODULE);
            Path actual=dll.toRealPath();
            if(!actual.startsWith(trusted)
                    || !Files.isRegularFile(dll,LinkOption.NOFOLLOW_LINKS)
                    || Files.size(dll)<4096)
                return out.append("cryptbase.dll: BUNDLED_SOURCE_INVALID\n").toString();
            try(InputStream input=Files.newInputStream(dll)) {
                if(input.read()!='M'||input.read()!='Z')
                    return out.append("cryptbase.dll: NOT_PE\n").toString();
            }
            Path prefix=p.winePrefix.toRealPath();
            Path system32=p.winePrefix.resolve("drive_c/windows/system32");
            if(!prefix.startsWith(trusted)
                    || !Files.isRegularFile(p.winePrefixMarker(),LinkOption.NOFOLLOW_LINKS)
                    || !Files.isDirectory(system32,LinkOption.NOFOLLOW_LINKS)
                    || !system32.toRealPath().startsWith(prefix))
                return out.append("cryptbase.dll: UNTRUSTED_PREFIX\n").toString();
            Path dest=system32.resolve(MODULE);
            if(Files.exists(dest,LinkOption.NOFOLLOW_LINKS)) {
                if(Files.isSymbolicLink(dest)) {
                    try {
                        if(dest.toRealPath().equals(actual))
                            return out.append("cryptbase.dll: READY_EXISTING_TRUSTED_LINK\n").toString();
                    } catch(Exception ignored) { }
                }
                return out.append("cryptbase.dll: EXISTING_ENTRY_PRESERVED\n").toString();
            }
            Files.createSymbolicLink(dest,actual);
            return out.append(Files.isRegularFile(dest)
                    && dest.toRealPath().equals(actual)
                    ? "cryptbase.dll: READY_NEW_TRUSTED_LINK\n"
                    : "cryptbase.dll: ALIAS_CREATED_BUT_NOT_READABLE\n").toString();
        } catch(Exception error) {
            return out.append("cryptbase.dll: UNCHANGED_")
                    .append(error.getClass().getSimpleName()).append('\n').toString();
        }
    }
}
