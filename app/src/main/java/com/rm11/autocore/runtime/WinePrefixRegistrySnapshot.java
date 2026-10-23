package com.rm11.autocore.runtime;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.charset.StandardCharsets;

/** Preserve registry before enabling Wine's previously disabled wine.inf update.
 * Opt-in embedded GUI path only; never edits any registry file.
 */
public final class WinePrefixRegistrySnapshot {
    private WinePrefixRegistrySnapshot() {}

    public static String backup(RuntimeLayout p) throws IOException {
        Path root = p.winePrefix.toRealPath();
        if (!root.startsWith(p.appFiles.toRealPath())
                || !Files.isRegularFile(p.winePrefixMarker(),LinkOption.NOFOLLOW_LINKS))
            throw new IOException("PREFIX_SNAPSHOT_UNTRUSTED_OR_UNCOMMITTED");
        Path snapshot = root.resolve(".rm11-registry-before-winedatadir-v283");
        Path marker = snapshot.resolve("snapshot-complete.txt");
        if (Files.exists(snapshot, LinkOption.NOFOLLOW_LINKS)) {
            if (Files.isDirectory(snapshot,LinkOption.NOFOLLOW_LINKS)
                    && Files.isRegularFile(marker,LinkOption.NOFOLLOW_LINKS))
                return "RM11_WINEPREFIX_REGISTRY_SNAPSHOT_V283: PREVIOUS_COMPLETE_SNAPSHOT_PRESERVED\n";
            throw new IOException("PREFIX_SNAPSHOT_INCOMPLETE_PRESERVED_NO_OVERWRITE");
        }
        Files.createDirectory(snapshot);
        for (String name : new String[]{"system.reg","user.reg"}) {
            Path src = root.resolve(name);
            if (!Files.isRegularFile(src,LinkOption.NOFOLLOW_LINKS)
                    || Files.size(src)>32L*1024*1024)
                throw new IOException("PREFIX_SNAPSHOT_REGISTRY_INVALID_"+name);
            Files.copy(src,snapshot.resolve(name),StandardCopyOption.COPY_ATTRIBUTES);
        }
        Files.write(marker,
                "RM11 v2.8.3 registry backup, before first corrected WINEDATADIR run\n"
                        .getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        return "RM11_WINEPREFIX_REGISTRY_SNAPSHOT_V283: BACKED_UP_SYSTEM_AND_USER_REGISTRY\n";
    }
}
