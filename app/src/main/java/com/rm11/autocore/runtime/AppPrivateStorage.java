package com.rm11.autocore.runtime;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/** Android-safe app-private storage budget check; requires no new permissions.
 *  Unlike Files.getFileStore(), File.getUsableSpace() avoids querying
 *  FileStore attributes guarded by RuntimePermission("getFileStoreAttributes").
 */
public final class AppPrivateStorage {
    private AppPrivateStorage() {}
    public static long usableBytes(Path privateFilesDir) throws IOException {
        if (!Files.isDirectory(privateFilesDir, LinkOption.NOFOLLOW_LINKS))
            throw new IOException("RM11 app-private files directory does not exist");
        final long free;
        try {
            free = privateFilesDir.toFile().getUsableSpace();
        } catch (SecurityException se) {
            throw new IOException("Cannot inspect free space in RM11 app-private directory", se);
        }
        if (free <= 0)
            throw new IOException("App-private free space unavailable or zero; refusing unsafe prefix staging");
        return free;
    }
}
