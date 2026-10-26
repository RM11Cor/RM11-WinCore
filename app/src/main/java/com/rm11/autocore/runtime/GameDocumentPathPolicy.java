package com.rm11.autocore.runtime;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Translate ONLY an Android ExternalStorageProvider primary: document ID to
 * a path that Wine can access after the user grants Android all-files access.
 * SAF content URIs from other providers are not POSIX executable paths.
 */
public final class GameDocumentPathPolicy {
    private GameDocumentPathPolicy() {}

    public static Path resolvePrimary(String authority, String documentId,
            String displayedName, Path externalRoot) throws IOException {
        if (!"com.android.externalstorage.documents".equals(authority)
                || documentId == null || !documentId.startsWith("primary:"))
            throw new IOException("Only primary shared-storage files can launch directly");
        String relative = documentId.substring("primary:".length());
        if (relative.isEmpty() || relative.startsWith("/")
                || relative.indexOf('\\') >= 0 || relative.indexOf('\u0000') >= 0
                || relative.indexOf(':') >= 0)
            throw new IOException("Unsafe Android document ID");
        Path root = externalRoot.toAbsolutePath().normalize();
        Path file = root.resolve(relative).normalize();
        if (!file.startsWith(root) || file.equals(root)
                || displayedName == null
                || !file.getFileName().toString().equals(displayedName))
            throw new IOException("Document does not match an authorized phone path");
        return file;
    }
}
