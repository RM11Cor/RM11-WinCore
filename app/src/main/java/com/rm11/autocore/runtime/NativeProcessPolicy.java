package com.rm11.autocore.runtime;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/** Android API 29+ native-code execution boundary. This is a policy guard,
 *  NOT an exec/re-exec shim or a substitute for a complete Wine process runtime.
 */
public final class NativeProcessPolicy {
    private NativeProcessPolicy() {}
    public static void requireApkNativeEntrypoint(RuntimeLayout layout, Path requested) throws IOException {
        Path path = requested.toAbsolutePath().normalize();
        if (!path.equals(layout.nativeWineLauncher) && !path.equals(layout.nativeWineServer))
            throw new IOException("Execution denied: only signed APK native-library entrypoints are approved: " + path);
        if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
            throw new IOException("Execution denied: native entrypoint is missing or a symlink: " + path);
    }
}
