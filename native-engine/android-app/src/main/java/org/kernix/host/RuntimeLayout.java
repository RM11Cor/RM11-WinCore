package org.kernix.host;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/**
 * App-private storage boundary for future Android-native FEX/Wine components.
 * Does not run binaries, mount/chroot, mark Linux/glibc artifacts Android-ready,
 * or modify host /usr/lib, /usr/share, /tmp or other apps.
 */
public final class RuntimeLayout {
    private RuntimeLayout() {}

    public static final class Layout {
        public final File root;
        public final File components;
        public final File fexAndroid;
        public final File wineGuest;
        public final File guestRootfs;
        public final File prefixes;
        public final File sessions;

        private Layout(File root) {
            this.root = root;
            components = new File(root, "components");
            fexAndroid = new File(components, "fex-android-arm64");
            wineGuest = new File(components, "wine-linux-x86_64");
            guestRootfs = new File(root, "guest-rootfs");
            prefixes = new File(root, "prefixes");
            sessions = new File(root, "sessions");
        }

        public boolean isGameReady() {
            // A directory tree is never an attestation of a runnable runtime.
            // Only a future verified Android ABI+dependency+execution gate
            // may promote a component and this API must be versioned then.
            return false;
        }

        public String diagnostic() {
            return "KERNIX isolated runtime folders: PREPARED\n"
                + "Private root: " + root.getAbsolutePath() + "\n"
                + "FEX Android AArch64: NOT INSTALLED / NOT VERIFIED\n"
                + "Wine x86_64 guest: NOT INSTALLED / NOT VERIFIED\n"
                + "Wine prefixes: " + prefixes.getAbsolutePath() + "\n"
                + "Guest rootfs: " + guestRootfs.getAbsolutePath() + "\n"
                + "Android Bionic/FEX integration: NOT PROVEN\n"
                + "Windows game execution: NOT READY\n"
                + "No files were copied from Linux CI or other emulators.";
        }
    }

    private static Path createCheckedDirectory(Path base, String child) throws IOException {
        Path current = base;
        for (String name : child.split("/")) {
            if (name.isEmpty() || name.equals(".") || name.equals(".."))
                throw new IOException("Invalid runtime path component");
            current = current.resolve(name);
            if (Files.isSymbolicLink(current))
                throw new IOException("Refusing symlink in runtime layout");
            if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
                if (!Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS))
                    throw new IOException("Runtime path occupied by non-directory");
            } else {
                Files.createDirectory(current);
            }
            // Fail closed on unexpected redirection. Storage belongs to our
            // own app UID; there is no external-storage or cross-app access.
            if (Files.isSymbolicLink(current) ||
                !current.toRealPath().startsWith(base))
                throw new IOException("Runtime path escaped private root");
        }
        return current;
    }

    public static Layout prepare(File appFilesDir) throws IOException {
        if (appFilesDir == null || Files.isSymbolicLink(appFilesDir.toPath())
                || !Files.isDirectory(appFilesDir.toPath(), LinkOption.NOFOLLOW_LINKS))
            throw new IOException("Android private files directory unavailable");
        final Path base = appFilesDir.toPath().toRealPath();
        // Never rely on an Android device's absolute /usr or /tmp paths.
        Path root = createCheckedDirectory(base, "kernix/runtime-v1");
        Layout result = new Layout(root.toFile());
        createCheckedDirectory(base, "kernix/runtime-v1/components/fex-android-arm64");
        createCheckedDirectory(base, "kernix/runtime-v1/components/wine-linux-x86_64");
        createCheckedDirectory(base, "kernix/runtime-v1/guest-rootfs");
        createCheckedDirectory(base, "kernix/runtime-v1/prefixes");
        createCheckedDirectory(base, "kernix/runtime-v1/sessions");
        return result;
    }
}
