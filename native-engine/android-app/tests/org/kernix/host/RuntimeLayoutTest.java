package org.kernix.host;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class RuntimeLayoutTest {
    private static void check(boolean result, String message) {
        if (!result) throw new AssertionError(message);
    }

    public static void main(String[] args) throws Exception {
        Path base = Files.createTempDirectory("kernix-private-layout-test-");
        try {
            Path app = Files.createDirectory(base.resolve("app-data"));
            RuntimeLayout.Layout p = RuntimeLayout.prepare(app.toFile());
            check(p.root.isDirectory() && p.prefixes.isDirectory(), "private dirs absent");
            check(p.fexAndroid.isDirectory() && p.wineGuest.isDirectory(), "component slots absent");
            check(p.guestRootfs.isDirectory() && p.sessions.isDirectory(), "runtime slots absent");
            check(!p.isGameReady(), "empty layout must not claim Windows support");
            check(p.root.getCanonicalPath().startsWith(app.toFile().getCanonicalPath()
                  + File.separator), "runtime escapes private root");
            check(!p.root.getPath().equals("/usr/lib"), "system host path used");
            RuntimeLayout.Layout second = RuntimeLayout.prepare(app.toFile());
            check(second.root.getCanonicalPath().equals(p.root.getCanonicalPath()),
                  "prepare is not idempotent");

            Path victim = Files.createDirectory(base.resolve("unrelated"));
            Path rogue = Files.createDirectory(base.resolve("rogue-app-data"));
            Files.createDirectory(rogue.resolve("kernix"));
            Files.createSymbolicLink(rogue.resolve("kernix/runtime-v1"), victim);
            boolean rejected = false;
            try { RuntimeLayout.prepare(rogue.toFile()); }
            catch (IOException expected) { rejected = true; }
            check(rejected, "symlink must be rejected");
            check(Files.list(victim).findAny().isEmpty(), "symlink target mutated");

            Path fileBlock = Files.createDirectory(base.resolve("blocked"));
            Files.createDirectory(fileBlock.resolve("kernix"));
            Files.writeString(fileBlock.resolve("kernix/runtime-v1"), "not a directory");
            rejected = false;
            try { RuntimeLayout.prepare(fileBlock.toFile()); }
            catch (IOException expected) { rejected = true; }
            check(rejected, "file collision must be rejected");

            rejected = false;
            try { RuntimeLayout.prepare(null); }
            catch (IOException expected) { rejected = true; }
            check(rejected, "missing private dir must be rejected");
            System.out.println("KERNIX_APP_PRIVATE_ANDROID_RUNTIME_PATH_CONTRACT_PASS");
        } finally {
            // Runner temporary directories only, never device/system paths.
        }
    }
}
