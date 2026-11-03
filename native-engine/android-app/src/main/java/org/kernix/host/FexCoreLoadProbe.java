package org.kernix.host;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

/** Fixed signed-APK FEXCore library loader test. Does NOT emulate x86 or run Wine. */
public final class FexCoreLoadProbe {
    private static final String LIBRARY = "libFEXCore.so";
    private static final String PROBE = "libkernix_fexcore_load_probe.so";
    static final String MARKER = "KERNIX_REAL_FEXCORE_ANDROID_DLOPEN_SYMBOL_PROOF_V1\n";
    private FexCoreLoadProbe() {}

    static File resolve(File directory, String name) throws IOException {
        if (directory == null || !directory.isDirectory()
                || !(name.equals(LIBRARY) || name.equals(PROBE)))
            throw new IOException("Invalid APK native library path");
        Path base = directory.toPath().toRealPath();
        Path file = base.resolve(name);
        if (Files.isSymbolicLink(file)
                || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)
                || !file.toRealPath().getParent().equals(base))
            throw new IOException("Missing or redirected signed-APK native binary");
        return file.toFile().getCanonicalFile();
    }

    static boolean verified(int exit, String output) {
        return exit == 0 && MARKER.equals(output);
    }

    public static String run(File nativeLibraryDirectory) {
        Process p = null;
        try {
            File probe = resolve(nativeLibraryDirectory, PROBE);
            File core = resolve(nativeLibraryDirectory, LIBRARY);
            if (!probe.canExecute()) throw new IOException("Native loader executable denied");
            p = new ProcessBuilder(probe.getAbsolutePath(), core.getAbsolutePath())
                .redirectErrorStream(true).start();
            if (!p.waitFor(8, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return "FEXCORE_ANDROID_LOAD_TIMEOUT; games not attempted";
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (InputStream stream = p.getInputStream()) {
                byte[] buffer = new byte[128];
                int count;
                while ((count = stream.read(buffer)) != -1 && out.size() < 4096)
                    out.write(buffer, 0, Math.min(count, 4096 - out.size()));
            }
            String response = out.toString(StandardCharsets.UTF_8.name());
            if (verified(p.exitValue(), response))
                return "FEXCORE_ANDROID_LOAD_PASS: actual verified upstream "
                    + "ARM64 original FEXCore without legacy syscall patch loaded and exported expected symbol.\n"
                    + "x86 instructions, Wine and games: NOT YET TESTED.";
            return "FEXCORE_ANDROID_LOAD_FAIL: exit=" + p.exitValue() + "; output="
                + response.replace('\n', ' ').substring(0, Math.min(response.length(), 240));
        } catch (IOException | SecurityException error) {
            return "FEXCORE_ANDROID_LOAD_FAIL: " + error.getMessage();
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            return "FEXCORE_ANDROID_LOAD_INTERRUPTED";
        } finally {
            if (p != null) p.destroyForcibly();
        }
    }
}
