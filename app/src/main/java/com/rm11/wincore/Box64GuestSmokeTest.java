package com.rm11.wincore;

import android.content.Context;
import android.os.Build;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/** Box64 V1.4.1 experimental execution of a bundled, known freestanding Linux x86-64 ELF.
 * The guest ELF is stored as data in assets; Android never executes it directly.
 * No arbitrary user EXE, system linker or Wine is used.
 */
public final class Box64GuestSmokeTest {
    private static final String BOX64 = "librm11box64.so";
    private static final String GUEST_ASSET = "box64_test/hello_x86_64.elf";
    private static final String SUCCESS = "RM11_X86_64_GUEST_EXEC_OK";
    private static final int MAX_GUEST_BYTES = 256 * 1024;
    private static final int MAX_LOG_BYTES = 16 * 1024;
    private Box64GuestSmokeTest() { }

    static void verifyGuest(byte[] data) {
        if (data.length < 64 || data.length > MAX_GUEST_BYTES ||
            data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' ||
            data[4] != 2 || data[5] != 1) {
            throw new IllegalArgumentException("Guest is not bounded ELF64 little endian");
        }
        ByteBuffer elf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        if (Short.toUnsignedInt(elf.getShort(16)) != 2 ||
            Short.toUnsignedInt(elf.getShort(18)) != 62) {
            throw new IllegalArgumentException("Expected x86-64 Linux ET_EXEC guest");
        }
        long phoff = elf.getLong(32);
        int entsize = Short.toUnsignedInt(elf.getShort(54));
        int count = Short.toUnsignedInt(elf.getShort(56));
        if (phoff < 64 || entsize < 56 || count == 0 || count > 64 ||
            phoff > data.length || (long) entsize * count > data.length - phoff) {
            throw new IllegalArgumentException("Invalid ELF program headers");
        }
        for (int i = 0; i < count; i++) {
            int offset = (int) (phoff + (long) entsize * i);
            if (elf.getInt(offset) == 3) {
                throw new IllegalArgumentException("Guest unexpectedly depends on a dynamic Linux loader");
            }
        }
    }

    private static byte[] loadGuest(Context context) throws Exception {
        try (InputStream in = context.getAssets().open(GUEST_ASSET);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) != -1) {
                if (out.size() + n > MAX_GUEST_BYTES) throw new IllegalArgumentException("Guest asset too large");
                out.write(buf, 0, n);
            }
            byte[] contents = out.toByteArray();
            verifyGuest(contents);
            return contents;
        }
    }

    public static String run(Context context) {
        StringBuilder log = new StringBuilder("RM11 WinCore V1.4.1 / Genuine Linux x86-64 guest via Box64\n")
            .append("Experimental, offline, freestanding guest (NO Linux glibc/Wine/EXE).\n");
        if (Build.SUPPORTED_ABIS.length == 0 || !"arm64-v8a".equals(Build.SUPPORTED_ABIS[0])) {
            return log.append("[STOP] ARM64 Android device required.\n").toString();
        }
        File box64 = new File(context.getApplicationInfo().nativeLibraryDir, BOX64);
        if (!box64.isFile()) {
            return log.append("[NOT BUILT] Actual upstream Box64 is missing from this APK.\n").toString();
        }
        File guest = null;
        Process process = null;
        try {
            // The guest file is DATA, read by Box64. Android kernel never executes this cache file.
            byte[] bytes = loadGuest(context);
            guest = File.createTempFile("rm11-x86-64-guest-", ".elf", context.getCacheDir());
            try (FileOutputStream out = new FileOutputStream(guest)) {
                out.write(bytes);
                out.getFD().sync();
            }
            // Box64's launcher requires X_OK on the guest file even though it opens
            // the x86-64 ELF as DATA rather than asking Android to execve it.
            // createTempFile() produces a private, non-executable 0600 file by default.
            // Apply owner-only execute bit; never use chmod 777 or launch this guest
            // directly via the Android kernel (app-private exec is restricted).
            boolean executableBitSet = guest.setExecutable(true, true) && guest.canExecute();
            log.append("Guest owner-execute bit for Box64's access check: ")
               .append(executableBitSet ? "YES" : "NO").append("\n");
            if (!executableBitSet) {
                return log.append("[FAIL] Android rejected owner X_OK permission in private cache.\n")
                    .append("Box64 guest startup skipped; this is not a Wine/game test.\n")
                    .toString();
            }
            // Box64 itself is a prepackaged Android ARM64 ELF in nativeLibraryDir.
            ProcessBuilder builder = new ProcessBuilder(box64.getAbsolutePath(), guest.getAbsolutePath());
            builder.redirectErrorStream(true);
            builder.directory(context.getCacheDir());
            builder.environment().put("BOX64_LOG", "1");
            process = builder.start();
            final Process target = process;
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            Thread collector = new Thread(() -> {
                try (InputStream stream = target.getInputStream()) {
                    byte[] buf = new byte[1024];
                    int n;
                    while ((n = stream.read(buf)) != -1) {
                        synchronized (out) {
                            if (out.size() < MAX_LOG_BYTES) {
                                out.write(buf, 0, Math.min(n, MAX_LOG_BYTES - out.size()));
                            }
                        }
                    }
                } catch (Exception ignored) { }
            }, "rm11-x86-guest-log");
            collector.setDaemon(true);
            collector.start();
            boolean done = process.waitFor(18, TimeUnit.SECONDS);
            if (!done) process.destroyForcibly();
            collector.join(1200);
            final String stdout;
            synchronized (out) { stdout = new String(out.toByteArray(), StandardCharsets.UTF_8); }
            log.append("Guest ELF: x86-64 ET_EXEC; bytes: ").append(bytes.length).append("\n")
               .append("Command: bundled Box64 <bundled Linux x86-64 guest>\n");
            if (!done) {
                return log.append("[TIMEOUT] Box64 did not finish the guest in 18 seconds.\n")
                    .append("Output (bounded):\n").append(stdout).toString();
            }
            int code = process.exitValue();
            log.append("Exit code: ").append(code).append("\n")
               .append("Output (bounded):\n").append(stdout).append("\n");
            if (code == 0 && stdout.contains(SUCCESS)) {
                log.append("[PASS] Box64 executed x86-64 guest arithmetic/branch and Linux write/exit syscalls.\n");
            } else {
                log.append("[FAIL] No confirmed x86-64 guest execution. Review errors above.\n")
                   .append("Possible limitation: experimental Android Box64 / guest syscall or ELF support.\n");
            }
        } catch (Exception e) {
            log.append("[FAIL] ").append(e.getClass().getSimpleName())
                .append(": ").append(e.getMessage()).append("\n");
        } finally {
            if (process != null && process.isAlive()) process.destroyForcibly();
            if (guest != null) guest.delete();
        }
        return log.append("[LIMIT] This is not Wine, not Windows EXE, not proof of game compatibility or FPS.\n")
            .toString();
    }
}
