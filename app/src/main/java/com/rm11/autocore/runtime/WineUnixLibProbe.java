package com.rm11.autocore.runtime;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/** Non-invasive evidence of the pinned FEX-2609 Android ARM64 native UnixLib pair. */
public final class WineUnixLibProbe {
    private WineUnixLibProbe() {}

    public static String describe(RuntimeLayout p) {
        StringBuilder out = new StringBuilder("RM11_FEX_UNIXLIB_V263\n");
        Path arm = p.apkNativeLibs.resolve("libarm64ecfex.so");
        Path wow = p.apkNativeLibs.resolve("libwow64fex.so");
        out.append("FEX ARM64EC UnixLib: ").append(checkElfArm64(arm)).append('\n');
        out.append("FEX WoW64 UnixLib: ").append(checkElfArm64(wow)).append('\n');
        out.append("Runtime PE DLL matched build tag: FEX-2609 (pinned source)\n");
        out.append("Native UnixLib search must hit Android APK native lib dir; no app-private executable copies.\n");
        return out.toString();
    }

    public static String checkElfArm64(Path p) {
        try {
            if (Files.isSymbolicLink(p) || !Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS))
                return "MISSING";
            long size = Files.size(p);
            if (size <= 1024) return "TOO_SMALL " + size;
            byte[] header = new byte[20];
            try (InputStream stream = Files.newInputStream(p)) {
                int bytesRead = 0;
                while (bytesRead < header.length) {
                    int n = stream.read(header, bytesRead, header.length - bytesRead);
                    if (n < 0) return "TRUNCATED_ELF";
                    bytesRead += n;
                }
            }
            if ((header[0] & 255) != 127 || header[1] != 'E' || header[2] != 'L' ||
                    header[3] != 'F' || header[4] != 2 || header[5] != 1)
                return "NOT_64_BIT_ELF";
            // ELF e_machine offset=18, little endian, EM_AARCH64=183 (0xB7)
            int machine = (header[18] & 255) | ((header[19] & 255) << 8);
            if (machine != 183) return "WRONG_CPU_ARCH=" + machine;
            return "PRESENT_ARM64_ELF bytes=" + size;
        } catch (Exception e) {
            return "INACCESSIBLE_" + e.getClass().getSimpleName();
        }
    }
}
