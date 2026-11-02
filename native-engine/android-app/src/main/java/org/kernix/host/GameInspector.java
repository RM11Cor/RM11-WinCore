package org.kernix.host;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/** Strictly read-only bounded PE header probe. Never loads or runs an EXE. */
public final class GameInspector {
    private static final int HEADER_LIMIT = 1024 * 1024;
    private GameInspector() {}

    private static int u16(byte[] b, int at) throws IOException {
        if (at < 0 || at + 2 > b.length) throw new IOException("Truncated PE header");
        return (b[at] & 255) | ((b[at + 1] & 255) << 8);
    }
    private static long u32(byte[] b, int at) throws IOException {
        return (long)u16(b, at) | ((long)u16(b, at + 2) << 16);
    }
    public static String inspect(InputStream stream) throws IOException {
        if (stream == null) throw new IOException("Cannot open selected file");
        ByteArrayOutputStream out = new ByteArrayOutputStream(4096);
        byte[] scratch = new byte[8192];
        int remaining = HEADER_LIMIT;
        int count;
        while (remaining > 0 && (count = stream.read(scratch, 0,
                Math.min(scratch.length, remaining))) != -1) {
            if (count == 0) continue;
            out.write(scratch, 0, count);
            remaining -= count;
        }
        byte[] b = out.toByteArray();
        if (b.length < 64 || b[0] != 'M' || b[1] != 'Z') {
            throw new IOException("Not a Windows MZ executable");
        }
        long peOffsetLong = u32(b, 0x3c);
        if (peOffsetLong > b.length - 24 || peOffsetLong < 64) {
            throw new IOException("PE signature outside bounded first 1 MiB");
        }
        int pe = (int)peOffsetLong;
        if (b[pe] != 'P' || b[pe + 1] != 'E' || b[pe + 2] != 0 || b[pe + 3] != 0) {
            throw new IOException("Missing PE signature");
        }
        int machine = u16(b, pe + 4);
        int sections = u16(b, pe + 6);
        int optionalSize = u16(b, pe + 20);
        if (sections < 1 || sections > 96 || optionalSize < 70 ||
                pe + 24L + optionalSize > b.length) {
            throw new IOException("Invalid or truncated PE optional header");
        }
        int magic = u16(b, pe + 24);
        if (magic != 0x10b && magic != 0x20b) {
            throw new IOException("Unsupported PE optional header");
        }
        int subsystem = u16(b, pe + 24 + 68);
        String architecture;
        switch (machine) {
            case 0x014c: architecture = "x86 32-bit"; break;
            case 0x8664: architecture = "x86-64"; break;
            case 0xaa64: architecture = "Windows ARM64"; break;
            default: architecture = "unknown (0x" + Integer.toHexString(machine) + ")";
        }
        String target = subsystem == 2 ? "Windows GUI"
                : subsystem == 3 ? "Windows console"
                : "other (" + subsystem + ")";
        return "PE architecture: " + architecture + "\n"
                + "Format: " + (magic == 0x20b ? "PE32+" : "PE32") + "\n"
                + "Subsystem: " + target + "\n"
                + "Sections: " + sections + "\n"
                + "DirectX version: NOT YET DETERMINED\n"
                + "Engine / components: NOT YET DETERMINED\n"
                + "Game executed: NO (read-only)";
    }
}
