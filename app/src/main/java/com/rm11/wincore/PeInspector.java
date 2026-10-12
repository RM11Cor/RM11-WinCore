package com.rm11.wincore;

import android.content.ContentResolver;
import android.net.Uri;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Locale;

/** Read-only, bounded analysis of PE headers. NEVER executes uploaded files. */
public final class PeInspector {
    private static final int MAX_HEADER = 1024 * 1024;
    private PeInspector() {}

    private static int u16(byte[] data, int pos) {
        return (data[pos] & 255) | ((data[pos + 1] & 255) << 8);
    }
    private static long u32(byte[] data, int pos) {
        return ((long) u16(data, pos)) | (((long) u16(data, pos + 2)) << 16);
    }
    public static String inspect(ContentResolver resolver, Uri uri) {
        StringBuilder sb = new StringBuilder("RM11 WinCore 0.3 / Windows PE Header Check\n");
        sb.append("READ ONLY — file was not installed, copied or executed.\n");
        try (InputStream in = resolver.openInputStream(uri)) {
            if (in == null) return sb.append("[FAIL] Cannot read file.\n").toString();
            byte[] buffer = new byte[8192];
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            int num;
            while (bytes.size() < MAX_HEADER &&
                    (num = in.read(buffer, 0, Math.min(buffer.length, MAX_HEADER - bytes.size()))) != -1) {
                bytes.write(buffer, 0, num);
            }
            byte[] pe = bytes.toByteArray();
            if (pe.length < 64 || pe[0] != 'M' || pe[1] != 'Z') {
                return sb.append("[FAIL] No DOS MZ header; not recognized as Windows PE.\n").toString();
            }
            long peOffsetLong = u32(pe, 0x3c);
            if (peOffsetLong > MAX_HEADER - 26) {
                return sb.append("[CHECK] PE header offset outside 1 MiB inspection limit.\n").toString();
            }
            int peOffset = (int) peOffsetLong;
            if (peOffset + 26 > pe.length || pe[peOffset] != 'P' ||
                    pe[peOffset + 1] != 'E' || pe[peOffset + 2] != 0 || pe[peOffset + 3] != 0) {
                return sb.append("[FAIL] No valid PE signature at e_lfanew.\n").toString();
            }
            int machine = u16(pe, peOffset + 4);
            int sections = u16(pe, peOffset + 6);
            int optSize = u16(pe, peOffset + 20);
            int optPos = peOffset + 24;
            String cpu;
            switch (machine) {
                case 0x8664: cpu = "x86-64 (needs Wine + Box64)"; break;
                case 0x014c: cpu = "x86 32-bit (may need additional 32-bit translation)"; break;
                case 0xaa64: cpu = "ARM64 Windows PE (not automatically Android-compatible)"; break;
                default: cpu = String.format(Locale.US, "Unknown machine 0x%04X", machine);
            }
            sb.append("[PASS] MZ + PE signature\n");
            sb.append("Architecture: ").append(cpu).append('\n');
            sb.append("Sections: ").append(sections).append('\n');
            if (optSize >= 2 && optPos + 2 <= pe.length) {
                int magic = u16(pe, optPos);
                sb.append("PE format: ").append(magic == 0x20b ? "PE32+ (64-bit)" :
                    magic == 0x10b ? "PE32 (32-bit)" : "Unknown").append('\n');
            } else sb.append("PE optional header: missing/truncated\n");
            sb.append("Wine/Box64 remain NOT INSTALLED. PE identification does not imply compatibility.\n");
        } catch (Exception e) {
            sb.append("[FAIL] File inspection error: ").append(e.getClass().getSimpleName()).append('\n');
        }
        return sb.toString();
    }
}
