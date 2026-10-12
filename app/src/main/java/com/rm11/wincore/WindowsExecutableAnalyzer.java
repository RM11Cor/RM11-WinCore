package com.rm11.wincore;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Read-only PE metadata inspector. Pure Java: runnable in a desktop unit test.
 * A best-effort import table is NOT a reliable list of all graphics APIs used by a game.
 * No Windows code is executed, installed or extracted.
 */
public final class WindowsExecutableAnalyzer {
    private static final int MAX_READ = 8 * 1024 * 1024;
    private static final int MAX_SECTIONS = 96;
    private static final int MAX_IMPORTS = 128;
    private WindowsExecutableAnalyzer() { }

    public static final class Result {
        public final String fileName;
        public final int machine;
        public final int magic;
        public final int sectionCount;
        public final boolean dll;
        public final Set<String> importedLibraries;
        public final String graphicsHint;
        public final boolean importsFullyVisible;

        private Result(String name, int machine, int magic, int sections, boolean dll,
                       Set<String> imports, String hint, boolean visible) {
            this.fileName = name;
            this.machine = machine;
            this.magic = magic;
            this.sectionCount = sections;
            this.dll = dll;
            this.importedLibraries = Collections.unmodifiableSet(new LinkedHashSet<>(imports));
            this.graphicsHint = hint;
            this.importsFullyVisible = visible;
        }

        public String architecture() {
            switch (machine) {
                case 0x8664: return "Windows x86-64 / PE32+";
                case 0x014c: return "Windows x86-32 / PE32";
                case 0xaa64: return "Windows ARM64 (not Android native)";
                default: return String.format(Locale.ROOT, "Unknown 0x%04X", machine);
            }
        }
    }

    public static Result analyze(InputStream stream, String displayName) throws IOException {
        if (stream == null) throw new IOException("No input stream");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] chunk = new byte[32768];
        int remaining = MAX_READ;
        int n;
        while (remaining > 0 && (n = stream.read(chunk, 0, Math.min(chunk.length, remaining))) != -1) {
            if (n == 0) continue;
            out.write(chunk, 0, n);
            remaining -= n;
        }
        return analyzeBytes(out.toByteArray(), displayName);
    }

    public static Result analyzeBytes(byte[] a, String name) throws IOException {
        if (!has(a, 0, 64) || u16(a, 0) != 0x5a4d) throw new IOException("Missing DOS MZ header");
        long peAtLong = u32(a, 0x3c);
        if (peAtLong > Integer.MAX_VALUE) throw new IOException("Invalid PE offset");
        int pe = (int) peAtLong;
        if (!has(a, pe, 24) || u32(a, pe) != 0x00004550L) throw new IOException("Invalid PE signature");
        int machine = u16(a, pe + 4);
        int sections = u16(a, pe + 6);
        int optLength = u16(a, pe + 20);
        boolean dll = (u16(a, pe + 22) & 0x2000) != 0;
        if (sections == 0 || sections > MAX_SECTIONS) throw new IOException("Invalid section count");
        int opt = pe + 24;
        if (!has(a, opt, optLength) || optLength < 2) throw new IOException("Truncated PE optional header");
        int magic = u16(a, opt);
        if (magic != 0x20b && magic != 0x10b) throw new IOException("Unknown PE optional header format");
        int dataDir = opt + (magic == 0x20b ? 112 : 96);
        int numberOfRvaOffset = opt + (magic == 0x20b ? 108 : 92);
        if (!has(a, numberOfRvaOffset, 4)) throw new IOException("Truncated PE data-directory count");
        long directoryCount = u32(a, numberOfRvaOffset);
        int sectionTable = opt + optLength;
        if (!has(a, sectionTable, sections * 40)) throw new IOException("Truncated PE section table");
        LinkedHashSet<String> dlls = new LinkedHashSet<>();
        boolean visible = true;
        if (directoryCount >= 2) {
            int impDir = dataDir + 8; // Import Directory entry #1
            if (impDir + 8 > opt + optLength) throw new IOException("Invalid import data directory");
            long importRva = u32(a, impDir);
            long importSize = u32(a, impDir + 4);
            if (importRva != 0 && importSize != 0) {
                int importPos = rvaToFile(a, sectionTable, sections, importRva);
                if (importPos < 0) {
                    visible = false;
                } else {
                    boolean terminated = false;
                    for (int i = 0; i < MAX_IMPORTS; i++) {
                        int pos = importPos + i * 20;
                        if (!has(a, pos, 20)) { visible = false; break; }
                        long orig = u32(a, pos), time = u32(a, pos + 4);
                        long forward = u32(a, pos + 8), dllNameRva = u32(a, pos + 12);
                        long firstThunk = u32(a, pos + 16);
                        if ((orig | time | forward | dllNameRva | firstThunk) == 0) { terminated = true; break; }
                        int dllPos = rvaToFile(a, sectionTable, sections, dllNameRva);
                        if (dllPos < 0) { visible = false; continue; }
                        String dllName = readAsciiZ(a, dllPos, 96);
                        if (dllName == null) { visible = false; continue; }
                        dlls.add(dllName.toLowerCase(Locale.ROOT));
                    }
                    if (!terminated) visible = false;
                }
            }
        } else {
            visible = false;
        }
        String graphics = detectGraphics(dlls);
        String safeName = name == null ? "unknown.exe" : name.replaceAll("[\\r\\n\\t]", " ");
        if (safeName.length() > 160) safeName = safeName.substring(0, 160);
        return new Result(safeName, machine, magic, sections, dll, dlls, graphics, visible);
    }

    private static String detectGraphics(Set<String> imports) {
        // Stronger evidence first. Some games import several and choose one at runtime.
        if (imports.contains("d3d12.dll")) return "D3D12";
        if (imports.contains("d3d11.dll")) return "D3D11";
        if (imports.contains("d3d10.dll") || imports.contains("d3d10core.dll")) return "D3D10";
        if (imports.contains("d3d9.dll")) return "D3D9";
        if (imports.contains("vulkan-1.dll")) return "Vulkan";
        if (imports.contains("opengl32.dll")) return "OpenGL";
        if (imports.contains("ddraw.dll")) return "DirectDraw";
        return "UNKNOWN";
    }

    private static boolean has(byte[] a, int i, int size) {
        return i >= 0 && size >= 0 && i <= a.length && size <= a.length - i;
    }
    private static int u16(byte[] a, int pos) {
        return (a[pos] & 255) | (a[pos + 1] & 255) << 8;
    }
    private static long u32(byte[] a, int pos) {
        return (u16(a, pos) & 65535L) | ((u16(a, pos + 2) & 65535L) << 16);
    }
    private static int rvaToFile(byte[] a, int table, int count, long rva) {
        for (int i = 0; i < count; i++) {
            int s = table + 40 * i;
            long virtualSize = u32(a, s + 8), virtualAddress = u32(a, s + 12);
            long rawSize = u32(a, s + 16), rawAt = u32(a, s + 20);
            long extent = Math.max(virtualSize, rawSize);
            if (rva >= virtualAddress && rva - virtualAddress < extent) {
                long relative = rva - virtualAddress;
                // Avoid decoding uninitialized virtual bytes beyond the on-disk section.
                if (relative >= rawSize) continue;
                long absolute = rawAt + relative;
                if (absolute < a.length && absolute <= Integer.MAX_VALUE) return (int) absolute;
            }
        }
        return -1;
    }
    private static String readAsciiZ(byte[] a, int at, int max) {
        if (at < 0 || at >= a.length) return null;
        int i = at;
        while (i < a.length && i - at < max && a[i] != 0) {
            int c = a[i] & 255;
            if (!(c >= 32 && c <= 126)) return null;
            i++;
        }
        if (i == a.length || i - at == max || a[i] != 0) return null;
        return new String(a, at, i - at, StandardCharsets.US_ASCII);
    }
}
