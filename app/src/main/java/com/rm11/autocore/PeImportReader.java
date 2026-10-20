package com.rm11.autocore;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Bounded, read-only Portable Executable (PE) header and import-table inspection.
 * Does not execute code or load a DLL. Does not copy executable files.
 * Import DLLs are clues, not a complete inventory: delay-loading and LoadLibrary
 * dependencies might be absent. Non-seekable Android document providers can fail.
 */
public final class PeImportReader {
    private PeImportReader() { }
    private static final int MAX_READ = 4096;
    private static final int MAX_SECTIONS = 96;
    private static final int MAX_IMPORTS = 128;

    public static final class Info {
        public final String architecture;
        public final List<String> importedDlls;
        public final boolean importTablePresent;
        Info(String architecture, List<String> imports, boolean hasTable) {
            this.architecture = architecture;
            this.importedDlls = Collections.unmodifiableList(new ArrayList<>(imports));
            this.importTablePresent = hasTable;
        }
    }
    private static Info empty() { return new Info("غير محدد", Collections.emptyList(), false); }
    private static int u16(byte[] b, int p) {
        if (p < 0 || p + 2 > b.length) return 0;
        return (b[p] & 255) | ((b[p + 1] & 255) << 8);
    }
    private static long u32(byte[] b, int p) {
        if (p < 0 || p + 4 > b.length) return 0;
        return ((long)b[p] & 255) | (((long)b[p + 1] & 255) << 8)
                | (((long)b[p + 2] & 255) << 16) | (((long)b[p + 3] & 255) << 24);
    }
    private static byte[] at(FileChannel c, long offset, int count) throws IOException {
        if (offset < 0 || count < 0 || count > MAX_READ || offset > c.size()
                || count > c.size() - offset) return null;
        byte[] b = new byte[count];
        ByteBuffer buf = ByteBuffer.wrap(b);
        while (buf.hasRemaining()) {
            int n = c.read(buf, offset + buf.position());
            if (n <= 0) return null;
        }
        return b;
    }
    private static String architecture(int machine) {
        switch (machine) {
            case 0x8664: return "x86-64";
            case 0x14c: return "x86-32";
            case 0xaa64: return "ARM64";
            case 0x1c4: return "ARM32";
            default: return "غير محدد (0x" + Integer.toHexString(machine) + ")";
        }
    }
    private static final class Section {
        final long rva, raw, size;
        Section(long rva, long raw, long size) { this.rva = rva; this.raw = raw; this.size = size; }
        long map(long address, long length, long fileSize) {
            if (address < rva || address - rva > size || length > size - (address - rva)) return -1;
            long pos = raw + (address - rva);
            return pos >= 0 && pos <= fileSize && length <= fileSize - pos ? pos : -1;
        }
    }
    private static long locate(List<Section> sections, long rva, long length, long fileSize) {
        for (Section s : sections) {
            long pos = s.map(rva, length, fileSize);
            if (pos >= 0) return pos;
        }
        return -1;
    }
    private static String readName(FileChannel channel, long pos) throws IOException {
        // Bounded, ASCII-only import library names (normal PE names are ASCII).
        byte[] raw = at(channel, pos, 128);
        if (raw == null) {
            long available = channel.size() - pos;
            if (available <= 0) return "";
            raw = at(channel, pos, (int)Math.min(available, 128));
            if (raw == null) return "";
        }
        int n = 0;
        while (n < raw.length && raw[n] != 0) {
            int ch = raw[n] & 255;
            if (ch < 32 || ch > 126) return "";
            n++;
        }
        if (n == 0 || n == raw.length) return "";
        String name = new String(raw, 0, n, StandardCharsets.US_ASCII).toLowerCase(Locale.ROOT);
        return name.matches("[a-z0-9_.+-]{3,128}\\.dll") ? name : "";
    }
    public static Info read(FileChannel channel) throws IOException {
        byte[] dos = at(channel, 0, 64);
        if (dos == null || u16(dos, 0) != 0x5a4d) return empty();
        long pe = u32(dos, 60);
        if (pe < 64 || pe > 1024 * 1024) return empty();
        byte[] header = at(channel, pe, 24);
        if (header == null || u32(header, 0) != 0x4550) return empty();
        String architecture = architecture(u16(header, 4));
        int sectionCount = u16(header, 6), optionalSize = u16(header, 20);
        if (sectionCount == 0 || sectionCount > MAX_SECTIONS || optionalSize < 96 || optionalSize > 2048)
            return new Info(architecture, Collections.emptyList(), false);
        byte[] optional = at(channel, pe + 24, optionalSize);
        if (optional == null) return new Info(architecture, Collections.emptyList(), false);
        int magic = u16(optional, 0);
        int directoryStart = magic == 0x10b ? 96 : magic == 0x20b ? 112 : -1;
        if (directoryStart < 0 || directoryStart + 16 > optional.length)
            return new Info(architecture, Collections.emptyList(), false);
        long importRva = u32(optional, directoryStart + 8);
        if (importRva == 0) return new Info(architecture, Collections.emptyList(), false);
        byte[] sectionHeaders = at(channel, pe + 24 + optionalSize, sectionCount * 40);
        if (sectionHeaders == null) return new Info(architecture, Collections.emptyList(), true);
        List<Section> sections = new ArrayList<>();
        for (int i = 0; i < sectionCount; i++) {
            int p = i * 40;
            long address = u32(sectionHeaders, p + 12);
            long rawSize = u32(sectionHeaders, p + 16);
            long rawOffset = u32(sectionHeaders, p + 20);
            if (rawSize > 0) sections.add(new Section(address, rawOffset, rawSize));
        }
        Set<String> dlls = new LinkedHashSet<>();
        for (int i = 0; i < MAX_IMPORTS; i++) {
            long offset = locate(sections, importRva + i * 20L, 20, channel.size());
            if (offset < 0) break;
            byte[] desc = at(channel, offset, 20);
            if (desc == null) break;
            long nameRva = u32(desc, 12);
            if (nameRva == 0 && u32(desc, 0) == 0 && u32(desc, 16) == 0) break;
            if (nameRva == 0) continue;
            long namePos = locate(sections, nameRva, 1, channel.size());
            if (namePos < 0) continue;
            String name = readName(channel, namePos);
            if (!name.isEmpty()) dlls.add(name);
        }
        return new Info(architecture, new ArrayList<>(dlls), true);
    }
}
