package com.rm11.wincore;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Read-only bounded ELF metadata audit for future Wine / Box64 runtime integration.
 * No ELF bytes are written, loaded or executed. A binary being parseable does NOT
 * imply it is safe, runnable, or compatible with Android/Bionic.
 */
public final class ElfRuntimeInspector {
    private static final int MAX_PREFIX = 256 * 1024;
    private static final int PT_LOAD = 1, PT_DYNAMIC = 2, PT_INTERP = 3;
    private ElfRuntimeInspector() {}

    public static final class Report {
        public final int elfClass, machine, kind;
        public final String interpreter;
        public final List<String> needed;
        public final boolean interpreterUnreadable;
        public final boolean dependenciesUnreadable;
        Report(int elfClass, int machine, int kind, String interpreter,
               List<String> needed, boolean interpreterUnreadable, boolean dependenciesUnreadable) {
            this.elfClass = elfClass;
            this.machine = machine;
            this.kind = kind;
            this.interpreter = interpreter;
            this.needed = java.util.Collections.unmodifiableList(new ArrayList<>(needed));
            this.interpreterUnreadable = interpreterUnreadable;
            this.dependenciesUnreadable = dependenciesUnreadable;
        }
    }

    private static void ensure(byte[] b, long start, long length) throws IOException {
        if (start < 0 || length < 0 || start > b.length || length > b.length - start)
            throw new IOException("ELF header points outside first " + MAX_PREFIX + " bytes");
    }
    private static long u16(byte[] b, long p) throws IOException {
        ensure(b, p, 2);
        int i = (int) p;
        return (b[i] & 255) | ((long) (b[i + 1] & 255) << 8);
    }
    private static long u32(byte[] b, long p) throws IOException {
        ensure(b, p, 4);
        long i = (int) p;
        return (b[(int)i] & 255L) | ((b[(int)i + 1] & 255L) << 8)
            | ((b[(int)i + 2] & 255L) << 16) | ((b[(int)i + 3] & 255L) << 24);
    }
    private static long u64(byte[] b, long p) throws IOException {
        long low = u32(b, p), high = u32(b, p + 4);
        if (high >= 0x80000000L) throw new IOException("ELF offset too large");
        return (high << 32) | low;
    }
    private static String cstr(byte[] b, long offset, long size) throws IOException {
        ensure(b, offset, size);
        int start = (int) offset, end = start, limit = (int)(offset + size);
        while (end < limit && b[end] != 0) end++;
        if (end == limit) throw new IOException("Unterminated ELF string");
        String value = new String(b, start, end - start, StandardCharsets.US_ASCII);
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch < 32 || ch > 126) throw new IOException("Invalid ELF string character");
        }
        return value;
    }
    private static final class Segment {
        long type, offset, vaddr, length;
        Segment(long type, long offset, long vaddr, long length) {
            this.type = type; this.offset = offset; this.vaddr = vaddr; this.length = length;
        }
    }
    private static long virtualToOffset(List<Segment> segments, long address) {
        for (Segment s : segments) {
            if (s.type == PT_LOAD && address >= s.vaddr && address - s.vaddr < s.length)
                return s.offset + (address - s.vaddr);
        }
        return -1;
    }
    public static Report analyze(InputStream source) throws IOException {
        if (source == null) throw new IOException("No input file");
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int n;
        while (bytes.size() < MAX_PREFIX
                && (n = source.read(chunk, 0, Math.min(chunk.length, MAX_PREFIX - bytes.size()))) != -1) {
            if (n == 0) continue;
            bytes.write(chunk, 0, n);
        }
        return analyzeBytes(bytes.toByteArray());
    }
    public static Report analyzeBytes(byte[] b) throws IOException {
        ensure(b, 0, 64);
        if (b[0] != 0x7f || b[1] != 'E' || b[2] != 'L' || b[3] != 'F')
            throw new IOException("Not an ELF file");
        int elfClass = b[4] & 255, endian = b[5] & 255;
        if ((elfClass != 1 && elfClass != 2) || endian != 1 || (b[6] & 255) != 1)
            throw new IOException("Only little-endian ELF32/ELF64 format version 1 supported");
        int kind = (int)u16(b, 16), machine = (int)u16(b, 18);
        if (kind != 2 && kind != 3) throw new IOException("Not an executable or shared-object ELF");
        boolean is64 = elfClass == 2;
        long phoff = is64 ? u64(b, 32) : u32(b, 28);
        long phentsize = u16(b, is64 ? 54 : 42);
        long phnum = u16(b, is64 ? 56 : 44);
        int minimum = is64 ? 56 : 32;
        if (phoff == 0 || phnum == 0 || phnum > 128 || phentsize < minimum || phentsize > 256)
            throw new IOException("Invalid or unsupported ELF program header table");
        if (phoff > MAX_PREFIX || phnum * phentsize > MAX_PREFIX - phoff)
            throw new IOException("ELF program headers not in bounded sample");
        List<Segment> segments = new ArrayList<>();
        long dynamicOffset = -1, dynamicLength = 0;
        String interp = null;
        boolean interpUnreadable = false, dependenciesUnreadable = false;
        for (int i = 0; i < phnum; i++) {
            long p = phoff + i * phentsize;
            long type = u32(b, p);
            long offset = is64 ? u64(b, p + 8) : u32(b, p + 4);
            long vaddr = is64 ? u64(b, p + 16) : u32(b, p + 8);
            long filesz = is64 ? u64(b, p + 32) : u32(b, p + 16);
            segments.add(new Segment(type, offset, vaddr, filesz));
            if (type == PT_INTERP) {
                if (filesz == 0 || filesz > 4096 || offset > b.length || filesz > b.length - offset)
                    interpUnreadable = true;
                else interp = cstr(b, offset, filesz);
            }
            if (type == PT_DYNAMIC) {
                dynamicOffset = offset;
                dynamicLength = filesz;
            }
        }
        List<String> libs = new ArrayList<>();
        if (dynamicOffset >= 0 && dynamicLength > 0) {
            int entryBytes = is64 ? 16 : 8;
            if (dynamicOffset > b.length || dynamicLength > b.length - dynamicOffset)
                dependenciesUnreadable = true;
            else {
                long max = Math.min(dynamicLength / entryBytes, 8192);
                long strtab = -1, strsz = 0;
                List<Long> needed = new ArrayList<>();
                for (int i = 0; i < max; i++) {
                    long p = dynamicOffset + i * entryBytes;
                    long tag = is64 ? u64(b, p) : u32(b, p);
                    long val = is64 ? u64(b, p + 8) : u32(b, p + 4);
                    if (tag == 0) break;
                    if (tag == 1 && needed.size() < 64) needed.add(val);
                    if (tag == 5) strtab = val;
                    if (tag == 10) strsz = val;
                }
                long stringOffset = virtualToOffset(segments, strtab);
                if (!needed.isEmpty() && (stringOffset < 0 || strsz <= 0
                        || strsz > 1024 * 1024 || stringOffset > b.length || strsz > b.length - stringOffset)) {
                    dependenciesUnreadable = true;
                } else {
                    for (long at : needed) {
                        if (at >= strsz) { dependenciesUnreadable = true; break; }
                        try { libs.add(cstr(b, stringOffset + at, strsz - at)); }
                        catch (IOException ex) { dependenciesUnreadable = true; break; }
                    }
                }
            }
        }
        return new Report(elfClass, machine, kind, interp, libs, interpUnreadable, dependenciesUnreadable);
    }

    public static String explain(Report r, String displayName) {
        String arch = r.machine == 183 ? "AArch64 (ARM64)" : r.machine == 62 ? "x86-64"
            : r.machine == 3 ? "x86-32" : r.machine == 40 ? "ARM32" : "other (e_machine=" + r.machine + ")";
        StringBuilder out = new StringBuilder("RM11 WinCore 0.6-A / Native ELF Audit\n");
        out.append("READ ONLY. Nothing installed, loaded, or executed.\n\n")
           .append("File: ").append(displayName == null ? "(unknown)" : displayName).append('\n')
           .append("Format: ELF").append(r.elfClass == 2 ? "64" : "32")
           .append(" / ").append(r.kind == 3 ? "ET_DYN" : "ET_EXEC")
           .append("\nArchitecture: ").append(arch).append('\n');
        out.append("Interpreter: ").append(r.interpreter == null ?
            (r.interpreterUnreadable ? "not readable in sample" : "none (could be shared library or static binary)")
            : r.interpreter).append('\n');
        out.append("DT_NEEDED: ").append(r.needed.isEmpty() ? "none seen" : String.join(", ", r.needed)).append('\n');
        if (r.dependenciesUnreadable) out.append("[LIMIT] Dynamic dependencies incomplete in bounded sample.\n");
        if (r.machine != 183) {
            out.append("[NOT NATIVE] This is not an ARM64 host binary. x86-64 Wine binaries may later use Box64.\n");
        } else if (r.interpreter != null && r.interpreter.contains("ld-linux")) {
            out.append("[LINUX USERLAND REQUIRED] glibc loader detected; Android/Bionic alone cannot run it.\n");
        } else if (r.interpreter != null && (r.interpreter.contains("linker64") || r.interpreter.contains("linker"))) {
            out.append("[ANDROID LOADER HINT] Android linker detected; dependencies, page-size compatibility and packaging still need validation.\n");
        } else {
            out.append("[REVIEW] ABI alone cannot prove Android compatibility, execution or safety.\n");
        }
        out.append("[NOT INTEGRATED] Wine, Box64, graphics/display and an executable runtime are not in this APK.\n");
        return out.toString();
    }
}
