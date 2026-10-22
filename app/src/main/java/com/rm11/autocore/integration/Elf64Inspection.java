package com.rm11.autocore.integration;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Read-only ELF64/AArch64 loader inspection to explain native Wine startup failures.
 * Parses PT_INTERP and DT_NEEDED; does NOT try to load or execute any library.
 */
public final class Elf64Inspection {
    private Elf64Inspection() {}
    public static final class Result {
        public final boolean arm64;
        public final String interpreter;
        public final List<String> needed;
        private Result(boolean arm64, String interpreter, List<String> needed) {
            this.arm64 = arm64;
            this.interpreter = interpreter;
            this.needed = Collections.unmodifiableList(new ArrayList<>(needed));
        }
    }
    private static final class Segment {
        final int type; final long offset, vaddr, fileSize;
        Segment(int type, long offset, long vaddr, long fileSize) {
            this.type=type; this.offset=offset; this.vaddr=vaddr; this.fileSize=fileSize;
        }
    }

    private static ByteBuffer read(FileChannel ch, long offset, int count) throws IOException {
        if (count < 0 || offset < 0 || offset > ch.size() || (long)count > ch.size() - offset)
            throw new IOException("ELF field outside file");
        ByteBuffer b = ByteBuffer.allocate(count).order(ByteOrder.LITTLE_ENDIAN);
        while (b.hasRemaining()) {
            int n = ch.read(b, offset + b.position());
            if (n <= 0) throw new IOException("Truncated ELF field");
        }
        b.flip();
        return b;
    }
    private static String cstring(FileChannel ch, long offset, int max) throws IOException {
        ByteBuffer b = read(ch, offset, max);
        int n = 0;
        while (n < max && b.get(n) != 0) n++;
        if (n == max) throw new IOException("Unterminated ELF string");
        byte[] bytes = new byte[n]; b.get(bytes);
        return new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
    }
    private static long fileOffset(List<Segment> segments, long address) throws IOException {
        for (Segment seg : segments) {
            if (seg.type == 1 && address >= seg.vaddr && address - seg.vaddr < seg.fileSize)
                return seg.offset + address - seg.vaddr;
        }
        throw new IOException("DT_STRTAB points outside file-backed PT_LOAD segment");
    }
    public static Result inspect(Path file) throws IOException {
        if (file == null || Files.isSymbolicLink(file) || !Files.isRegularFile(file))
            throw new IOException("Missing or unsafe ELF path");
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ)) {
            if (ch.size() < 64) throw new IOException("ELF64 header truncated");
            ByteBuffer h = read(ch, 0, 64);
            if ((h.get(0)&255)!=127 || h.get(1)!='E' || h.get(2)!='L' || h.get(3)!='F'
                    || h.get(4)!=2 || h.get(5)!=1) throw new IOException("Not little-endian ELF64");
            boolean arm64 = (h.getShort(18)&0xffff) == 183;
            long phoff = h.getLong(32);
            int phentsize = h.getShort(54)&0xffff, phnum = h.getShort(56)&0xffff;
            if (phentsize < 56 || phnum == 0 || phnum > 256 || phoff < 0 ||
                    phoff > ch.size() || (long)phentsize * phnum > ch.size() - phoff)
                throw new IOException("Invalid ELF program header table");
            List<Segment> segments = new ArrayList<>();
            for (int i=0;i<phnum;i++) {
                ByteBuffer p = read(ch, phoff + (long)i*phentsize, 56);
                segments.add(new Segment(p.getInt(0), p.getLong(8),p.getLong(16),p.getLong(32)));
            }
            String interpreter = "(none; may be a shared library)";
            List<Long> neededIndexes = new ArrayList<>();
            long strtab=-1, strsz=0;
            for (Segment s : segments) {
                if (s.type == 3) {
                    if (s.fileSize <= 0 || s.fileSize > 4096) throw new IOException("Invalid PT_INTERP");
                    interpreter = cstring(ch, s.offset, (int)s.fileSize);
                }
                if (s.type == 2) {
                    if (s.fileSize < 0 || s.fileSize > 1024*1024) throw new IOException("Invalid PT_DYNAMIC size");
                    for(long o=0; o + 16 <= s.fileSize; o += 16) {
                        ByteBuffer d=read(ch,s.offset+o,16);
                        long tag=d.getLong(0),value=d.getLong(8);
                        if(tag==0) break;
                        if(tag==1) neededIndexes.add(value);
                        if(tag==5) strtab=value;
                        if(tag==10) strsz=value;
                    }
                }
            }
            List<String> libs = new ArrayList<>();
            if (!neededIndexes.isEmpty()) {
                if(strtab<0 || strsz<=0 || strsz>4*1024*1024) throw new IOException("Missing valid ELF dynstr table");
                long base=fileOffset(segments,strtab);
                for (long at : neededIndexes) {
                    if(at<0 || at>=strsz) throw new IOException("Invalid DT_NEEDED string offset");
                    libs.add(cstring(ch,base+at,(int)Math.min(512,strsz-at)));
                }
            }
            return new Result(arm64,interpreter,libs);
        }
    }
}
