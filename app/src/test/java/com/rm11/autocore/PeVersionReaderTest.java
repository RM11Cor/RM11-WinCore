package com.rm11.autocore;

import org.junit.Test;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.channels.FileChannel;
import static org.junit.Assert.*;

public class PeVersionReaderTest {
    @Test public void parsesWin32VersionResourceString() {
        String key = "ProductName\u0000";
        String value = "Meteor Horizon\u0000";
        byte[] k = key.getBytes(StandardCharsets.UTF_16LE);
        byte[] v = value.getBytes(StandardCharsets.UTF_16LE);
        int valueOffset = (6 + k.length + 3) & ~3;
        byte[] block = new byte[valueOffset + v.length];
        int blockLength = block.length, valueChars = value.length();
        block[0] = (byte) blockLength;
        block[1] = (byte) (blockLength >>> 8);
        block[2] = (byte) valueChars;
        block[3] = (byte) (valueChars >>> 8);
        block[4] = 1;
        System.arraycopy(k, 0, block, 6, k.length);
        System.arraycopy(v, 0, block, valueOffset, v.length);
        assertEquals("Meteor Horizon", PeVersionReader.parseVersionBlob(block).productName);
    }
    private static void set16(byte[] a, int off, int v) {
        a[off] = (byte) v; a[off+1] = (byte) (v >>> 8);
    }
    private static void set32(byte[] a, int off, long v) {
        for (int i=0;i<4;i++) a[off+i] = (byte) (v >>> (i*8));
    }
    @Test public void readsProductNameFromMinimalPeResource() throws Exception {
        byte[] pe = new byte[2048];
        set16(pe, 0, 0x5a4d); set32(pe, 60, 0x80);
        set32(pe, 0x80, 0x4550); // PE signature
        set16(pe, 0x86, 1); // one section
        set16(pe, 0x94, 224); // optional header size
        int opt = 0x98;
        set16(pe, opt, 0x10b); // PE32
        set32(pe, opt + 96 + 16, 0x1000); // resources RVA
        int sec = opt + 224;
        set32(pe, sec + 8, 1024); set32(pe, sec + 12, 0x1000);
        set32(pe, sec + 16, 1024); set32(pe, sec + 20, 0x400);
        int r = 0x400;
        set16(pe, r+14, 1); set32(pe, r+16, 16); set32(pe, r+20, 0x80000020L);
        set16(pe, r+32+14, 1); set32(pe, r+32+16, 1); set32(pe, r+32+20, 0x80000040L);
        set16(pe, r+64+14, 1); set32(pe, r+64+16, 1033); set32(pe, r+64+20, 96);
        String key = "ProductName\u0000", value = "Boreal Quest\u0000";
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_16LE);
        byte[] valueBytes = value.getBytes(StandardCharsets.UTF_16LE);
        int valPos = (6+keyBytes.length+3)&~3;
        int blobLen = valPos + valueBytes.length;
        set32(pe, r+96, 0x1000+128); set32(pe, r+100, blobLen);
        set16(pe, r+128, blobLen); set16(pe, r+130, value.length()); set16(pe, r+132, 1);
        System.arraycopy(keyBytes, 0, pe, r+134, keyBytes.length);
        System.arraycopy(valueBytes, 0, pe, r+128+valPos, valueBytes.length);
        Path temp = Files.createTempFile("rm11-pe-version", ".exe");
        try {
            Files.write(temp, pe);
            try (FileChannel ch = FileChannel.open(temp, StandardOpenOption.READ)) {
                assertEquals("Boreal Quest", PeVersionReader.read(ch).productName);
            }
        } finally { Files.deleteIfExists(temp); }
    }
    @Test public void rejectsGarbageGracefully() {
        assertEquals("", PeVersionReader.parseVersionBlob(new byte[30]).productName);
    }
}
