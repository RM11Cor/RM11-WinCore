package com.rm11.autocore;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Read-only, bounded Win32 RT_VERSION extractor; no execution or whole-EXE copies. */
public final class PeVersionReader {
    private PeVersionReader() { }
    private static final int MAX_VERSION = 512 * 1024;
    public static final class Info {
        public final String productName, fileDescription, productVersion;
        Info(String name, String description, String version) {
            productName = name; fileDescription = description; productVersion = version;
        }
    }
    private static int word(byte[] a, int i) {
        if (i < 0 || i + 2 > a.length) return 0;
        return (a[i] & 255) | ((a[i + 1] & 255) << 8);
    }
    private static long dword(byte[] a, int i) {
        if (i < 0 || i + 4 > a.length) return 0;
        return ((long) a[i] & 255L) | (((long) a[i + 1] & 255L) << 8)
                | (((long) a[i + 2] & 255L) << 16) | (((long) a[i + 3] & 255L) << 24);
    }
    private static byte[] at(FileChannel channel, long pos, int size) throws IOException {
        if (size < 0 || size > MAX_VERSION || pos < 0 || pos + size > channel.size()) return null;
        byte[] data = new byte[size];
        ByteBuffer buffer = ByteBuffer.wrap(data);
        long offset = pos;
        while (buffer.hasRemaining()) {
            int n = channel.read(buffer, offset);
            if (n <= 0) return null;
            offset += n;
        }
        return data;
    }
    private static final class Section {
        final long rva, size, fileOffset;
        Section(long rva, long size, long fileOffset) {
            this.rva = rva; this.size = size; this.fileOffset = fileOffset;
        }
        long offset(long targetRva) {
            return targetRva >= rva && targetRva < rva + size
                    ? fileOffset + targetRva - rva : -1;
        }
    }
    private static long map(List<Section> sections, long rva) {
        for (Section s : sections) {
            long off = s.offset(rva);
            if (off >= 0) return off;
        }
        return -1;
    }
    private static int firstChild(byte[] resource, int directoryOffset, int desiredId) {
        if (directoryOffset < 0 || directoryOffset + 16 > resource.length) return -1;
        int named = word(resource, directoryOffset + 12);
        int ids = word(resource, directoryOffset + 14);
        int count = named + ids;
        if (count <= 0 || count > 1024 || directoryOffset + 16L + count * 8L > resource.length) return -1;
        for (int i = 0; i < count; i++) {
            int entry = directoryOffset + 16 + i * 8;
            long name = dword(resource, entry);
            if (desiredId >= 0 && (name & 0x80000000L) != 0) continue;
            if (desiredId < 0 || (name & 0xffff) == desiredId) return entry;
        }
        return -1;
    }
    private static Info empty() { return new Info("", "", ""); }
    public static Info read(FileChannel channel) throws IOException {
        byte[] dos = at(channel, 0, 64);
        if (dos == null || word(dos, 0) != 0x5a4d) return empty();
        long peOffset = dword(dos, 60);
        if (peOffset < 64 || peOffset > 1024 * 1024) return empty();
        byte[] headers = at(channel, peOffset, 24);
        if (headers == null || dword(headers, 0) != 0x4550) return empty();
        int count = word(headers, 6), optionalSize = word(headers, 20);
        if (count < 1 || count > 96 || optionalSize < 96 || optionalSize > 4096) return empty();
        byte[] optional = at(channel, peOffset + 24, optionalSize);
        if (optional == null) return empty();
        int magic = word(optional, 0);
        int directories = magic == 0x20b ? 112 : magic == 0x10b ? 96 : -1;
        if (directories < 0 || directories + 24 > optional.length) return empty();
        long resourceRva = dword(optional, directories + 16);
        if (resourceRva == 0) return empty();
        byte[] table = at(channel, peOffset + 24 + optionalSize, count * 40);
        if (table == null) return empty();
        List<Section> sections = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            int p = i * 40;
            long virtualSize = dword(table, p + 8), virtualAddr = dword(table, p + 12);
            long rawSize = dword(table, p + 16), rawOffset = dword(table, p + 20);
            sections.add(new Section(virtualAddr, Math.max(virtualSize, rawSize), rawOffset));
        }
        long resourceOffset = map(sections, resourceRva);
        if (resourceOffset < 0) return empty();
        // Resource index is typically small; version blob is read separately by RVA.
        byte[] root = at(channel, resourceOffset, (int) Math.min(128 * 1024L, channel.size() - resourceOffset));
        if (root == null) return empty();
        int entry = firstChild(root, 0, 16); // RT_VERSION
        if (entry < 0 || (dword(root, entry + 4) & 0x80000000L) == 0) return empty();
        int level1 = (int) (dword(root, entry + 4) & 0x7fffffffL);
        entry = firstChild(root, level1, -1); // name
        if (entry < 0 || (dword(root, entry + 4) & 0x80000000L) == 0) return empty();
        int level2 = (int) (dword(root, entry + 4) & 0x7fffffffL);
        entry = firstChild(root, level2, -1); // language
        if (entry < 0 || (dword(root, entry + 4) & 0x80000000L) != 0) return empty();
        int dataEntry = (int) dword(root, entry + 4);
        if (dataEntry < 0 || dataEntry + 16 > root.length) return empty();
        long blobRva = dword(root, dataEntry), length = dword(root, dataEntry + 4);
        if (length == 0 || length > MAX_VERSION) return empty();
        long blobOffset = map(sections, blobRva);
        if (blobOffset < 0) return empty();
        byte[] blob = at(channel, blobOffset, (int) length);
        return blob == null ? empty() : parseVersionBlob(blob);
    }
    static Info parseVersionBlob(byte[] data) {
        if (data == null || data.length == 0) return empty();
        return new Info(extractString(data, "ProductName"),
                extractString(data, "FileDescription"), extractString(data, "ProductVersion"));
    }
    static String extractString(byte[] blob, String key) {
        byte[] needle = (key + "\u0000").getBytes(StandardCharsets.UTF_16LE);
        for (int i = 6; i + needle.length + 2 < blob.length; i += 2) {
            boolean matches = true;
            for (int j = 0; j < needle.length; j++) {
                if (blob[i + j] != needle[j]) { matches = false; break; }
            }
            if (!matches) continue;
            int start = i - 6;
            int len = word(blob, start), valueChars = word(blob, start + 2), type = word(blob, start + 4);
            if (len < 16 || valueChars <= 0 || valueChars > 256 || type != 1) continue;
            int valueOffset = (i + needle.length + 3) & ~3;
            if (valueOffset + valueChars * 2L > blob.length || valueOffset + valueChars * 2L > start + len) continue;
            String s = new String(blob, valueOffset, valueChars * 2, StandardCharsets.UTF_16LE)
                    .replace("\u0000", "").trim();
            if (s.length() > 1 && s.length() < 160) return s;
        }
        return "";
    }
}
