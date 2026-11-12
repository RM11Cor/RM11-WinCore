package com.rm11cor.carxstreet.portlab;

import java.nio.charset.StandardCharsets;

/**
 * Bounded, pure Java Unity/IL2CPP file-header inspection.
 * NO decompression, decryption, code execution or game assets extraction.
 * Entirely independent from Android so it can be unit-tested on CI.
 */
public final class UnityFormatProbe {
    private UnityFormatProbe() {}

    public static final class Metadata {
        public final boolean classicMagic;
        public final long rawMagic;
        public final long rawVersion;
        public final boolean plausibleVersion;

        private Metadata(boolean classicMagic, long rawMagic, long rawVersion,
                         boolean plausibleVersion) {
            this.classicMagic = classicMagic;
            this.rawMagic = rawMagic;
            this.rawVersion = rawVersion;
            this.plausibleVersion = plausibleVersion;
        }
    }

    public static final class Bundle {
        public final String signature;
        public final boolean recognized;
        public final long formatVersion;
        public final String unityVersion;
        public final String unityRevision;
        public final boolean headerComplete;

        private Bundle(String signature, boolean recognized, long formatVersion,
                       String unityVersion, String unityRevision, boolean headerComplete) {
            this.signature = signature;
            this.recognized = recognized;
            this.formatVersion = formatVersion;
            this.unityVersion = unityVersion;
            this.unityRevision = unityRevision;
            this.headerComplete = headerComplete;
        }
    }

    public static Metadata metadata(byte[] head) {
        if (head == null || head.length < 8) {
            return new Metadata(false, -1, -1, false);
        }
        long magic = u32le(head, 0);
        long version = u32le(head, 4);
        boolean valid = magic == 0xFAB11BAFL;
        // Report the version but never assume it means the original
        // C# code or Android-compatible IL2CPP binaries are present.
        return new Metadata(valid, magic, version,
                valid && version >= 16 && version <= 40);
    }

    public static Bundle bundle(byte[] head) {
        if (head == null || head.length < 16) {
            return new Bundle("", false, -1, "", "", false);
        }
        int end = zEnd(head, 0, 20);
        if (end < 0) {
            return new Bundle("invalid-signature", false, -1, "", "", false);
        }
        String signature = new String(head, 0, end, StandardCharsets.US_ASCII);
        if (!signature.equals("UnityFS") &&
            !signature.equals("UnityWeb") &&
            !signature.equals("UnityRaw")) {
            return new Bundle(signature, false, -1, "", "", false);
        }
        int cursor = end + 1;
        if (cursor + 4 >= head.length) {
            return new Bundle(signature, true, -1, "", "", false);
        }
        long format = u32be(head, cursor);
        cursor += 4;
        int versionEnd = zEnd(head, cursor, 80);
        if (versionEnd < 0) {
            return new Bundle(signature, true, format, "", "", false);
        }
        String version = new String(head, cursor, versionEnd - cursor,
                StandardCharsets.US_ASCII);
        cursor = versionEnd + 1;
        int revisionEnd = zEnd(head, cursor, 120);
        if (revisionEnd < 0) {
            return new Bundle(signature, true, format, version, "", false);
        }
        String revision = new String(head, cursor, revisionEnd - cursor,
                StandardCharsets.US_ASCII);
        return new Bundle(signature, true, format, version, revision, true);
    }

    static long u32le(byte[] b, int off) {
        return ((long)b[off] & 255L) | (((long)b[off+1] & 255L) << 8)
                | (((long)b[off+2] & 255L) << 16)
                | (((long)b[off+3] & 255L) << 24);
    }

    static long u32be(byte[] b, int off) {
        return (((long)b[off] & 255L) << 24)
                | (((long)b[off+1] & 255L) << 16)
                | (((long)b[off+2] & 255L) << 8)
                | ((long)b[off+3] & 255L);
    }

    private static int zEnd(byte[] b, int from, int maxBytes) {
        if (from < 0 || from >= b.length) return -1;
        int to = Math.min(b.length, from + maxBytes);
        for (int i=from; i<to; i++) {
            if (b[i] == 0) return i;
            int ch = b[i] & 255;
            if (ch < 0x20 || ch > 0x7e) return -1;
        }
        return -1;
    }
}
