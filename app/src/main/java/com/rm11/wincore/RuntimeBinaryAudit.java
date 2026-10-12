package com.rm11.wincore;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

/**
 * Rechecks saved component bytes before interpreting bounded ELF metadata.
 * Pure Java; does NOT dlopen, chmod, fork, extract or execute untrusted files.
 * SHA256 is consistency with the bundled manifest, not publisher authentication.
 */
public final class RuntimeBinaryAudit {
    private static final long MAX_COMPONENT = 512L * 1024 * 1024;
    private RuntimeBinaryAudit() {}

    public static final class Result {
        public final boolean isElf;
        public final ElfRuntimeInspector.Report elf;
        public final String metadataError;
        Result(boolean isElf, ElfRuntimeInspector.Report elf, String metadataError) {
            this.isElf = isElf;
            this.elf = elf;
            this.metadataError = metadataError;
        }
        public boolean isNativeArm64() {
            return elf != null && elf.elfClass == 2 && elf.machine == 183;
        }
        public boolean usesGlibcLoader() {
            if (elf == null) return false;
            if (elf.interpreter != null && elf.interpreter.contains("ld-linux")) return true;
            for (String dep : elf.needed) if (dep.equals("libc.so.6")) return true;
            return false;
        }
    }

    public static Result inspect(File file, long expectedBytes, String expectedSha256) throws IOException {
        if (file == null || !file.isFile() || expectedBytes <= 0 || expectedBytes > MAX_COMPONENT
                || file.length() != expectedBytes || expectedSha256 == null
                || !expectedSha256.matches("(?i)[a-f0-9]{64}")) {
            throw new IOException("Saved component metadata/size invalid");
        }
        MessageDigest digest;
        try { digest = MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException e) { throw new IOException(e); }
        byte[] buf = new byte[64 * 1024];
        try (FileInputStream in = new FileInputStream(file)) {
            int n;
            while ((n = in.read(buf)) != -1) if (n > 0) digest.update(buf, 0, n);
        }
        StringBuilder hex = new StringBuilder(64);
        for (byte b : digest.digest()) hex.append(String.format(Locale.US, "%02x", b & 255));
        if (!hex.toString().equalsIgnoreCase(expectedSha256)) throw new IOException("Saved component SHA256 changed");

        byte[] magic = new byte[4];
        try (FileInputStream in = new FileInputStream(file)) {
            if (in.read(magic) != 4 || magic[0] != 0x7f || magic[1] != 'E'
                    || magic[2] != 'L' || magic[3] != 'F') {
                return new Result(false, null, null);
            }
        }
        try (FileInputStream in = new FileInputStream(file)) {
            return new Result(true, ElfRuntimeInspector.analyze(in), null);
        } catch (IOException ex) {
            // Still an ELF by magic, but bounded inspection failed. Never treat as compatible.
            return new Result(true, null, ex.getMessage());
        }
    }
}
