package com.rm11.wincore;

import android.content.ContentResolver;
import android.net.Uri;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * V0.4 Stage A: bounded, read-only verification of a component bundle supplied via SAF.
 * Does NOT execute, install, or extract Wine/Box64/rootfs. SHA256 verifies that bytes
 * agree with the supplied manifest, NOT that the supplier is trusted.
 *
 * Bundle contract: rm11-engine.json MUST be the first entry and list every subsequent
 * entry; see ENGINE-BUNDLE-FORMAT-AR.md. Rejects traversal, duplicates, oversized data,
 * undeclared entries, mismatched digests and wrong-device bundles.
 */
public final class EngineBundleVerifier {
    private static final long MAX_COMPONENT = 512L * 1024 * 1024;
    private static final long MAX_TOTAL = 1536L * 1024 * 1024;
    private static final int MAX_MANIFEST = 128 * 1024;
    private EngineBundleVerifier() {}

    private static final class Spec {
        final String id, path, checksum, license;
        final long bytes;
        Spec(String id, String path, String checksum, long bytes, String license) {
            this.id = id; this.path = path; this.checksum = checksum;
            this.bytes = bytes; this.license = license;
        }
    }

    private static void validPath(String path) throws Exception {
        if (path == null || path.length() == 0 || path.startsWith("/") || path.contains("\\")
                || path.contains("//") || path.equals("..") || path.startsWith("../")
                || path.endsWith("/..") || path.contains("/../") || path.contains("/./")
                || path.indexOf('\u0000') >= 0 || path.contains(":")) {
            throw new IllegalArgumentException("Unsafe entry path");
        }
    }

    private static JSONObject readManifest(ZipInputStream zin) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = zin.read(buf)) != -1) {
            if (out.size() + n > MAX_MANIFEST) throw new IllegalArgumentException("Manifest too large");
            out.write(buf, 0, n);
        }
        return new JSONObject(new String(out.toByteArray(), StandardCharsets.UTF_8));
    }

    private static String hex(byte[] bytes) {
        StringBuilder b = new StringBuilder(bytes.length * 2);
        for (byte v : bytes) b.append(String.format(Locale.US, "%02x", v & 255));
        return b.toString();
    }

    public static String verify(ContentResolver resolver, Uri uri) {
        StringBuilder result = new StringBuilder("RM11 WinCore V0.4 / Runtime component audit\n");
        result.append("READ-ONLY. Does NOT install/extract/execute any component.\n");
        result.append("Manifest hashes are NOT proof of publisher authenticity.\n\n");
        if (!RuntimeBootstrap.correctDevice()) {
            return result.append("[STOP] Only verified NX809J ARM64 / Android 16 allowed.\n").toString();
        }
        try (InputStream source = resolver.openInputStream(uri)) {
            if (source == null) throw new IllegalArgumentException("Cannot read selected file");
            try (ZipInputStream zip = new ZipInputStream(source)) {
                ZipEntry entry = zip.getNextEntry();
                if (entry == null || entry.isDirectory() || !"rm11-engine.json".equals(entry.getName())) {
                    throw new IllegalArgumentException("First ZIP entry must be rm11-engine.json");
                }
                JSONObject manifest = readManifest(zip);
                zip.closeEntry();
                if (manifest.getInt("schema") != 1
                        || !"NX809J".equalsIgnoreCase(manifest.getString("targetModel"))
                        || !"arm64-v8a".equals(manifest.getString("abi"))
                        || manifest.getInt("minApi") > android.os.Build.VERSION.SDK_INT) {
                    throw new IllegalArgumentException("Wrong schema, device, ABI, or Android API");
                }
                JSONArray components = manifest.getJSONArray("components");
                if (components.length() == 0 || components.length() > 32) {
                    throw new IllegalArgumentException("Invalid component count");
                }
                Map<String, Spec> required = new HashMap<>();
                Set<String> ids = new HashSet<>();
                long declaredTotal = 0;
                for (int i = 0; i < components.length(); i++) {
                    JSONObject item = components.getJSONObject(i);
                    String id = item.getString("id");
                    String path = item.getString("path");
                    String checksum = item.getString("sha256").toLowerCase(Locale.ROOT);
                    String license = item.getString("license");
                    long bytes = item.getLong("bytes");
                    validPath(path);
                    if ("rm11-engine.json".equals(path) || !path.startsWith("components/")
                            || !id.matches("[a-z0-9_.-]{2,40}") || !ids.add(id)
                            || !checksum.matches("[a-f0-9]{64}") || license.trim().isEmpty()
                            || bytes <= 0 || bytes > MAX_COMPONENT || required.containsKey(path)) {
                        throw new IllegalArgumentException("Invalid manifest entry: " + id);
                    }
                    declaredTotal += bytes;
                    if (declaredTotal > MAX_TOTAL) throw new IllegalArgumentException("Bundle exceeds size limit");
                    required.put(path, new Spec(id, path, checksum, bytes, license));
                }

                Set<String> seen = new HashSet<>();
                long total = 0;
                byte[] buffer = new byte[64 * 1024];
                while ((entry = zip.getNextEntry()) != null) {
                    if (entry.isDirectory()) { zip.closeEntry(); continue; }
                    String path = entry.getName();
                    validPath(path);
                    Spec spec = required.get(path);
                    if (spec == null || !seen.add(path)) {
                        throw new IllegalArgumentException("Undeclared or duplicate ZIP file: " + path);
                    }
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    long len = 0;
                    int n;
                    while ((n = zip.read(buffer)) != -1) {
                        len += n;
                        total += n;
                        if (len > MAX_COMPONENT || total > MAX_TOTAL || len > spec.bytes) {
                            throw new IllegalArgumentException("Component size limit exceeded: " + spec.id);
                        }
                        digest.update(buffer, 0, n);
                    }
                    if (len != spec.bytes || !hex(digest.digest()).equals(spec.checksum)) {
                        throw new IllegalArgumentException("Size or SHA256 mismatch: " + spec.id);
                    }
                    result.append("[PASS] ").append(spec.id).append(": ")
                        .append(len).append(" bytes / SHA256 match / ")
                        .append(spec.license).append('\n');
                    zip.closeEntry();
                }
                if (seen.size() != required.size()) {
                    throw new IllegalArgumentException("Manifest references absent components");
                }
                result.append("\n[PASS] All ").append(seen.size()).append(" declared components were read and matched.\n");
                result.append("[NOT READY] Verification ONLY; no functional Wine/Box64 runtime is integrated.\n");
            }
        } catch (Exception e) {
            result.append("[FAIL] ").append(e.getClass().getSimpleName())
                .append(": ").append(e.getMessage()).append('\n');
        }
        return result.toString();
    }
}
