package com.rm11.wincore;

import android.content.Context;
import android.net.Uri;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * V0.9: stages a selected component bundle as INERT DATA only.
 * Not a Wine/Box64 installer, no chmod, no exec, no extraction into executable locations.
 * The manifest is provided by the bundle creator, so a matching SHA256 is NOT a signature.
 */
public final class EngineBundleStager {
    private static final long MAX_COMPONENT = 512L * 1024L * 1024L;
    private static final long MAX_TOTAL = 1536L * 1024L * 1024L;
    private static final long MIN_SPARE = 256L * 1024L * 1024L;
    private static final int MAX_MANIFEST = 128 * 1024;
    private static final String CURRENT = "rm11-engine-staged";
    private static final String PREVIOUS = "rm11-engine-backup";
    private EngineBundleStager() {}

    private static final class Spec {
        final String id, path, sha256;
        final long bytes;
        Spec(String id, String path, String sha256, long bytes) {
            this.id = id;
            this.path = path;
            this.sha256 = sha256;
            this.bytes = bytes;
        }
    }

    private static String shaHex(byte[] digest) {
        StringBuilder result = new StringBuilder(digest.length * 2);
        for (byte b : digest) result.append(String.format(Locale.US, "%02x", b & 255));
        return result.toString();
    }

    private static byte[] readSmall(InputStream stream) throws IOException {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = stream.read(buf)) >= 0) {
            if (n == 0) continue;
            if (out.size() > MAX_MANIFEST - n) throw new IOException("Manifest size exceeds limit");
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    private static boolean safePath(String path) {
        if (path == null || !path.startsWith("components/") || path.contains("\\")
                || path.contains(":") || path.indexOf(0) >= 0 || path.contains("//")) return false;
        String[] parts = path.split("/", -1);
        if (parts.length < 2) return false;
        for (String part : parts) {
            if (part.isEmpty() || part.equals(".") || part.equals("..")) return false;
        }
        return true;
    }

    private static void removeTree(File file) {
        if (file == null || !file.exists()) return;
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) for (File f : children) removeTree(f);
        }
        file.delete();
    }

    /** For the UI, run from a background thread. Stores only verified, non-executable bytes. */
    public static synchronized String stage(Context context, Uri uri) {
        StringBuilder result = new StringBuilder("RM11 WinCore V0.9 / Inert runtime bundle staging\n");
        result.append("NO ENGINE EXECUTION. No Wine, Box64 or Windows launcher installed.\n");
        result.append("SHA256 in the same ZIP is integrity checking, NOT authenticity.\n\n");
        if (!RuntimeBootstrap.correctDevice()) {
            return result.append("[STOP] NX809J / Android 16 only.\n").toString();
        }
        File root = context.getFilesDir();
        File active = new File(root, CURRENT);
        File previous = new File(root, PREVIOUS);
        File stage = new File(root, ".rm11-incoming-" + UUID.randomUUID());
        long total = 0;
        try {
            if (previous.exists()) throw new IOException("Incomplete previous installation; do not overwrite backup");
            if (!stage.mkdir()) throw new IOException("Cannot create temporary private directory");
            try (InputStream source = context.getContentResolver().openInputStream(uri)) {
                if (source == null) throw new IOException("Cannot open selected bundle");
                try (ZipInputStream zip = new ZipInputStream(source)) {
                    ZipEntry entry = zip.getNextEntry();
                    if (entry == null || entry.isDirectory() || !"rm11-engine.json".equals(entry.getName())) {
                        throw new IOException("First entry must be rm11-engine.json");
                    }
                    byte[] rawManifest = readSmall(zip);
                    zip.closeEntry();
                    JSONObject manifest = new JSONObject(new String(rawManifest, StandardCharsets.UTF_8));
                    if (manifest.getInt("schema") != 1
                            || !"NX809J".equalsIgnoreCase(manifest.getString("targetModel"))
                            || !"arm64-v8a".equals(manifest.getString("abi"))
                            || manifest.getInt("minApi") > android.os.Build.VERSION.SDK_INT) {
                        throw new IOException("Wrong schema, target, ABI or API");
                    }
                    JSONArray items = manifest.getJSONArray("components");
                    if (items.length() == 0 || items.length() > 32) throw new IOException("Bad component count");
                    java.util.Map<String, Spec> expected = new java.util.HashMap<>();
                    java.util.Set<String> ids = new java.util.HashSet<>();
                    long declared = 0;
                    for (int i = 0; i < items.length(); ++i) {
                        JSONObject item = items.getJSONObject(i);
                        String id = item.getString("id");
                        String path = item.getString("path");
                        String sha = item.getString("sha256").toLowerCase(Locale.ROOT);
                        String license = item.getString("license");
                        long bytes = item.getLong("bytes");
                        if (!id.matches("[a-z0-9_.-]{2,40}") || !ids.add(id) || !safePath(path)
                                || expected.containsKey(path) || !sha.matches("[a-f0-9]{64}")
                                || license.trim().isEmpty() || bytes <= 0 || bytes > MAX_COMPONENT) {
                            throw new IOException("Invalid component manifest");
                        }
                        declared += bytes;
                        if (declared > MAX_TOTAL) throw new IOException("Bundle exceeds maximum staged size");
                        expected.put(path, new Spec(id, path, sha, bytes));
                    }
                    if (root.getUsableSpace() < declared + MIN_SPARE) {
                        throw new IOException("Insufficient free space (leave 256 MiB spare)");
                    }
                    java.util.Set<String> seen = new java.util.HashSet<>();
                    byte[] buf = new byte[64 * 1024];
                    while ((entry = zip.getNextEntry()) != null) {
                        if (entry.isDirectory()) {
                            throw new IOException("Directory entries are not allowed in RM11 bundles");
                        }
                        String path = entry.getName();
                        Spec spec = expected.get(path);
                        if (!safePath(path) || spec == null || !seen.add(path)) {
                            throw new IOException("Unexpected/duplicate ZIP entry");
                        }
                        // Use a fresh internal name, NEVER a path taken from the archive.
                        File target = new File(stage, spec.id + ".blob");
                        MessageDigest digest = MessageDigest.getInstance("SHA-256");
                        long read = 0;
                        try (OutputStream out = new FileOutputStream(target)) {
                            int n;
                            while ((n = zip.read(buf)) != -1) {
                                if (n == 0) continue;
                                read += n;
                                total += n;
                                if (read > spec.bytes || read > MAX_COMPONENT || total > MAX_TOTAL) {
                                    throw new IOException("Component exceeds declared size");
                                }
                                digest.update(buf, 0, n);
                                out.write(buf, 0, n);
                            }
                        }
                        if (read != spec.bytes || !shaHex(digest.digest()).equals(spec.sha256)) {
                            throw new IOException("Incorrect size or SHA256 for " + spec.id);
                        }
                        result.append("[PASS] ").append(spec.id).append(" / ").append(read).append(" bytes\n");
                        zip.closeEntry();
                    }
                    if (seen.size() != expected.size()) throw new IOException("Bundle components missing");
                    try (OutputStream out = new FileOutputStream(new File(stage, "rm11-engine.json"))) {
                        out.write(rawManifest);
                    }
                    try (OutputStream out = new FileOutputStream(new File(stage, "STAGED-NOT-EXECUTABLE.txt"))) {
                        out.write(("Verified inert data. No files are executed, chmod'ed or integrated.\n"
                                + "Android app-data W^X restrictions apply.\n").getBytes(StandardCharsets.UTF_8));
                    }
                }
            }
            // Keep the previous good bundle unless the new one has passed every validation.
            if (active.exists() && !active.renameTo(previous)) throw new IOException("Cannot back up old stage");
            if (!stage.renameTo(active)) {
                if (previous.exists()) previous.renameTo(active);
                throw new IOException("Cannot activate verified stage");
            }
            if (previous.exists()) removeTree(previous);
            result.append("\n[STAGED] ").append(total).append(" bytes under private app storage.\n")
                .append("[NOT RUNNABLE] Data only. Wine/Box64 NOT integrated.\n");
            return result.toString();
        } catch (Exception ex) {
            result.append("\n[FAIL] ").append(ex.getClass().getSimpleName()).append(": ")
                .append(ex.getMessage()).append("\n[SAFE] Existing verified bundle remains unchanged.\n");
            return result.toString();
        } finally {
            removeTree(stage);
        }
    }

    public static String status(Context context) {
        File dir = new File(context.getFilesDir(), CURRENT);
        File manifest = new File(dir, "rm11-engine.json");
        if (!manifest.isFile()) return "No component bundle staged yet. Wine/Box64 unavailable.";
        return "[STAGED DATA] Verified components saved in private storage. NOT executable or integrated.";
    }
}
