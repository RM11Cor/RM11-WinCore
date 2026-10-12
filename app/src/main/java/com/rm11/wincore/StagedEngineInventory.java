package com.rm11.wincore;

import android.content.Context;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * V1.0 read-only, on-device audit of components already staged in V0.9.
 * No exec, dlopen of staged blobs, WINEPREFIX, chmod, rootfs launch or EXE support.
 */
public final class StagedEngineInventory {
    private StagedEngineInventory() {}

    public static String inspect(Context context) {
        StringBuilder result = new StringBuilder("RM11 WinCore V1.0-A / Saved runtime inventory\n");
        result.append("READ ONLY. SHA256 is NOT proof of origin. No components executed.\n\n");
        if (!RuntimeBootstrap.correctDevice()) return result.append("[STOP] NX809J / Android 16 only.\n").toString();
        File dir = new File(context.getFilesDir(), "rm11-engine-staged");
        File manifestFile = new File(dir, "rm11-engine.json");
        if (!manifestFile.isFile()) return result.append("[MISSING] No staged bundle. Import a valid RM11 Engine ZIP in section 09 first.\n").toString();
        try {
            if (manifestFile.length() > 128 * 1024 || manifestFile.length() == 0)
                throw new IllegalArgumentException("Manifest length invalid");
            JSONObject manifest = new JSONObject(new String(Files.readAllBytes(manifestFile.toPath()), StandardCharsets.UTF_8));
            if (manifest.getInt("schema") != 1 || !"NX809J".equalsIgnoreCase(manifest.getString("targetModel"))
                    || !"arm64-v8a".equals(manifest.getString("abi"))
                    || manifest.getInt("minApi") > android.os.Build.VERSION.SDK_INT)
                throw new IllegalArgumentException("Wrong bundle target/schema");
            JSONArray items = manifest.getJSONArray("components");
            if (items.length() == 0 || items.length() > 32)
                throw new IllegalArgumentException("Invalid component count");
            Set<String> ids = new HashSet<>();
            boolean hasBox64 = false, hasWine = false, hasUserland = false, hasGraphics = false;
            long total = 0;
            for (int i = 0; i < items.length(); i++) {
                JSONObject item = items.getJSONObject(i);
                String id = item.getString("id");
                String sha = item.getString("sha256");
                long bytes = item.getLong("bytes");
                if (!id.matches("[a-z0-9_.-]{2,40}") || !ids.add(id)
                        || !item.getString("path").startsWith("components/")
                        || item.getString("license").trim().isEmpty())
                    throw new IllegalArgumentException("Invalid saved manifest entry");
                File stored = new File(dir, id + ".blob");
                RuntimeBinaryAudit.Result check = RuntimeBinaryAudit.inspect(stored, bytes, sha);
                total += bytes;
                if (total > 1536L * 1024 * 1024) throw new IllegalArgumentException("Size limit exceeded");
                result.append("[HASH OK] ").append(id).append(" / ").append(bytes).append(" bytes\n");
                if (!check.isElf) {
                    result.append("  [DATA] Not an ELF program/library\n");
                } else if (check.elf == null) {
                    result.append("  [ELF UNKNOWN] ").append(check.metadataError).append("\n");
                } else {
                    ElfRuntimeInspector.Report elf = check.elf;
                    String arch = elf.machine == 183 && elf.elfClass == 2 ? "ARM64"
                            : elf.machine == 62 && elf.elfClass == 2 ? "x86-64" : "other";
                    result.append("  [ELF] ").append(arch).append(" / ")
                            .append(elf.kind == 3 ? "ET_DYN" : "ET_EXEC").append("\n");
                    if (elf.interpreter != null) result.append("  loader: ").append(elf.interpreter).append("\n");
                    if (check.usesGlibcLoader()) result.append("  [BLOCKER] glibc userland/loader required\n");
                    if (elf.dependenciesUnreadable || elf.interpreterUnreadable)
                        result.append("  [LIMIT] Incomplete ELF metadata in 256 KiB sample\n");
                    if (!elf.needed.isEmpty()) result.append("  needed: ")
                            .append(String.join(", ", elf.needed)).append("\n");
                }
                // A role label is a claim supplied by the ZIP author; a real usable
                // runtime still requires audited, Android-compatible binaries.
                if (id.equals("box64") && check.isNativeArm64()) hasBox64 = true;
                if (id.equals("wine") && check.elf != null) hasWine = true;
                if (id.equals("glibc-loader") && check.isNativeArm64()) hasUserland = true;
                if (id.equals("dxvk") || id.equals("vkd3d")) hasGraphics = true;
            }
            result.append("\n--- Bundle inventory (not runtime activation) ---\n");
            result.append(hasBox64 ? "[PRESENT] ARM64 Box64-labelled ELF\n" : "[MISSING] ARM64 Box64 executable\n");
            result.append(hasWine ? "[PRESENT] Wine-labelled ELF\n" : "[MISSING] Wine loader/program\n");
            result.append(hasUserland ? "[PRESENT] ARM64 glibc-loader-labelled ELF\n" : "[MISSING] Linux/glibc userland and loader\n");
            result.append(hasGraphics ? "[PRESENT] Graphics-labelled data\n" : "[MISSING] DXVK/VKD3D graphics integration\n");
            result.append("[NOT RUNNABLE] Components, even if present, are saved as inert data.\n");
            result.append("[NEXT] Build/package licensed Android-compatible native runtime and test actual loader/dependencies.\n");
        } catch (Exception e) {
            result.append("[FAIL] Saved component audit: ").append(e.getClass().getSimpleName())
                    .append(": ").append(e.getMessage()).append("\n");
            result.append("[SAFE] No stored component executed or modified.\n");
        }
        return result.toString();
    }
}
