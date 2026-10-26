package com.rm11.autocore.diagnostics;

import android.content.Context;
import android.os.Build;

import com.rm11.autocore.runtime.RuntimeLayout;
import com.rm11.autocore.runtime.NativeXorgLifecycleDiagnostics;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitOption;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * On-device offline evidence only. No root, network, logs from other apps,
 * game data or copies of the Wine runtime binaries.
 */
public final class OfflineDiagnosticArchive {
    private static final int MAX_WINE_TEXT = 185000;
    private static final int MAX_JOURNAL_TEXT = 175000;
    private static final int MAX_INVENTORY_ENTRIES = 4200;
    private static final int MAX_INVENTORY_BYTES = 460000;
    private static final int MAX_SHA_BYTES = 16 * 1024 * 1024;

    private OfflineDiagnosticArchive() {}

    public static void export(Context context, OutputStream destination) throws Exception {
        if (destination == null) throw new IOException("Export destination not available");
        RuntimeLayout runtime = new RuntimeLayout(context.getFilesDir().toPath(),
                new File(context.getApplicationInfo().nativeLibraryDir).toPath());

        try (ZipOutputStream zip = new ZipOutputStream(destination, StandardCharsets.UTF_8)) {
            zip.setLevel(6);
            String instructions = "RM11 v2.6.0 OFFLINE DIAGNOSTICS\n"
                    + "This ZIP describes the RM11-WinCore runtime, file layout and local failures.\n"
                    + "Contains NO game assets, executable copies, full system logs, root data or pairing keys.\n"
                    + "The included Wine log is bounded; missing lines do not imply that nothing failed.\n"
                    + "Share only if you approve the included data. No automatic upload happens.\n"
                    + "FILES: summary.json, events.json, wine/last-smoke.json, wine/last-smoke.log,\n"
                    + "inventory/native-and-critical.json, inventory/wine-files.tsv, inventory/prefix-files.tsv.\n"
                    + "Native X.Org evidence: native-xorg/service-state.txt and native-xorg/process-exits.json.\n";
            write(zip, "README.txt", instructions);

            JSONObject summary = new JSONObject();
            summary.put("schema", "rm11.offline-diagnostics.v1");
            summary.put("capturedAtUnixMs", System.currentTimeMillis());
            summary.put("package", context.getPackageName());
            summary.put("androidSdk", Build.VERSION.SDK_INT);
            summary.put("androidRelease", Build.VERSION.RELEASE);
            summary.put("manufacturer", Build.MANUFACTURER);
            summary.put("model", Build.MODEL);
            summary.put("supportedAbis", new JSONArray(Arrays.asList(Build.SUPPORTED_ABIS)));
            summary.put("networkTransferRequired", false);
            summary.put("shizukuRequired", false);
            summary.put("containsRuntimeBinaryFiles", false);
            summary.put("rootCauseAutomaticallyVerified", false);
            summary.put("gameExecutionVerified", false);
            summary.put("maxWineTextChars", MAX_WINE_TEXT);
            summary.put("inventoryEntriesPerRootLimit", MAX_INVENTORY_ENTRIES);
            summary.put("inventoryIncludesExternalGameFolders", false);
            write(zip, "summary.json", summary.toString(2));

            Path journal = context.getFilesDir().toPath().resolve("offline-diagnostics/events.json");
            // Include independently persisted failure evidence even if many
            // post-game status events have rolled over the general journal.
            write(zip, "events.json", safeJournal(journal));
            write(zip, "game/last-assertion.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-game-assertion.json")));
            write(zip, "game/last-seh.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-game-seh.json")));
            // v4.0.2: distinguish X.Org SIGSEGV/exit before creating
            // $TMPDIR/.X11-unix/X2. These are ONLY app-owned process details;
            // no logcat, raw tombstone file, root or user game data.
            write(zip,"native-xorg/service-state.txt",
                    NativeXorgLifecycleDiagnostics.readPhase(context));
            write(zip,"native-xorg/process-exits.json",
                    NativeXorgLifecycleDiagnostics.recentServiceExits(context));

            Path lastWine = context.getFilesDir().toPath().resolve("directbridge/last-wine-smoke.json");
            if (Files.isRegularFile(lastWine, LinkOption.NOFOLLOW_LINKS)
                    && Files.size(lastWine) <= 320000) {
                JSONObject raw = new JSONObject(new String(Files.readAllBytes(lastWine), StandardCharsets.UTF_8));
                String log = DiagnosticSanitizer.scrub(raw.optString("wineReport", ""), MAX_WINE_TEXT);
                raw.remove("wineReport");
                raw.remove("evidenceExcerpt");
                raw.put("evidenceExcerpt", DiagnosticSanitizer.scrub(
                        raw.optString("summary", ""), 1000));
                raw.put("exportLogBounded", true);
                raw.put("exportLogFile", "wine/last-smoke.log");
                write(zip, "wine/last-smoke.json", raw.toString(2));
                write(zip, "wine/last-smoke.log", log);
            } else {
                write(zip, "wine/last-smoke.json",
                        "{\"status\":\"NO_SAVED_WINE_TEST\",\"action\":\"Run WineServer test first\"}\n");
            }

            write(zip, "inventory/native-and-critical.json", nativeReport(runtime).toString(2));
            write(zip, "inventory/wine-files.tsv",
                    inventory(runtime.wineRoot, runtime.appFiles, "Wine runtime", MAX_INVENTORY_ENTRIES));
            write(zip, "inventory/prefix-files.tsv",
                    inventory(runtime.winePrefix, runtime.appFiles, "Windows prefix", MAX_INVENTORY_ENTRIES));
            zip.finish();
        }
    }

    private static String safeCrashSnapshot(Path file) {
        try {
            if(!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)
                    ||Files.size(file)>18000)return "{}";
            JSONObject event=new JSONObject(new String(Files.readAllBytes(file),
                    StandardCharsets.UTF_8));
            if(!event.has("test")||!event.has("result"))return "{}";
            return event.toString();
        }catch(Exception ignored){return "{}";}
    }

    private static String safeJournal(Path file) throws IOException {
        try {
            String original="[]";
            if(Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)
                    &&Files.size(file)<=550000)
                original=new String(Files.readAllBytes(file),StandardCharsets.UTF_8);

            // Hold some export room for the *critical* independent snapshots.
            JSONArray entries=new JSONArray(boundedJournalJson(original,
                    MAX_JOURNAL_TEXT-28000));
            for(String name:new String[]{"last-game-seh.json","last-game-assertion.json"}) {
                String saved=safeCrashSnapshot(file.getParent().resolve(name));
                if("{}".equals(saved))continue;
                JSONObject item=new JSONObject(saved);
                boolean alreadyIncluded=false;
                for(int i=0;i<entries.length();i++) {
                    JSONObject old=entries.optJSONObject(i);
                    if(old!=null
                            &&old.optLong("timeUnixMs")==item.optLong("timeUnixMs")
                            &&old.optString("test").equals(item.optString("test"))) {
                        alreadyIncluded=true;
                        break;
                    }
                }
                if(!alreadyIncluded)entries.put(item);
            }
            // Crash snapshots are appended last; remove stale ordinary
            // records first to satisfy the strict user-export byte bound.
            java.util.ArrayList<String> all=new java.util.ArrayList<>();
            for(int i=0;i<entries.length();i++)
                all.add(entries.get(i).toString());
            while(!all.isEmpty()) {
                String result="["+String.join(",",all)+"]";
                if(result.getBytes(StandardCharsets.UTF_8).length<=MAX_JOURNAL_TEXT)
                    return result;
                all.remove(0);
            }
        }catch(Exception malformed) {
            // Standalone crash snapshot files still export independently.
        }
        return "[]";
    }

    /** Retain the newest COMPLETE events rather than truncating a JSON string
     * in the middle of its last record (the v2.7.3 export suffered this bug).
     * There is no arbitrary-text scrubbing here: the on-device journal already
     * scrubs each event at the time it is recorded.
     */
    static String boundedJournalJson(String content, int maxBytes) throws Exception {
        JSONArray original = new JSONArray(content);
        JSONArray latest = new JSONArray();
        java.util.ArrayList<Object> reversed = new java.util.ArrayList<>();
        int budget = 2; // JSON brackets
        for (int i=original.length()-1; i>=0; i--) {
            Object event=original.get(i);
            String compact=event.toString();
            int bytes=compact.getBytes(StandardCharsets.UTF_8).length + 1;
            if (budget + bytes > maxBytes) break;
            reversed.add(event);
            budget += bytes;
        }
        for (int i=reversed.size()-1; i>=0; i--) latest.put(reversed.get(i));
        String result=latest.toString(2);
        if (result.getBytes(StandardCharsets.UTF_8).length > maxBytes) {
            // Pretty formatting may increase size. Compact JSON is valid too.
            result=latest.toString();
        }
        return result;
    }

    private static JSONObject nativeReport(RuntimeLayout runtime) throws Exception {
        JSONObject report = new JSONObject();
        report.put("description", "Existence/size/checksum of allowlisted critical runtime files only.");
        report.put("apkNativeLibDir", "[APP_NATIVE_LIBRARY_DIR]");
        report.put("wineServer", describe(runtime.nativeWineServer, "apk-native/WineServer"));
        report.put("wineLauncher", describe(runtime.nativeWineLauncher, "apk-native/WineLoader"));
        report.put("wineNtdll", describe(runtime.nativeNtdll, "apk-native/WineNtdll"));
        report.put("nlsRedirect", describe(runtime.apkNativeLibs.resolve(
                "librm11_wine_data_redirect.so"), "apk-native/NlsRedirect"));
        report.put("fexArm64ec", describe(runtime.fexArm64ec(), "imagefs/Wine/FEXArm64ec"));
        report.put("fexArm64EcSystem32", describe(runtime.winePrefix.resolve(
                "drive_c/windows/system32/libarm64ecfex.dll"), "wineprefix/System32/Arm64EcFexAlias"));
        report.put("fexWow64", describe(runtime.fexWow64(), "imagefs/Wine/FEXWow64"));
        report.put("fexUnixArm64Ec", describe(runtime.apkNativeLibs.resolve("libarm64ecfex.so"),
                "apk-native/FEX-2609/ARM64EC-UnixLib"));
        report.put("fexUnixWow64", describe(runtime.apkNativeLibs.resolve("libwow64fex.so"),
                "apk-native/FEX-2609/WoW64-UnixLib"));
        report.put("unixNtdll", describe(runtime.unixNtdll(), "imagefs/Wine/UnixNtdll"));
        report.put("unixWs2_32Original", describe(runtime.wineDllRoot.resolve("aarch64-unix/ws2_32.so"),
                "imagefs/Wine/UnixLib/ws2_32.so"));
        report.put("unixWs2_32SignedApk", describe(runtime.apkNativeLibs.resolve("libwine_ws2_32.so"),
                "apk-native/Wine/ws2_32.so"));
        report.put("wineRootIsAppPrivateSymlink", Files.isSymbolicLink(runtime.wineRoot));
        report.put("peNtdllDll", describe(runtime.wineDllRoot.resolve("aarch64-windows/ntdll.dll"),
                "imagefs/Wine/aarch64-windows/ntdll.dll"));
        report.put("peWinebootExe", describe(runtime.wineDllRoot.resolve("aarch64-windows/wineboot.exe"),
                "imagefs/Wine/aarch64-windows/wineboot.exe"));
        report.put("peKernel32Dll", describe(runtime.wineDllRoot.resolve("aarch64-windows/kernel32.dll"),
                "imagefs/Wine/aarch64-windows/kernel32.dll"));
        report.put("peKernelbaseDll", describe(runtime.wineDllRoot.resolve("aarch64-windows/kernelbase.dll"),
                "imagefs/Wine/aarch64-windows/kernelbase.dll"));
        report.put("prefixKernel32Dll", describe(runtime.winePrefix.resolve("drive_c/windows/system32/kernel32.dll"),
                "wineprefix/System32/kernel32.dll"));
        report.put("prefixKernelbaseDll", describe(runtime.winePrefix.resolve("drive_c/windows/system32/kernelbase.dll"),
                "wineprefix/System32/kernelbase.dll"));
        report.put("prefixNtdllDll", describe(runtime.winePrefix.resolve("drive_c/windows/system32/ntdll.dll"),
                "imagefs/Prefix/system32/ntdll.dll"));
        report.put("prefixWinebootExe", describe(runtime.winePrefix.resolve("drive_c/windows/system32/wineboot.exe"),
                "imagefs/Prefix/system32/wineboot.exe"));
        report.put("nlsInternational", describe(runtime.wineNls, "imagefs/NLS/l_intl.nls"));
        report.put("nlsLocale", describe(runtime.wineNls.resolveSibling("locale.nls"),
                "imagefs/NLS/locale.nls"));
        report.put("prefixMarker", describe(runtime.winePrefixMarker(),
                "imagefs/Prefix/CommittedMarker"));
        report.put("prefixSystem32", Files.isDirectory(runtime.winePrefix.resolve(
                "drive_c/windows/system32"), LinkOption.NOFOLLOW_LINKS));
        report.put("logMetadataOnly", true);
        return report;
    }

    private static JSONObject describe(Path path, String label) throws Exception {
        JSONObject obj = new JSONObject();
        obj.put("label", label);
        boolean alias = Files.isSymbolicLink(path);
        boolean exists = Files.isRegularFile(path);
        obj.put("exists", exists);
        obj.put("readable", exists && Files.isReadable(path));
        obj.put("symlink", alias);
        obj.put("sha256OfSymlinkTarget", false);
        if (!exists) return obj;
        long bytes = Files.size(path);
        obj.put("sizeBytes", bytes);
        if (alias) obj.put("sha256", "SYMLINK_TARGET_NOT_HASHED");
        else if (bytes > 0 && bytes <= MAX_SHA_BYTES) obj.put("sha256", sha256(path));
        else obj.put("sha256", "SKIPPED_SIZE_LIMIT");
        return obj;
    }

    private static String sha256(Path file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream in = Files.newInputStream(file)) {
            byte[] chunk = new byte[8192];
            int n;
            while ((n = in.read(chunk)) > 0) digest.update(chunk, 0, n);
        }
        StringBuilder hex = new StringBuilder();
        for (byte b : digest.digest()) hex.append(String.format(Locale.ROOT, "%02x", b & 255));
        return hex.toString();
    }

    /** Enumerate metadata with strict time, byte and entry bounds; never follow symlinks. */
    private static String inventory(Path root, Path appFiles, String scope, int limit) throws IOException {
        StringBuilder out = new StringBuilder("relative_path\tkind\tsize_bytes\n");
        Path candidate = root;
        if (Files.isSymbolicLink(root)) {
            // ImageFsProvisioner intentionally aliases opt/wine to appFiles/runtime-v2417.
            // Do not follow arbitrary external symlinks; only a target inside RM11's
            // private app directory may be inventoried.
            try {
                Path target = root.toRealPath();
                Path trusted = appFiles.toRealPath();
                if (!target.startsWith(trusted))
                    return out + "# SYMLINK_OUTSIDE_APP_REJECTED: " + scope + "\n";
                candidate = target;
                out.append("# APP_PRIVATE_SYMLINK_ROOT_RESOLVED\n");
            } catch (IOException e) {
                return out + "# BROKEN_SYMLINK_ROOT: " + scope + "\n";
            }
        }
        final Path treeRoot = candidate;
        if (!Files.isDirectory(treeRoot, LinkOption.NOFOLLOW_LINKS)) {
            return out + "# NOT_INSTALLED_OR_NOT_DIRECTORY: " + scope + "\n";
        }
        final AtomicInteger count = new AtomicInteger();
        final long started = System.nanoTime();
        final boolean[] cut = {false};
        Files.walkFileTree(treeRoot, EnumSet.noneOf(FileVisitOption.class), 15,
                new SimpleFileVisitor<Path>() {
                    private boolean overBudget() {
                        boolean hit = count.get() >= limit || out.length() > MAX_INVENTORY_BYTES
                                || System.nanoTime() - started > 8_000_000_000L;
                        if (hit) cut[0] = true;
                        return hit;
                    }
                    @Override public FileVisitResult preVisitDirectory(
                            Path path, BasicFileAttributes attrs) throws IOException {
                        if (overBudget()) return FileVisitResult.TERMINATE;
                        Path relative = treeRoot.relativize(path);
                        String value = relative.toString().replace('\\','/');
                        // Personal user directories can contain saves, settings or names.
                        if (value.startsWith("drive_c/users") || value.startsWith("users/")
                                || value.contains("/AppData/") || value.contains("/appdata/")) {
                            return FileVisitResult.SKIP_SUBTREE;
                        }
                        if (!value.isEmpty()) addLine(out, value, "DIR", 0);
                        count.incrementAndGet();
                        return FileVisitResult.CONTINUE;
                    }
                    @Override public FileVisitResult visitFile(
                            Path path, BasicFileAttributes attrs) throws IOException {
                        if (overBudget()) return FileVisitResult.TERMINATE;
                        Path relative = treeRoot.relativize(path);
                        String value = relative.toString().replace('\\','/');
                        // Metadata only; no file bytes enter the export.
                        addLine(out, value, attrs.isSymbolicLink() ? "SYMLINK" : "FILE",
                                attrs.isRegularFile() ? attrs.size() : 0);
                        count.incrementAndGet();
                        return FileVisitResult.CONTINUE;
                    }
                    @Override public FileVisitResult visitFileFailed(
                            Path path, IOException ex) {
                        if (overBudget()) return FileVisitResult.TERMINATE;
                        addLine(out, treeRoot.relativize(path).toString(), "READ_ERROR", 0);
                        count.incrementAndGet();
                        return FileVisitResult.CONTINUE;
                    }
                });
        if (cut[0]) out.append("# TRUNCATED: item/time/size limit reached; inventory is NOT complete\n");
        return out.toString();
    }

    private static void addLine(StringBuilder text, String path, String kind, long size) {
        String safe = DiagnosticSanitizer.shortLabel(path);
        // File names are truncated to avoid leakage from large, user-defined paths.
        // Keep final suffix and beginning for recognizing required DLLs.
        if (path.length() > 80) {
            safe = DiagnosticSanitizer.shortLabel(path.substring(0, 40)
                    + "[…]" + path.substring(path.length() - 38));
        }
        text.append(safe).append('\t').append(kind).append('\t').append(size).append('\n');
    }

    private static void write(ZipOutputStream zip, String entryName, String value) throws IOException {
        ZipEntry entry = new ZipEntry(entryName);
        entry.setTime(0L); // stable contents except captured times inside report
        zip.putNextEntry(entry);
        zip.write(value.getBytes(StandardCharsets.UTF_8));
        zip.closeEntry();
    }
}
