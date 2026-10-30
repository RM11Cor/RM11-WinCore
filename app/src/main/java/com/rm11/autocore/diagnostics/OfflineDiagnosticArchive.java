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
            // v485: previous device ZIPs cannot distinguish current APK from
            // a stale on-device build. Record Android PackageManager's LIVE
            // installed package version, never infer version from file name.
            summary.put("rm11DiagnosticGeneration", "v485-carx-dx11-build-proof");
            try {
                android.content.pm.PackageInfo apk=context.getPackageManager()
                        .getPackageInfo(context.getPackageName(),0);
                summary.put("rm11InstalledApkVersionName",apk.versionName);
                summary.put("rm11InstalledApkVersionCode",apk.getLongVersionCode());
                summary.put("rm11InstalledApkSource","ANDROID_PACKAGE_MANAGER");
            }catch(android.content.pm.PackageManager.NameNotFoundException missing){
                summary.put("rm11InstalledApkSource","PACKAGE_INFO_UNAVAILABLE");
            }
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
            write(zip, "game/last-native-abort.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-native-abort.json")));
            write(zip, "game/last-adreno-isolation.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-adreno-isolation.json")));
            write(zip, "game/last-v467-isolation.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v467-isolation.json")));
            write(zip, "game/last-graphics-backend.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-graphics-backend.json")));
            write(zip, "graphics/last-v472-wsi.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v472-wsi.json")));
            write(zip, "graphics/last-v473-private-vulkan.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v473-private-vulkan.json")));
            write(zip, "graphics/last-v474-x11-surface.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v474-x11-surface.json")));
            write(zip, "graphics/last-v475-x11-present.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v475-x11-present.json")));
            write(zip, "graphics/last-v476-x11-dri3.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v476-x11-dri3.json")));
            write(zip, "graphics/last-v477-x11-swapchain.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v477-x11-swapchain.json")));
            write(zip, "graphics/last-v478-x11-software-wsi.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v478-x11-software-wsi.json")));
            write(zip, "graphics/last-v480-x11-touch-stability.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v480-x11-touch-stability.json")));
            write(zip, "graphics/last-v480-touch-pixels.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v480-touch-pixels.json")));
            write(zip, "graphics/last-v479-game-wsi.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v479-game-wsi.json")));
            write(zip, "game/last-v482-game-window.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v482-game-window.json")));
            write(zip, "game/last-v482-game-window-final.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v482-game-window-final.json")));
            write(zip, "game/last-v482-no-window-trigger.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v482-no-window-trigger.json")));
            write(zip, "graphics/last-v482-game-touch-baseline.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v482-game-touch-baseline.json")));
            write(zip, "graphics/last-v482-game-touch-after.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v482-game-touch-after.json")));
            write(zip, "game/last-v483-game-window-recovery.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v483-game-window-recovery.json")));
            write(zip, "game/last-v484-window-inventory.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v484-window-inventory.json")));
            write(zip, "game/last-v484-first-window-inventory.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v484-first-window-inventory.json")));
            write(zip, "game/last-v484-window-recovery-decision.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v484-window-recovery-decision.json")));
            write(zip, "game/last-v485-game-launch-args.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v485-game-launch-args.json")));
            write(zip, "game/last-v49033-carx-vulkan-route.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v49033-carx-vulkan-route.json")));
            write(zip, "game/last-v49033-carx-runtime-plan.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v49033-carx-runtime-plan.json")));
            write(zip, "game/last-v49034-carx-sidecar.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v49034-carx-sidecar.json")));
            write(zip, "game/last-v49034-carx-effective-command.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v49034-carx-effective-command.json")));
            write(zip, "game/last-v486-game-startup-first.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v486-game-startup-first.json")));
            write(zip, "game/last-v486-game-startup-final.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v486-game-startup-final.json")));
            write(zip, "game/last-v487-game-process-first.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v487-game-process-first.json")));
            write(zip, "game/last-v487-game-process-live.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v487-game-process-live.json")));
            write(zip, "game/last-v487-game-process-final.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v487-game-process-final.json")));
            write(zip, "game/last-v488-wine-native-first.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v488-wine-native-first.json")));
            write(zip, "game/last-v488-wine-native-live.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v488-wine-native-live.json")));
            write(zip, "game/last-v488-wine-native-final.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v488-wine-native-final.json")));
            write(zip, "game/last-v489-native-first.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v489-native-first.json")));
            write(zip, "game/last-v489-native-live.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v489-native-live.json")));
            write(zip, "game/last-v489-native-final.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v489-native-final.json")));
            // v4.0.2: distinguish X.Org SIGSEGV/exit before creating
            // $TMPDIR/.X11-unix/X2. These are ONLY app-owned process details;
            // no logcat, raw tombstone file, root or user game data.
            write(zip,"native-xorg/service-state.txt",
                    NativeXorgLifecycleDiagnostics.readPhase(context));
            write(zip,"native-xorg/startup-timeline.txt",
                    NativeXorgLifecycleDiagnostics.readTimeline(context));
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

            // The old wine/last-smoke.log can predate the selected mini EXE.
            // Include the newest direct process output separately, bounded and
            // sanitized, without pretending this proves graphics success.
            Path miniTrace=journal.getParent().resolve("last-mini-d3d11-wine-runtime.log");
            String miniLog="RM11_V49020_MINI_TRACE=NOT_CAPTURED";
            try {
                if (Files.isRegularFile(miniTrace,LinkOption.NOFOLLOW_LINKS)) {
                    long size=Files.size(miniTrace);
                    if (size>0) {
                        try (java.io.RandomAccessFile in=new java.io.RandomAccessFile(miniTrace.toFile(),"r")) {
                            long pos=Math.max(0,size-MAX_WINE_TEXT);
                            in.seek(pos);
                            byte[] bytes=new byte[(int)(size-pos)];
                            in.readFully(bytes);
                            miniLog="RM11_V49020_TOTAL_BYTES="+size+"\\n"
                                    +"RM11_V49020_TAIL_OFFSET="+pos+"\\n"
                                    +DiagnosticSanitizer.scrub(
                                        new String(bytes,StandardCharsets.UTF_8),MAX_WINE_TEXT);
                        }
                    }
                }
            }catch(Exception e){
                miniLog="RM11_V49020_MINI_TRACE_READ_ERROR="+e.getClass().getSimpleName();
            }
            write(zip,"wine/last-mini-d3d11-runtime.log",miniLog);
            // Independent Win32 CreateFile journal: confirms whether Present
            // entered or returned even if Wine/Android stdout loses printf.
            // App-private path, bounded and sanitized; never export binaries.
            Path presentTrace=journal.getParent().resolve("last-v49030-win32-present.log");
            String presentLog="RM11_V49030_PRESENT_JOURNAL=NOT_WRITTEN";
            try {
                if(Files.isRegularFile(presentTrace,LinkOption.NOFOLLOW_LINKS)
                        && Files.size(presentTrace)<=50000) {
                    presentLog=DiagnosticSanitizer.scrub(
                        new String(Files.readAllBytes(presentTrace),StandardCharsets.UTF_8),
                        40000);
                }
            }catch(Exception ignored){
                presentLog="RM11_V49030_PRESENT_JOURNAL=READ_FAILED";
            }
            write(zip,"wine/v49030-win32-present.log",presentLog);
            // v49038 proves that the game's XInput DLL actually attempted
            // to map shared memory, rather than merely existing in the APK.
            Path xinputTrace=journal.getParent().resolve("last-v49038-xinput-native.log");
            String xinputNative="RM11_V49038_XINPUT_NATIVE_NOT_INVOKED_OR_TRACE_MISSING";
            try {
                if(Files.isRegularFile(xinputTrace,LinkOption.NOFOLLOW_LINKS)
                        && !Files.isSymbolicLink(xinputTrace)
                        && Files.size(xinputTrace)>0 && Files.size(xinputTrace)<20000)
                    xinputNative=DiagnosticSanitizer.scrub(
                        new String(Files.readAllBytes(xinputTrace),StandardCharsets.UTF_8),16000);
            }catch(Exception e) {
                xinputNative="RM11_V49038_XINPUT_NATIVE_TRACE_READ_FAILED";
            }
            write(zip,"game/v49038-xinput-native.log",xinputNative);
            write(zip,"game/last-v49038-controller-status.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v49038-controller-status.json")));
            write(zip,"game/last-v49038-xinput-stage.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v49038-xinput-stage.json")));
            write(zip,"game/last-v49041-touch-input.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v49041-touch-input.json")));
            write(zip,"game/last-v49041-keyboard-transport.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v49041-keyboard-transport.json")));
            write(zip,"game/last-v49041-controller-profile.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v49041-controller-profile.json")));
            write(zip,"game/last-v49042-pad-hotplug.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v49042-pad-hotplug.json")));
            write(zip,"game/last-v49044-winebus-probe.json",
                    safeCrashSnapshot(journal.getParent().resolve("last-v49044-winebus-probe.json")));
            for(String report:new String[]{"last-v49044-sdlbus-native.log",
                                           "last-v49044-win-enumeration.log"}){
                Path candidate=journal.getParent().resolve(report);
                String content="RM11_V49044_REPORT_NOT_FOUND";
                try{
                    if(Files.isRegularFile(candidate,LinkOption.NOFOLLOW_LINKS)
                            && !Files.isSymbolicLink(candidate)
                            && Files.size(candidate)<24000)
                        content=DiagnosticSanitizer.scrub(
                          new String(Files.readAllBytes(candidate),StandardCharsets.UTF_8),12000);
                }catch(Exception ignored){
                    content="RM11_V49044_REPORT_READ_FAILED";
                }
                write(zip,"game/"+report,content);
            }

            // v49032: do not mistake an environment request for DXVK load.
            // Record exactly which CarX process produced native DXVK logs.
            // Absent files remain explicit NOT_FOUND rather than claiming
            // the signed provider was loaded by the selected game.
            for(String api:new String[]{"d3d11","dxgi"}) {
                String detail="RM11_V49032_"+api.toUpperCase(Locale.ROOT)
                        +"_LOG=NOT_FOUND";
                String[] bases={"CarX Street Launcher","CarXStreet",
                        "CarX Street","CarXStreet-Win64-Shipping"};
                for(String base:bases) {
                    Path candidate=journal.getParent().resolve(base+"_"+api+".log");
                    try {
                        if(Files.isRegularFile(candidate,LinkOption.NOFOLLOW_LINKS)
                                &&!Files.isSymbolicLink(candidate)
                                &&Files.size(candidate)>0
                                &&Files.size(candidate)<300000) {
                            detail=DiagnosticSanitizer.scrub(
                                    new String(Files.readAllBytes(candidate),
                                        StandardCharsets.UTF_8),50000);
                            break;
                        }
                    } catch(Exception ignored) {
                        detail="RM11_V49032_"+api.toUpperCase(Locale.ROOT)
                                +"_LOG=READ_FAILED";
                    }
                }
                write(zip,"wine/v49032-carx-"+api+".log",detail);
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
            for(String name:new String[]{"last-game-seh.json","last-game-assertion.json","last-native-abort.json","last-adreno-isolation.json","last-v467-isolation.json","last-graphics-backend.json","last-v472-wsi.json","last-v473-private-vulkan.json","last-v474-x11-surface.json","last-v475-x11-present.json","last-v476-x11-dri3.json","last-v477-x11-swapchain.json","last-v478-x11-software-wsi.json","last-v479-game-wsi.json","last-v480-x11-touch-stability.json","last-v480-touch-pixels.json","last-v482-game-window.json","last-v482-game-window-final.json","last-v482-no-window-trigger.json","last-v482-game-touch-baseline.json","last-v482-game-touch-after.json","last-v483-game-window-recovery.json","last-v484-window-inventory.json","last-v484-first-window-inventory.json","last-v484-window-recovery-decision.json","last-v485-game-launch-args.json","last-v49033-carx-vulkan-route.json","last-v49033-carx-runtime-plan.json","last-v49034-carx-sidecar.json","last-v49034-carx-effective-command.json","last-v486-game-startup-first.json","last-v486-game-startup-final.json","last-v487-game-process-first.json","last-v487-game-process-live.json","last-v487-game-process-final.json","last-v488-wine-native-first.json","last-v488-wine-native-live.json","last-v488-wine-native-final.json","last-v489-native-first.json","last-v489-native-live.json","last-v489-native-final.json"}) {
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
