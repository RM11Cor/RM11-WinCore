package com.rm11.autocore.bridge;

import android.content.Context;
import android.os.Build;
import android.util.Log;
import com.rm11.autocore.runtime.RuntimeLayout;
import org.json.JSONObject;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.AtomicMoveNotSupportedException;

/**
 * Local-only RM11 DirectBridge stage 1. Does NOT send telemetry, start a server,
 * execute shell commands or provide a remote device connection.
 */
public final class DirectBridgeDiagnostics {
    private static final String TAG = "RM11-DirectBridge";
    private static final String DIRECTORY = "directbridge";
    private static final String FILE = "last-wine-smoke.json";
    private static final int MAX_LOG_CHARS = 131072;

    private DirectBridgeDiagnostics() {}

    private static Path folder(Context context) {
        return new File(context.getFilesDir(), DIRECTORY).toPath();
    }

    private static boolean regularFile(Path file) {
        return Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS);
    }

    private static String scrub(String data) {
        String limited = data == null ? "" : data.substring(0, Math.min(data.length(), MAX_LOG_CHARS));
        // Defensive masking before persistence; extra redaction is required before remote transfer.
        return limited.replaceAll(
                "(?i)(\\b(?:authorization|password|passwd|token|secret|cookie)\\b\\s*[:=]\\s*)[^\\s\\r\\n]+",
                "$1[REDACTED]");
    }

    private static JSONObject runtime(Context context) throws Exception {
        RuntimeLayout p = new RuntimeLayout(context.getFilesDir().toPath(),
                new File(context.getApplicationInfo().nativeLibraryDir).toPath());
        JSONObject files = new JSONObject();
        files.put("wineServerNativeArm64Present", regularFile(p.nativeWineServer));
        files.put("wineLauncherNativeArm64Present", regularFile(p.nativeWineLauncher));
        files.put("wineNtdllNativePresent", regularFile(p.nativeNtdll));
        files.put("fexArm64EcPresent", regularFile(p.fexArm64ec()));
        files.put("fexWow64Present", regularFile(p.fexWow64()));
        files.put("wineNlsInternationalPresent", regularFile(p.wineNls));
        files.put("wineNlsLocalePresent", regularFile(p.wineNls.resolveSibling("locale.nls")));
        files.put("winePrefixMarkerPresent", regularFile(p.winePrefixMarker()));
        files.put("winePrefixSystem32Present", Files.isDirectory(p.winePrefix.resolve("drive_c/windows/system32")));
        files.put("nativeNlsRedirectPresent", regularFile(p.apkNativeLibs.resolve("librm11_wine_data_redirect.so")));
        files.put("childReexecVerified", false);
        files.put("gameExecutionVerified", false);
        return files;
    }

    /** Persist the last completed Wine run inside this app's private data. No network I/O. */
    public static boolean recordSmoke(Context context, String resultText) {
        Path pending = null;
        try {
            Files.createDirectories(folder(context));
            Path dir = folder(context);
            Path target = dir.resolve(FILE);
            pending = dir.resolve(FILE + ".pending");
            if (Files.isSymbolicLink(dir) || Files.isSymbolicLink(target) || Files.isSymbolicLink(pending))
                throw new IllegalStateException("Refusing symlink in diagnostic store");
            String clean = scrub(resultText);
            DirectBridgeFailure.Finding finding = DirectBridgeFailure.analyze(clean);
            JSONObject record = new JSONObject();
            record.put("schema", "rm11.directbridge.smoke.v1");
            record.put("capturedAtUnixMs", System.currentTimeMillis());
            record.put("transportConnected", false);
            record.put("resultCode", finding.code);
            record.put("rootCauseConfirmed", false);
            record.put("summary", finding.summary);
            record.put("evidenceExcerpt", finding.evidence);
            record.put("wineServerAliveAtClientExit", clean.contains("Server at client exit: ALIVE"));
            record.put("nlsRedirectObserved", clean.contains("Native NLS redirect observed: YES"));
            record.put("uiCaptureTruncated", clean.contains("[LOG TRUNCATED") || clean.contains("[LOG MIDDLE OMITTED"));
            record.put("runtimeFiles", runtime(context));
            record.put("wineReport", clean);
            byte[] encoded = record.toString().getBytes(StandardCharsets.UTF_8);
            try (FileOutputStream out = new FileOutputStream(pending.toFile(), false)) {
                out.write(encoded);
                out.getFD().sync();
            }
            try {
                Files.move(pending, target, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException ex) {
                Files.move(pending, target, StandardCopyOption.REPLACE_EXISTING);
            }
            return true;
        } catch (Exception ex) {
            Log.w(TAG, "Unable to persist local diagnostic: " + ex.getClass().getSimpleName());
            if (pending != null) {
                try { Files.deleteIfExists(pending); } catch (Exception ignored) { }
            }
            return false;
        }
    }

    /** App-local view. A future authenticated tool can expose only an approved subset. */
    public static String localStatus(Context context) {
        try {
            JSONObject status = new JSONObject();
            status.put("bridge", "RM11 DirectBridge stage 1");
            status.put("connection", "NOT_CONNECTED");
            status.put("remoteAccessEnabled", false);
            status.put("backgroundTelemetryEnabled", false);
            status.put("shellExecutionEnabled", false);
            status.put("appPackage", context.getPackageName());
            status.put("androidApi", Build.VERSION.SDK_INT);
            status.put("supportedAbis", new org.json.JSONArray(java.util.Arrays.asList(Build.SUPPORTED_ABIS)));
            status.put("currentRuntimeFiles", runtime(context));
            Path latest = folder(context).resolve(FILE);
            if (regularFile(latest) && Files.size(latest) <= 300000) {
                JSONObject record = new JSONObject(new String(Files.readAllBytes(latest), StandardCharsets.UTF_8));
                record.remove("wineReport"); // Keep full report private; show concise evidence on screen.
                status.put("lastWineSmoke", record);
            } else {
                status.put("lastWineSmoke", "No saved run. Use the WineServer test once after installing a future APK.");
            }
            return status.toString(2);
        } catch (Exception ex) {
            return "RM11 DirectBridge local diagnostic unavailable: " + ex.getClass().getSimpleName()
                    + ". No remote connection was attempted.";
        }
    }
}
