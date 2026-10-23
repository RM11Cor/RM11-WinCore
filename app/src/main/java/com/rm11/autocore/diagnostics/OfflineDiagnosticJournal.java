package com.rm11.autocore.diagnostics;

import android.content.Context;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Lightweight on-device test event journal; writes only results produced by RM11.
 * It never performs remote I/O or reads files owned by another Android app.
 */
public final class OfflineDiagnosticJournal {
    private static final int KEEP_EVENTS = 18;
    private static final int MAX_TEXT_PER_EVENT = 11000;
    private static final String TAG = "RM11-Diagnostics";

    private OfflineDiagnosticJournal() {}

    public static synchronized void record(Context context, String test, String report) {
        try {
            Path dir = new File(context.getFilesDir(), "offline-diagnostics").toPath();
            Files.createDirectories(dir);
            Path path = dir.resolve("events.json");
            if (Files.isSymbolicLink(path) || Files.isSymbolicLink(dir)) return;
            JSONArray events = new JSONArray();
            if (Files.isRegularFile(path) && Files.size(path) < 210000) {
                try {
                    events = new JSONArray(Files.readString(path, StandardCharsets.UTF_8));
                } catch (Exception ignored) {
                    events = new JSONArray();
                }
            }
            JSONObject event = new JSONObject();
            event.put("timeUnixMs", System.currentTimeMillis());
            event.put("test", DiagnosticSanitizer.shortLabel(test));
            event.put("result", DiagnosticSanitizer.scrub(report, MAX_TEXT_PER_EVENT));
            JSONArray kept = new JSONArray();
            for (int i = Math.max(0, events.length() - KEEP_EVENTS + 1);
                 i < events.length(); i++) kept.put(events.opt(i));
            kept.put(event);
            Path temp = dir.resolve("events.json.pending");
            if (Files.isSymbolicLink(temp)) return;
            byte[] bytes = kept.toString(2).getBytes(StandardCharsets.UTF_8);
            try (FileOutputStream out = new FileOutputStream(temp.toFile())) {
                out.write(bytes);
                out.getFD().sync();
            }
            Files.move(temp, path, StandardCopyOption.REPLACE_EXISTING);
        } catch (Exception failure) {
            Log.w(TAG, "Unable to save event: " + failure.getClass().getSimpleName());
        }
    }
}
