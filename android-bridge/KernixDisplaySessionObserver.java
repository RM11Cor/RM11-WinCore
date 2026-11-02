package com.winlator.star.kernix;

import android.app.Activity;
import android.app.Application;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Log;
import org.json.JSONObject;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * Conservative Android-only XServer activity lifecycle journal.
 * Never interprets a displayed surface as a running Windows game or FPS.
 * Small bounded synchronous event writes survive Activity/process teardown;
 * a vanished process is reported as interrupted, never as a clean pause.
 */
public final class KernixDisplaySessionObserver implements Application.ActivityLifecycleCallbacks {
    private static final String TAG = "KernixSessionObserver";
    private static final String PREFS = "kernix-display-session-state";
    private static final long MAX_BYTES = 256 * 1024;
    private static volatile boolean installed;
    private static volatile KernixDisplaySessionObserver activeObserver;
    private final File log;
    private final SharedPreferences state;
    private long openedNanos = -1L;
    private String currentSessionId;
    private long sequence;
    private boolean exitRequested;

    private KernixDisplaySessionObserver(Application app) {
        log = new File(app.getFilesDir(), "kernix-display-lifecycle.jsonl");
        state = app.getSharedPreferences(PREFS, 0);
        // Old builds restarted the counter on every process, so check both disk
        // and preferences to avoid a repeated sequence after a restart.
        sequence = Math.max(state.getLong("sequence", 0), lastDiskSequence());
        String interrupted = state.getString("open_session", null);
        if (interrupted != null && !interrupted.isEmpty()) {
            record("display_interrupted", -1, interrupted);
            state.edit().remove("open_session").commit();
        }
    }

    public static synchronized void install(Application app) {
        if (installed) return;
        KernixDisplaySessionObserver observer = new KernixDisplaySessionObserver(app);
        activeObserver = observer;
        app.registerActivityLifecycleCallbacks(observer);
        installed = true;
    }

    /** Called only from the in-game drawer Exit button, before its existing handler.
     * This is a user intent marker, NOT proof that Windows/game exited. */
    public static void noteExitRequested() {
        KernixDisplaySessionObserver observer = activeObserver;
        if (observer != null) observer.onExitRequest();
    }

    private synchronized void onExitRequest() {
        if (openedNanos <= 0 || currentSessionId == null || exitRequested) return;
        exitRequested = true;
        long elapsed = Math.max(0, (SystemClock.elapsedRealtimeNanos() - openedNanos) / 1_000_000L);
        record("display_exit_requested", elapsed, currentSessionId);
    }

    private long lastDiskSequence() {
        if (!log.isFile() || log.length() > MAX_BYTES) return 0;
        long last = 0;
        try (FileInputStream in = new FileInputStream(log)) {
            byte[] bytes = new byte[(int) log.length()];
            int read = 0, n;
            while (read < bytes.length && (n = in.read(bytes, read, bytes.length - read)) > 0)
                read += n;
            String data = new String(bytes, 0, read, StandardCharsets.UTF_8);
            for (String line : data.split("\n")) {
                try {
                    JSONObject entry = new JSONObject(line);
                    last = Math.max(last, entry.optLong("event_sequence", 0));
                } catch (Exception ignored) { /* Legacy partial records are not rewritten. */ }
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to inspect previous trace sequence", e);
        }
        return last;
    }

    private boolean isDisplay(Activity a) {
        return "com.winlator.star.XServerDisplayActivity".equals(a.getClass().getName());
    }

    private synchronized void record(String event, long durationMs, String sessionId) {
        long next = ++sequence;
        // Persist sequence even when the log has reached its hard cap.
        state.edit().putLong("sequence", next).commit();
        try {
            JSONObject j = new JSONObject();
            j.put("schema", "kernix.android-display-lifecycle.v1");
            j.put("event", event);
            j.put("session_id", sessionId);
            j.put("event_sequence", next);
            j.put("elapsed_ms", durationMs);
            j.put("monotonic_ns", SystemClock.elapsedRealtimeNanos());
            j.put("game_process_confirmed", JSONObject.NULL);
            j.put("game_fps", JSONObject.NULL);
            j.put("frame_count", JSONObject.NULL);
            j.put("game_exe_sha256", JSONObject.NULL);
            j.put("actual_game_started", JSONObject.NULL);
            j.put("source", "Android XServerDisplayActivity lifecycle only");
            byte[] bytes = (j.toString() + "\n").getBytes(StandardCharsets.UTF_8);
            if (log.exists() && log.length() + bytes.length > MAX_BYTES) {
                Log.w(TAG, "Display trace full; journal was not modified");
                return;
            }
            try (FileOutputStream output = new FileOutputStream(log, true)) {
                output.write(bytes);
                output.getFD().sync();
            }
        } catch (Exception e) {
            Log.w(TAG, "Optional display lifecycle trace write failed", e);
        }
    }

    @Override public synchronized void onActivityResumed(Activity a) {
        if (!isDisplay(a) || openedNanos > 0) return;
        openedNanos = SystemClock.elapsedRealtimeNanos();
        currentSessionId = UUID.randomUUID().toString();
        exitRequested = false;
        // An abnormal process termination can now be detected on next launch.
        state.edit().putString("open_session", currentSessionId).commit();
        record("display_resumed", 0, currentSessionId);
    }

    private synchronized void endDisplay(Activity a, String reason) {
        if (!isDisplay(a) || openedNanos <= 0) return;
        long elapsed = Math.max(0, (SystemClock.elapsedRealtimeNanos() - openedNanos) / 1_000_000L);
        openedNanos = -1;
        String finished = currentSessionId;
        currentSessionId = null;
        exitRequested = false;
        // Record the terminal event before clearing the durable pending marker.
        record(reason, elapsed, finished);
        state.edit().remove("open_session").commit();
    }

    @Override public void onActivityPaused(Activity a) { endDisplay(a, "display_paused"); }
    @Override public void onActivityStopped(Activity a) { endDisplay(a, "display_stopped"); }
    @Override public void onActivityDestroyed(Activity a) { endDisplay(a, "display_destroyed"); }
    @Override public void onActivityCreated(Activity a, Bundle state) { }
    @Override public void onActivityStarted(Activity a) { }
    @Override public void onActivitySaveInstanceState(Activity a, Bundle state) { }
}
