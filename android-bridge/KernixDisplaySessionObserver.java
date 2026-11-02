package com.winlator.star.kernix;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Log;
import org.json.JSONObject;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Observes only Android XServer display Activity lifecycle. This does NOT
 * measure actual game frames, GPU performance, EXE runtime or game FPS.
 * Never reads game files, Wine prefixes or controller input.
 */
public final class KernixDisplaySessionObserver implements Application.ActivityLifecycleCallbacks {
    private static final String TAG = "KernixSessionObserver";
    private static final long MAX_TRACE_BYTES = 256 * 1024;
    private static volatile boolean installed;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final File log;
    private long openedNanos = -1L;
    private String currentSessionId = null;
    private long sessionSequence = 0L;

    private KernixDisplaySessionObserver(Application app) {
        log = new File(app.getFilesDir(), "kernix-display-lifecycle.jsonl");
    }

    public static synchronized void install(Application app) {
        if (installed) return;
        KernixDisplaySessionObserver observer = new KernixDisplaySessionObserver(app);
        app.registerActivityLifecycleCallbacks(observer);
        installed = true;
    }

    private boolean isDisplay(Activity activity) {
        return "com.winlator.star.XServerDisplayActivity".equals(activity.getClass().getName());
    }

    private void record(String type, long elapsedMs, String sessionId, long sequence) {
        final long monotonic = SystemClock.elapsedRealtimeNanos();
        worker.execute(() -> {
            try {
                JSONObject value = new JSONObject();
                value.put("schema", "kernix.android-display-lifecycle.v1");
                value.put("event", type);
                value.put("session_id", sessionId == null ? JSONObject.NULL : sessionId);
                value.put("event_sequence", sequence);
                value.put("game_process_confirmed", JSONObject.NULL);
                value.put("elapsed_ms", elapsedMs);
                value.put("monotonic_ns", monotonic);
                value.put("frame_count", JSONObject.NULL);
                value.put("game_fps", JSONObject.NULL);
                value.put("game_exe_sha256", JSONObject.NULL);
                value.put("actual_game_started", JSONObject.NULL);
                value.put("source", "Android XServerDisplayActivity lifecycle only");
                byte[] bytes = (value.toString() + "\n").getBytes(StandardCharsets.UTF_8);
                if (log.exists() && log.length() + bytes.length > MAX_TRACE_BYTES)
                    return; // Preserve old diagnostic evidence, never grow unbounded.
                try (FileOutputStream out = new FileOutputStream(log, true)) {
                    out.write(bytes);
                }
            } catch (Exception e) {
                Log.w(TAG, "Optional lifecycle trace unavailable", e);
            }
        });
    }

    @Override public void onActivityResumed(Activity activity) {
        if (!isDisplay(activity)) return;
        // Re-entrant resumes must not overwrite an unfinished timing interval.
        if (openedNanos > 0) return;
        openedNanos = SystemClock.elapsedRealtimeNanos();
        currentSessionId = UUID.randomUUID().toString();
        sessionSequence++;
        record("display_resumed", 0, currentSessionId, sessionSequence);
    }

    @Override public void onActivityPaused(Activity activity) {
        if (!isDisplay(activity)) return;
        long start = openedNanos;
        if (start <= 0) return;
        openedNanos = -1L;
        String endedSessionId = currentSessionId;
        currentSessionId = null;
        sessionSequence++;
        long duration = start > 0
                ? Math.max(0, (SystemClock.elapsedRealtimeNanos() - start) / 1_000_000L)
                : -1L;
        record("display_paused", duration, endedSessionId, sessionSequence);
    }

    @Override public void onActivityCreated(Activity activity, Bundle state) { }
    @Override public void onActivityStarted(Activity activity) { }
    @Override public void onActivityStopped(Activity activity) { }
    @Override public void onActivitySaveInstanceState(Activity activity, Bundle state) { }
    @Override public void onActivityDestroyed(Activity activity) { }
}
