package com.r4.carxpc;

import android.app.ActivityManager;
import android.app.ApplicationExitInfo;
import android.content.Context;
import android.os.Build;
import android.util.Base64;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.List;
import java.util.Locale;

/**
 * Read-only extraction of Android's OWN process native tombstone protobuf.
 * Only data already recorded by Android's crash infrastructure is read.
 * No signal handler modifications, no ptrace, no fabricated guest syscall.
 * The caller holds the output locally; no network transfer is performed.
 */
public final class R3D9NativeCrashTrace {
    private static final int MAX_TRACE_BYTES = 1024 * 1024;
    private static final String PROCESS_NAME = R3D4ProbeService.PROCESS_NAME;
    private R3D9NativeCrashTrace(){}

    public static ApplicationExitInfo newest(Context context, long notBeforeMs) {
        if (Build.VERSION.SDK_INT < 30) return null;
        ActivityManager am=(ActivityManager)
            context.getSystemService(Context.ACTIVITY_SERVICE);
        if (am==null) return null;
        ApplicationExitInfo selected=null;
        List<ApplicationExitInfo> records =
            am.getHistoricalProcessExitReasons(context.getPackageName(),0,32);
        for (ApplicationExitInfo record : records) {
            if (record.getReason()!=ApplicationExitInfo.REASON_CRASH_NATIVE)
                continue;
            if (!PROCESS_NAME.equals(record.getProcessName())) continue;
            if (record.getTimestamp()<notBeforeMs) continue;
            if (selected==null ||
                record.getTimestamp()>selected.getTimestamp()) selected=record;
        }
        return selected;
    }

    public static JSONObject extract(ApplicationExitInfo exit) {
        JSONObject out=new JSONObject();
        try {
            out.put("available",false);
            out.put("format","android_native_tombstone_protobuf");
            out.put("source","ApplicationExitInfo.getTraceInputStream");
            out.put("max_capture_bytes",MAX_TRACE_BYTES);
            out.put("uploaded_automatically",false);
            if (exit==null) {
                out.put("reason","NO_MATCHING_EXIT_RECORD");
                return out;
            }
            out.put("exit_pid",exit.getPid());
            out.put("exit_reason",exit.getReason());
            out.put("exit_status_or_signal",exit.getStatus());
            out.put("exit_timestamp_ms",exit.getTimestamp());
            if (Build.VERSION.SDK_INT<31) {
                out.put("reason","NATIVE_TOMBSTONE_REQUIRES_ANDROID_12");
                return out;
            }
            InputStream stream=exit.getTraceInputStream();
            if (stream==null) {
                out.put("reason","ANDROID_TOMBSTONE_NOT_AVAILABLE_OR_OVERWRITTEN");
                return out;
            }
            byte[] raw;
            try (InputStream input=stream;
                 ByteArrayOutputStream bytes=new ByteArrayOutputStream()) {
                byte[] buf=new byte[8192];
                int read;
                while ((read=input.read(buf))!=-1) {
                    if(read==0)continue;
                    if (bytes.size()+read>MAX_TRACE_BYTES) {
                        // Preserve a complete protobuf only: do not supply a
                        // falsely decodable truncated tombstone.
                        out.put("reason","TOMBSTONE_EXCEEDS_CAPTURE_LIMIT");
                        out.put("at_least_bytes",bytes.size()+read);
                        return out;
                    }
                    bytes.write(buf,0,read);
                }
                raw=bytes.toByteArray();
            }
            if (raw.length==0) {
                out.put("reason","TOMBSTONE_EMPTY");
                return out;
            }
            byte[] digest=MessageDigest.getInstance("SHA-256").digest(raw);
            StringBuilder hex=new StringBuilder();
            for (byte b:digest) hex.append(String.format(Locale.ROOT,
                "%02x", b & 0xff));
            out.put("available",true);
            out.put("reason","OK");
            out.put("protobuf_size_bytes",raw.length);
            out.put("protobuf_sha256",hex.toString());
            out.put("protobuf_base64",Base64.encodeToString(raw,Base64.NO_WRAP));
        } catch (Throwable t) {
            try {
                out.put("available",false);
                out.put("reason","TRACE_READ_ERROR_"+
                    t.getClass().getSimpleName());
            } catch (Throwable ignored) {}
        }
        return out;
    }

    public static String displayWithoutBinary(JSONObject data) {
        try {
            JSONObject copy=new JSONObject(data.toString());
            JSONObject trace=copy.optJSONObject("native_crash_tombstone");
            if (trace!=null && trace.has("protobuf_base64")) {
                trace.remove("protobuf_base64");
                trace.put("protobuf_in_saved_json_file_only",true);
            }
            return copy.toString(2);
        } catch (Throwable t) {
            return "REPORT_PREVIEW_ERROR_"+t.getClass().getSimpleName();
        }
    }
}
