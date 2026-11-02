package com.winlator.star.kernix;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.ApplicationExitInfo;
import android.os.Build;
import android.content.Context;
import org.json.JSONObject;
import java.util.List;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.FileInputStream;
import java.io.File;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;
import java.util.Locale;

/**
 * KERNIX safe, read-only diagnostic entry point.
 * Uses the system document picker. Does not execute Windows code, install drivers,
 * create Wine prefixes, or modify the selected document.
 */
public final class KernixDiagnosticsActivity extends Activity {
    private static final int PICK_EXE = 5107;
    private static final long MAX_HASH_BYTES = 512L * 1024L * 1024L;
    private static final int MAX_PE_OFFSET = 1024 * 1024;
    private TextView result;
    private Button pick;
    private volatile boolean busy;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout panel = new LinearLayout(this);
        panel.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (20 * getResources().getDisplayMetrics().density);
        panel.setPadding(pad, pad, pad, pad);
        panel.setBackgroundColor(0xff10141c);

        TextView title = new TextView(this);
        title.setText("KERNIX · Safe Game Analyzer");
        title.setTextSize(22);
        title.setTextColor(0xffeaf4ff);
        panel.addView(title);

        TextView detail = new TextView(this);
        detail.setText("اختر ملف EXE لفحصه بدون تشغيل اللعبة. التشخيص الأولي يحدد معمارية الملف فقط؛ لا يختار مكونات ولا يقيس FPS.");
        detail.setTextColor(0xffb2c2d8);
        detail.setTextSize(15);
        detail.setPadding(0, pad, 0, pad);
        panel.addView(detail);

        pick = new Button(this);
        pick.setText("اختيار EXE من الملفات");
        pick.setOnClickListener(v -> chooseExe());
        panel.addView(pick);

        Button viewSessions = new Button(this);
        viewSessions.setText("عرض آخر جلسة وسبب توقف التطبيق");
        viewSessions.setOnClickListener(v -> showDisplaySessions());
        panel.addView(viewSessions);

        Button fullSessions = new Button(this);
        fullSessions.setText("عرض السجل الكامل");
        fullSessions.setOnClickListener(v -> { if (!busy) result.setText(readDisplaySessions()); });
        panel.addView(fullSessions);

        Button shareSessions = new Button(this);
        shareSessions.setText("مشاركة تقرير الجلسات النصي");
        shareSessions.setOnClickListener(v -> shareDisplaySessions());
        panel.addView(shareSessions);

        result = new TextView(this);
        result.setTextColor(0xfff1f5fa);
        result.setTextSize(15);
        result.setTextIsSelectable(true);
        result.setPadding(0, pad, 0, 0);
        result.setText("جاهز للفحص الآمن. لم يتم تشغيل أي لعبة.");

        ScrollView scroll = new ScrollView(this);
        scroll.addView(result);
        panel.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1f));
        setContentView(panel);
    }

    private String readDisplaySessions() {
        File log = new File(getFilesDir(), "kernix-display-lifecycle.jsonl");
        if (!log.exists()) return "لا توجد جلسات عرض مسجلة بعد.\nفتح شاشة EXE للفحص لا يشغّل جلسة Windows.";
        if (!log.isFile() || log.length() > 256 * 1024)
            return "ملف الجلسات غير متاح أو تجاوز الحد المسموح.";
        try {
            String raw = new String(Files.readAllBytes(log.toPath()), StandardCharsets.UTF_8);
            if (raw.isEmpty()) return "سجل الجلسات فارغ.";
            return "KERNIX Display Lifecycle (Android only)\n" +
                    "FPS: غير متوفر — لم يتم قياس إطارات اللعبة\n" +
                    "مكونات اللعبة أثناء التشغيل: غير موثقة\n\n" + raw;
        } catch (Exception e) {
            return "تعذرت قراءة سجل الجلسات: " + e.getClass().getSimpleName();
        }
    }

    private String recentExitReason() {
        if (Build.VERSION.SDK_INT < 30) return "سبب إغلاق عملية Android: النظام لا يدعم API 30";
        try {
            ActivityManager manager = (ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);
            if (manager == null) return "سبب إغلاق العملية: الخدمة غير متاحة";
            List<ApplicationExitInfo> history = manager.getHistoricalProcessExitReasons(getPackageName(), 0, 3);
            if (history == null || history.isEmpty())
                return "سبب إغلاق العملية: لا توجد معلومات محفوظة من Android";
            StringBuilder out = new StringBuilder("أسباب انتهاء عمليات Android السابقة (ليست إثباتاً لسبب إنهاء جلسة Windows):\n");
            for (ApplicationExitInfo info : history) {
                out.append("pid=").append(info.getPid())
                   .append(" reason=").append(info.getReason())
                   .append(" status=").append(info.getStatus())
                   .append(" timestamp=").append(info.getTimestamp()).append('\n');
            }
            return out.toString();
        } catch (Exception ex) {
            return "سبب إغلاق العملية غير متاح: " + ex.getClass().getSimpleName();
        }
    }

    private String lastSessionReport() {
        File file = new File(getFilesDir(), "kernix-display-lifecycle.jsonl");
        if (!file.isFile() || file.length() > 256 * 1024)
            return "ماكو سجل جلسات صالح حالياً.\n" + recentExitReason();
        try {
            String[] lines = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8).split("\\n");
            JSONObject lastStart = null;
            String latestId = null;
            for (String line : lines) {
                if (line.trim().isEmpty()) continue;
                JSONObject e;
                try { e = new JSONObject(line); } catch (Exception ignored) { continue; }
                if ("display_resumed".equals(e.optString("event"))) {
                    latestId = e.optString("session_id", "");
                    lastStart = e;
                }
            }
            if (latestId == null) return "ماكو جلسة عرض مسجلة.\n" + recentExitReason();
            StringBuilder out = new StringBuilder("KERNIX — آخر جلسة عرض\n");
            out.append("session_id: ").append(latestId).append("\n");
            boolean requested = false;
            String closure = "غير مسجل";
            for (String line : lines) {
                if (line.trim().isEmpty()) continue;
                JSONObject e;
                try { e = new JSONObject(line); } catch (Exception ignored) { continue; }
                if (!latestId.equals(e.optString("session_id"))) continue;
                String event = e.optString("event", "");
                out.append(event).append(" · #").append(e.optLong("event_sequence"))
                   .append(" · elapsed_ms=").append(e.optLong("elapsed_ms")).append("\n");
                if ("display_exit_requested".equals(event)) requested = true;
                if ("display_paused".equals(event) || "display_stopped".equals(event) ||
                    "display_destroyed".equals(event) || "display_interrupted".equals(event))
                    closure = event;
            }
            out.append("زر Exit: ").append(requested ? "وصل الطلب" : "لم يُسجل").append("\n");
            out.append("حالة الإغلاق: ").append(closure).append("\n");
            out.append("FPS: غير مقاس · تشغيل EXE: غير موثق\n\n");
            out.append(recentExitReason());
            return out.toString();
        } catch (Exception e) {
            return "تعذر تلخيص آخر جلسة: " + e.getClass().getSimpleName();
        }
    }

    private void showDisplaySessions() {
        if (busy) return;
        result.setText(lastSessionReport());
    }

    private void shareDisplaySessions() {
        if (busy) return;
        String data = readDisplaySessions();
        if (!data.contains("kernix.android-display-lifecycle.v1")) {
            result.setText(data);
            return;
        }
        Intent send = new Intent(Intent.ACTION_SEND);
        send.setType("text/plain");
        send.putExtra(Intent.EXTRA_SUBJECT, "KERNIX Android display session report");
        send.putExtra(Intent.EXTRA_TEXT, data);
        startActivity(Intent.createChooser(send, "مشاركة سجل جلسات KERNIX"));
    }

    private void chooseExe() {
        if (busy) return;
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        startActivityForResult(intent, PICK_EXE);
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != PICK_EXE || resultCode != RESULT_OK || data == null || data.getData() == null || busy)
            return;
        final Uri uri = data.getData();
        if (!"content".equals(uri.getScheme())) {
            result.setText("تم رفض المصدر: نسمح بملفات مختارة من نظام Android فقط.");
            return;
        }
        busy = true;
        pick.setEnabled(false);
        result.setText("جاري قراءة ترويسة Windows PE بدون تنفيذ الملف...");
        new Thread(() -> {
            String message;
            try {
                message = inspect(uri);
            } catch (Exception error) {
                message = "تعذر الفحص بأمان: " + error.getClass().getSimpleName() +
                          "\nقد يكون الملف غير مدعوم أو مزود الملفات لا يسمح بالقراءة العشوائية.";
            }
            final String shown = message;
            runOnUiThread(() -> {
                result.setText(shown);
                busy = false;
                pick.setEnabled(true);
            });
        }, "KERNIX-Static-PE-Inspection").start();
    }

    private byte[] read(FileChannel channel, long offset, int length) throws Exception {
        if (length <= 0 || length > 4096 || offset < 0 || offset + length > channel.size())
            throw new IllegalArgumentException("PE offset outside file");
        ByteBuffer b = ByteBuffer.allocate(length);
        while (b.hasRemaining()) {
            int count = channel.read(b, offset + b.position());
            if (count <= 0) throw new IllegalArgumentException("truncated Windows PE");
        }
        return b.array();
    }

    private String inspect(Uri uri) throws Exception {
        try (ParcelFileDescriptor descriptor = getContentResolver().openFileDescriptor(uri, "r")) {
            if (descriptor == null) throw new IllegalArgumentException("file unavailable");
            try (FileInputStream stream = new FileInputStream(descriptor.getFileDescriptor())) {
                FileChannel channel = stream.getChannel();
                long length = channel.size();
                if (length < 128) throw new IllegalArgumentException("file too short");
                byte[] dos = read(channel, 0, 64);
                if ((dos[0] & 255) != 0x4d || (dos[1] & 255) != 0x5a)
                    throw new IllegalArgumentException("not an MZ executable");
                int offset = ByteBuffer.wrap(dos).order(ByteOrder.LITTLE_ENDIAN).getInt(0x3c);
                if (offset < 64 || offset > MAX_PE_OFFSET || (long) offset + 26 > length)
                    throw new IllegalArgumentException("invalid PE location");
                byte[] pe = read(channel, offset, 26);
                if (pe[0] != 'P' || pe[1] != 'E' || pe[2] != 0 || pe[3] != 0)
                    throw new IllegalArgumentException("not a PE executable");
                ByteBuffer header = ByteBuffer.wrap(pe).order(ByteOrder.LITTLE_ENDIAN);
                int machine = header.getShort(4) & 0xffff;
                int sections = header.getShort(6) & 0xffff;
                int optionalSize = header.getShort(20) & 0xffff;
                int magic = header.getShort(24) & 0xffff;
                if (sections < 1 || sections > 96 || optionalSize < 2 ||
                    (long) offset + 24 + optionalSize + sections * 40L > length)
                    throw new IllegalArgumentException("invalid PE sections");
                if (magic != 0x10b && magic != 0x20b)
                    throw new IllegalArgumentException("unsupported PE format");
                String arch = machine == 0x8664 ? "x86-64" :
                              machine == 0x14c ? "x86 (32-bit)" :
                              machine == 0xaa64 ? "ARM64" : "Unknown";
                String hash = "not calculated (large file)";
                if (length <= MAX_HASH_BYTES) {
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    byte[] buffer = new byte[256 * 1024];
                    long cursor = 0;
                    while (cursor < length) {
                        ByteBuffer chunk = ByteBuffer.wrap(buffer, 0, (int) Math.min(buffer.length, length-cursor));
                        int n = channel.read(chunk, cursor);
                        if (n <= 0) throw new IllegalArgumentException("truncated file during hash");
                        digest.update(buffer, 0, n);
                        cursor += n;
                    }
                    StringBuilder hex = new StringBuilder();
                    for (byte b : digest.digest()) hex.append(String.format(Locale.ROOT, "%02x", b & 255));
                    hash = hex.toString();
                }
                return "KERNIX · Static Report\n\n" +
                       "File size: " + length + " bytes\n" +
                       "CPU architecture: " + arch + "\n" +
                       "PE format: " + (magic == 0x20b ? "PE32+" : "PE32") + "\n" +
                       "Sections: " + sections + "\n" +
                       "SHA-256: " + hash + "\n\n" +
                       "No game launch. No driver changes. No FPS measurement.\n" +
                       "DirectX/DLL compatibility remains unverified in this Android preview.";
            }
        }
    }
}
