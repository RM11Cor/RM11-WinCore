package com.fh5.port;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.os.Build;
import android.view.Gravity;
import android.view.Surface;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import org.json.JSONObject;
import java.io.FileInputStream;
import java.io.OutputStream;
import android.os.ParcelFileDescriptor;
import java.nio.charset.StandardCharsets;

/**
 * A standalone Forza Horizon 5 APK entry point (P0 native surface gate).
 * Never implies the actual game is executable until the runtime is linked.
 */
public final class MainActivity extends Activity implements SurfaceHolder.Callback {
    private static final int SELECT_ARCHIVE = 110;
    private static final int SELECT_FOLDER = 111;
    private static final int EXPORT_REPORT = 112;
    private static final String PREFS = "fh5_native_port";
    private static final String GAME_ARCHIVE = "game_archive";
    private static final String GAME_FOLDER = "game_folder";
    private SurfaceView gameSurface;
    private Button gpuButton;
    private TextView status;
    private boolean surfaceReady = false;
    private boolean gpuBusy = false;
    private JSONObject gpuResult = new JSONObject();
    private JSONObject archiveInfo = new JSONObject();
    private SharedPreferences prefs;

    @Override public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        getWindow().setStatusBarColor(0xFF0B1120);
        getWindow().setNavigationBarColor(0xFF0B1120);
        prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(0xFF0B1120);
        root.setPadding(dp(14), dp(8), dp(14), dp(10));

        TextView title = label("FORZA HORIZON 5", 22, Color.WHITE);
        title.setTypeface(null, android.graphics.Typeface.BOLD);
        title.setGravity(Gravity.CENTER);
        root.addView(title, new LinearLayout.LayoutParams(-1, -2));

        TextView sub = label("FH5 Native Port | P0 | Android ARM64", 12, 0xFF72C6FE);
        sub.setGravity(Gravity.CENTER);
        root.addView(sub, new LinearLayout.LayoutParams(-1, -2));

        root.addView(button("اختيار أرشيف اللعبة ZIP", () -> pickArchive()));
        root.addView(button("اختيار مجلد ملفات اللعبة", () -> pickFolder()));

        gameSurface = new SurfaceView(this);
        gameSurface.getHolder().addCallback(this);
        LinearLayout.LayoutParams screen = new LinearLayout.LayoutParams(-1, 0, 1f);
        screen.setMargins(0, dp(8), 0, dp(8));
        root.addView(gameSurface, screen);

        gpuButton = button("اختبار Vulkan داخل تطبيق فورزا", () -> testGpu());
        gpuButton.setEnabled(false);
        root.addView(gpuButton);
        Button play = button("تشغيل Forza Horizon 5 — غير متاح بعد", () -> {});
        play.setEnabled(false);
        root.addView(play);
        root.addView(button("تصدير تقرير P0", () -> exportReport()));

        status = label("", 13, 0xFFD4E5F8);
        status.setPadding(dp(7), dp(9), dp(7), dp(3));
        root.addView(status, new LinearLayout.LayoutParams(-1, -2));
        setContentView(root);
        updateStatus("هذا أول APK مستقل للمشروع. حتى الآن يُظهر سطح Vulkan ويختار ملفات اللعبة فقط. تشغيل عالم فورزا لم يُبنَ بعد.");
    }

    private int dp(int v) {
        return Math.round(getResources().getDisplayMetrics().density * v);
    }
    private TextView label(String s, int size, int color) {
        TextView t = new TextView(this);
        t.setText(s); t.setTextColor(color); t.setTextSize(size);
        return t;
    }
    private Button button(String caption, Runnable cb) {
        Button b = new Button(this);
        b.setText(caption);
        b.setTextColor(Color.WHITE);
        b.setAllCaps(false);
        b.setOnClickListener(v -> cb.run());
        return b;
    }
    private void updateStatus(String text) {
        if (status != null) status.setText(text);
    }
    private void pickArchive() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION |
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        startActivityForResult(intent, SELECT_ARCHIVE);
    }
    private void pickFolder() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION |
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        startActivityForResult(intent, SELECT_FOLDER);
    }
    private void exportReport() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/json");
        intent.putExtra(Intent.EXTRA_TITLE, "FH5_PORT_P0_REPORT.json");
        startActivityForResult(intent, EXPORT_REPORT);
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (result != RESULT_OK || data == null || data.getData() == null) return;
        Uri uri = data.getData();
        if (request == EXPORT_REPORT) {
            try (OutputStream o = getContentResolver().openOutputStream(uri, "wt")) {
                if (o == null) throw new IllegalStateException("null output stream");
                o.write(buildReport().toString(2).getBytes(StandardCharsets.UTF_8));
                updateStatus("تم حفظ تقرير P0. ارفع ملف FH5_PORT_P0_REPORT.json فقط.");
            } catch (Exception e) {
                updateStatus("فشل حفظ التقرير: " + e.getClass().getSimpleName());
            }
            return;
        }
        try {
            getContentResolver().takePersistableUriPermission(
                uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
        } catch (SecurityException ignored) { }
        if (request == SELECT_ARCHIVE) {
            boolean zip = false;
            long length = -1;
            try (ParcelFileDescriptor pfd = getContentResolver()
                    .openFileDescriptor(uri, "r")) {
                if (pfd == null) throw new IllegalStateException("null descriptor");
                length = pfd.getStatSize();
                byte[] head = new byte[4];
                try (FileInputStream input = new FileInputStream(pfd.getFileDescriptor())) {
                    int count = input.read(head);
                    zip = count == 4 && head[0] == 'P' && head[1] == 'K'
                        && ((head[2] == 3 && head[3] == 4) ||
                            (head[2] == 5 && head[3] == 6) ||
                            (head[2] == 7 && head[3] == 8));
                }
            } catch (Exception e) {
                updateStatus("تعذر الوصول إلى الأرشيف: " + e.getClass().getSimpleName());
                return;
            }
            try {
                archiveInfo = new JSONObject()
                    .put("zip_magic_verified", zip)
                    .put("archive_size_bytes", length)
                    .put("contents_verified", false);
            } catch (Exception ignored) { }
            if (zip) {
                prefs.edit().putString(GAME_ARCHIVE, uri.toString()).apply();
                updateStatus("تعرفنا على توقيع ZIP. محفوظ موقع الأرشيف دون نسخه. هذا لا يثبت اكتمال اللعبة.");
            } else {
                updateStatus("الملف المحدد ليس ZIP بالتوقيع المعروف. لم نعتمده.");
            }
        } else if (request == SELECT_FOLDER) {
            prefs.edit().putString(GAME_FOLDER, uri.toString()).apply();
            updateStatus("تم حفظ إذن مجلد اللعبة. ما زال يحتاج فحص المحتويات وربطه بمحرك التشغيل.");
        }
    }

    private void testGpu() {
        if (gpuBusy || !surfaceReady) return;
        gpuBusy = true;
        gpuButton.setEnabled(false);
        updateStatus("يُجري التطبيق اختبار عرض Vulkan مباشر على GPU...");
        final Surface surface = gameSurface.getHolder().getSurface();
        Thread thread = new Thread(() -> {
            JSONObject r = VulkanBridge.test(surface);
            runOnUiThread(() -> {
                gpuBusy = false;
                gpuResult = r;
                gpuButton.setEnabled(surfaceReady);
                String result = r.optBoolean("success", false) ? "نجح" : "فشل";
                updateStatus("اختبار Vulkan: " + result +
                    "\nGPU: " + r.optString("gpu", "unknown") +
                    "\nStage: " + r.optString("stage", "unknown") +
                    "\nFrames: " + r.optInt("frames", 0) +
                    "\nهذا اختبار Vulkan مستقل، وليس تشغيل لعبة Forza بعد.");
            });
        }, "fh5-native-vulkan");
        thread.start();
    }
    private JSONObject buildReport() {
        JSONObject data = new JSONObject();
        try {
            data.put("project", "FH5 Native Port")
                .put("stage", "P0")
                .put("application_id", getPackageName())
                .put("native_arm64_apk", true)
                .put("android_sdk", Build.VERSION.SDK_INT)
                .put("device_model", Build.MODEL)
                .put("game_zip_selected", prefs.contains(GAME_ARCHIVE))
                .put("game_folder_selected", prefs.contains(GAME_FOLDER))
                .put("archive_header", archiveInfo)
                .put("vulkan_surface_result", gpuResult)
                .put("game_code_loaded", false)
                .put("wine_fex_embedded", false)
                .put("game_playable", false)
                .put("external_emulator_invoked", false)
                .put("game_bytes_uploaded", false)
                .put("private_uri_uploaded", false);
        } catch (Exception ignored) { }
        return data;
    }
    @Override public void surfaceCreated(SurfaceHolder holder) {
        surfaceReady = true;
        if (gpuButton != null) gpuButton.setEnabled(!gpuBusy);
    }
    @Override public void surfaceChanged(SurfaceHolder holder, int f, int w, int h) {
        surfaceReady = w > 0 && h > 0;
        if (gpuButton != null) gpuButton.setEnabled(surfaceReady && !gpuBusy);
    }
    @Override public void surfaceDestroyed(SurfaceHolder holder) {
        surfaceReady = false;
        if (gpuButton != null) gpuButton.setEnabled(false);
    }
}
