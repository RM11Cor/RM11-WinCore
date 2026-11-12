package com.fh5.port;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Insets;
import android.net.Uri;
import android.os.Bundle;
import android.os.Build;
import android.view.Gravity;
import android.view.WindowInsets;
import android.view.Surface;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import org.json.JSONObject;
import java.io.FileInputStream;
import java.io.OutputStream;
import android.os.ParcelFileDescriptor;
import java.nio.charset.StandardCharsets;
import java.nio.channels.FileChannel;

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
    private boolean x64Busy = false;
    private volatile boolean exeBusy = false;
    private Button realExeButton;
    private JSONObject realExeMetadata = new JSONObject();
    private Button x64Button;
    private JSONObject x64Result = new JSONObject();
    private volatile boolean archiveBusy = false;
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
        if (Build.VERSION.SDK_INT >= 30) {
            root.setOnApplyWindowInsetsListener((v, insets) -> {
                Insets bars = insets.getInsets(WindowInsets.Type.systemBars());
                root.setPadding(dp(14), dp(8) + bars.top,
                        dp(14), dp(10) + bars.bottom);
                return insets;
            });
        }

        TextView title = label("FORZA HORIZON 5", 22, Color.WHITE);
        title.setTypeface(null, android.graphics.Typeface.BOLD);
        title.setGravity(Gravity.CENTER);
        root.addView(title, new LinearLayout.LayoutParams(-1, -2));

        TextView sub = label("FH5 Native Port | P2.2 | Android ARM64", 12, 0xFF72C6FE);
        sub.setGravity(Gravity.CENTER);
        root.addView(sub, new LinearLayout.LayoutParams(-1, -2));

        root.addView(button("اختيار أرشيف اللعبة ZIP", () -> pickArchive()));
        root.addView(button("اختيار مجلد ملفات اللعبة", () -> pickFolder()));

        gameSurface = new SurfaceView(this);
        gameSurface.getHolder().addCallback(this);
        LinearLayout.LayoutParams screen = new LinearLayout.LayoutParams(-1, dp(225));
        screen.setMargins(0, dp(8), 0, dp(8));
        root.addView(gameSurface, screen);

        gpuButton = button("اختبار Vulkan داخل تطبيق فورزا", () -> testGpu());
        gpuButton.setEnabled(false);
        root.addView(gpuButton);
        x64Button = button("اختبار تنفيذ x64 داخل APK — برنامج مصغّر", () -> testX64());
        root.addView(x64Button);
        realExeButton = button("فحص ملف ForzaHorizon5.exe الحقيقي (بدون تشغيل)", () -> testRealExe());
        root.addView(realExeButton);
        Button play = button("تشغيل Forza Horizon 5 — غير متاح بعد", () -> {});
        play.setEnabled(false);
        root.addView(play);
        root.addView(button("تصدير تقرير P2.2", () -> exportReport()));

        status = label("", 13, 0xFFD4E5F8);
        status.setPadding(dp(7), dp(9), dp(7), dp(3));
        root.addView(status, new LinearLayout.LayoutParams(-1, -2));
        ScrollView page = new ScrollView(this);
        page.setFillViewport(false);
        page.setBackgroundColor(0xFF0B1120);
        page.addView(root);
        setContentView(page);
        updateStatus("P2.2: اختَر أرشيف فورزا. ثم افحص PE64 الحقيقي داخل ZIP بدون فك ضغط أو تشغيل اللعبة. اختبارات Vulkan وx64 الصغيرة متاحة أيضاً.");
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
        intent.putExtra(Intent.EXTRA_TITLE, "FH5_PORT_P2_2_REPORT.json");
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
                updateStatus("تم حفظ تقرير P2.2. ارفع ملف FH5_PORT_P2_REPORT.json فقط.");
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
            if (archiveBusy) {
                updateStatus("يوجد فحص جارٍ. اختر الأرشيف بعد اكتماله.");
                return;
            }
            archiveBusy = true;
            final Uri selectedUri = uri;
            prefs.edit().putString(GAME_ARCHIVE, selectedUri.toString()).apply();
            updateStatus("جاري قراءة فهرس ZIP/ZIP64 من الملفات الأصلية... بدون استخراج.");
            Thread worker = new Thread(() -> {
                JSONObject info = new JSONObject();
                String message;
                try (ParcelFileDescriptor pfd =
                        getContentResolver().openFileDescriptor(selectedUri, "r")) {
                    if (pfd == null) throw new java.io.IOException("storage_file_not_available");
                    try (FileInputStream input = new FileInputStream(
                            pfd.getFileDescriptor())) {
                        FileChannel channel = input.getChannel();
                        Zip64Index.Result indexResult = Zip64Index.inspect(channel);
                        info.put("status", "P1_ZIP_INDEXED");
                        info.put("archive_size_bytes", indexResult.archiveBytes);
                        info.put("zip64_central_directory", indexResult.zip64);
                        info.put("central_directory_bytes", indexResult.directoryBytes);
                        info.put("entry_count", indexResult.entries);
                        info.put("file_count", indexResult.files);
                        info.put("folder_entries", indexResult.directories);
                        info.put("forza_exe_name_matches", indexResult.exeMatches);
                        info.put("nested_zip_name_matches", indexResult.nestedZipNames);
                        info.put("potential_data_entries", indexResult.dataEntries);
                        info.put("modelbin_name_matches", indexResult.modelBinNames);
                        info.put("carbin_name_matches", indexResult.carBinNames);
                        info.put("shaderbin_name_matches", indexResult.shaderBinNames);
                        info.put("materialbin_name_matches", indexResult.materialBinNames);
                        info.put("known_unpacked_bytes", indexResult.summedKnownUnpackedBytes);
                        info.put("unknown_unpacked_lengths", indexResult.unknownUnpackedLengths);
                        info.put("central_index_complete", indexResult.entireCentralDirectoryIndexed);
                        info.put("game_file_crc_verified", false);
                        info.put("game_content_complete_verified", false);
                        info.put("game_code_executed", false);
                        info.put("raw_game_bytes_exported", false);
                        info.put("source_path_exported", false);
                        message = "فهرس ZIP جاهز!\n" +
                            "الملفات: " + indexResult.files + "\n" +
                            "ملف تشغيل Forza: " + indexResult.exeMatches + "\n" +
                            "أرشيفات فرعية: " + indexResult.nestedZipNames + "\n" +
                            "بيانات مرشحة: " + indexResult.dataEntries + "\n" +
                            "لم نتحقق من سلامة جميع الملفات أو نشغّل اللعبة بعد.";
                    }
                } catch (Exception ex) {
                    String kind = "storage_read_or_seek_error";
                    if (ex instanceof java.io.IOException) {
                        String err = ex.getMessage();
                        if (err != null && err.startsWith("zip_") &&
                                err.matches("zip_[a-z0-9_]{1,80}")) {
                            kind = err;
                        }
                    }
                    try {
                        info.put("status", "P1_ARCHIVE_SCAN_FAILED");
                        info.put("error_kind", kind);
                        info.put("exception_class", ex.getClass().getSimpleName());
                        info.put("source_path_exported", false);
                        info.put("raw_game_bytes_exported", false);
                    } catch (Exception ignored) { }
                    message = "تعذر قراءة فهرس الأرشيف: " + kind +
                        "\nقد يكون مزود الملفات لا يدعم القراءة العشوائية لملف كبير.";
                }
                final JSONObject completed = info;
                final String viewMessage = message;
                runOnUiThread(() -> {
                    archiveInfo = completed;
                    archiveBusy = false;
                    updateStatus(viewMessage);
                });
            }, "fh5-zip64-index");
            worker.start();
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
    private void testX64() {
        if (x64Busy) return;
        x64Busy=true;
        x64Button.setEnabled(false);
        updateStatus("نجرب تنفيذ تعليمات PE64 مصغرة من داخل تطبيق فورزا نفسه...");
        Thread worker=new Thread(() -> {
            JSONObject result=X64Proof.run();
            runOnUiThread(() -> {
                x64Result=result;
                x64Busy=false;
                x64Button.setEnabled(true);
                boolean passed=result.optBoolean("smoke_result_is_42",false);
                updateStatus("اختبار x64 على ARM64: " + (passed ? "نجح: النتيجة 42" : "لم يجتز الاختبار") +
                    "\nNative status: " + result.optString("status","unknown") +
                    "\nنفذنا برنامج x86-64 اصطناعياً محدوداً، وليس كود Forza Horizon 5.");
            });
        },"fh5-native-x64-proof");
        worker.start();
    }

    private void testRealExe() {
        if (exeBusy || archiveBusy) {
            updateStatus("أكمل فهرسة الأرشيف أولاً قبل اختبار EXE.");
            return;
        }
        String saved=prefs.getString(GAME_ARCHIVE,"");
        if (saved.isEmpty()) {
            updateStatus("أولاً اختر أرشيف Forza ZIP من داخل التطبيق.");
            return;
        }
        exeBusy=true;
        realExeButton.setEnabled(false);
        updateStatus("نفحص PE64 الحقيقي من داخل ZIP64 مباشرةً، دون استخراج أو تنفيذ...");
        Thread worker=new Thread(() -> {
            JSONObject info=new JSONObject();
            String message;
            try (ParcelFileDescriptor pfd=getContentResolver()
                    .openFileDescriptor(Uri.parse(saved),"r")) {
                if(pfd==null)throw new java.io.IOException("zip_document_unavailable");
                try(FileInputStream stream=new FileInputStream(pfd.getFileDescriptor())) {
                    GameExeHeaderProbe.Result r=GameExeHeaderProbe.inspect(stream.getChannel());
                    info.put("stage",r.stage);
                    info.put("status","P2_2_REAL_EXE_HEADER_VERIFIED");
                    info.put("amd64",r.amd64);
                    info.put("pe32plus",r.pe32plus);
                    info.put("machine",r.machine);
                    info.put("sections",r.sections);
                    info.put("subsystem",r.subsystem);
                    info.put("entry_point_rva",r.entryPointRva);
                    info.put("image_size",r.imageSize);
                    info.put("import_directory_rva",r.importDirectoryRva);
                    info.put("import_directory_size",r.importDirectorySize);
                    info.put("import_directory_present",r.importsPresent);
                    info.put("exe_compressed_bytes",r.compressedExeBytes);
                    info.put("exe_unpacked_bytes",r.unpackedExeBytes);
                    info.put("compression_method",r.compressionMethod);
                    info.put("header_bytes_read",r.headerBytesRead);
                    info.put("original_exe_header_read_from_zip",true);
                    info.put("original_exe_code_executed",false);
                    info.put("all_game_files_verified",false);
                    info.put("original_exe_full_crc_verified",false);
                    info.put("raw_exe_bytes_uploaded",false);
                    info.put("file_names_uploaded",false);
                    info.put("private_uri_uploaded",false);
                    message="فحص EXE الحقيقي ناجح!\n" +
                        "PE64 AMD64: نعم\n" +
                        "الحجم داخل الأرشيف: "+r.unpackedExeBytes+" بايت\n" +
                        "عدد أقسام EXE: "+r.sections+"\n" +
                        "جدول الاستيراد موجود: "+(r.importsPresent?"نعم":"لا")+"\n" +
                        "مهم: هذا تحليل ملف فورزا الأصلي، لم ننفذ تعليماته بعد.";
                }
            } catch(Exception ex) {
                String kind="zip_document_or_read_failure";
                if(ex instanceof java.io.IOException) {
                    String raw=ex.getMessage();
                    if(raw!=null && raw.matches("(zip|zip64|pe)_[a-z0-9_]{2,90}"))
                        kind=raw;
                }
                try {
                    info.put("status","P2_2_REAL_EXE_PROBE_FAILED");
                    info.put("error_kind",kind);
                    info.put("exception_class",ex.getClass().getSimpleName());
                    info.put("original_exe_code_executed",false);
                    info.put("raw_exe_bytes_uploaded",false);
                    info.put("private_uri_uploaded",false);
                } catch(Exception ignored) {}
                message="تعذر قراءة رأس EXE الحقيقي: "+kind;
            }
            final JSONObject result=info;
            final String resultMessage=message;
            runOnUiThread(() -> {
                exeBusy=false;
                realExeMetadata=result;
                realExeButton.setEnabled(true);
                updateStatus(resultMessage);
            });
        },"fh5-real-exe-header-probe");
        worker.start();
    }

    private JSONObject buildReport() {
        JSONObject data = new JSONObject();
        try {
            data.put("project", "FH5 Native Port")
                .put("stage", "P2.2")
                .put("application_id", getPackageName())
                .put("native_arm64_apk", true)
                .put("android_sdk", Build.VERSION.SDK_INT)
                .put("device_model", Build.MODEL)
                .put("game_zip_selected", prefs.contains(GAME_ARCHIVE))
                .put("game_folder_selected", prefs.contains(GAME_FOLDER))
                .put("archive_header", archiveInfo)
                .put("vulkan_surface_result", gpuResult)
                .put("synthetic_x64_execution_result", x64Result)
                .put("real_forza_exe_header_result",realExeMetadata)
                .put("x64_translation_component_present", true)
                .put("x64_original_game_executed", false)
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
