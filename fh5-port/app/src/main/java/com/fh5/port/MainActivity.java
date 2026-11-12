package com.fh5.port;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Insets;
import android.net.Uri;
import android.database.Cursor;
import android.provider.OpenableColumns;
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
import org.json.JSONArray;
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
    private static final int SELECT_DIRECT_EXE = 113;
    private static final String PREFS = "fh5_native_port";
    private static final String GAME_ARCHIVE = "game_archive";
    private static final String GAME_FOLDER = "game_folder";
    private static final String GAME_DIRECT_EXE = "direct_forza_exe";
    private static final String AUTO_EXE_FROM_FOLDER = "direct_exe_from_folder";
    private SurfaceView gameSurface;
    private Button gpuButton;
    private TextView status;
    private boolean surfaceReady = false;
    private boolean gpuBusy = false;
    private boolean x64Busy = false;
    private volatile boolean exeBusy = false;
    private volatile boolean entryBusy = false;
    private Button entryButton;
    private JSONObject actualEntryProbe = new JSONObject();
    private Button realExeButton;
    private Button importButton;
    private volatile boolean importBusy=false;
    private JSONObject peImportsResult=new JSONObject();
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

        TextView sub = label("FH5 Native Port | P3.7 | Android ARM64", 12, 0xFF72C6FE);
        sub.setGravity(Gravity.CENTER);
        root.addView(sub, new LinearLayout.LayoutParams(-1, -2));

        root.addView(button("اختيار مجلد فورزا المستخرج (يكتشف EXE تلقائياً)", () -> pickFolder()));
        root.addView(button("اختيار EXE مباشرة (إذا ظهر في الملفات)", () -> pickDirectExe()));
        root.addView(button("اختيار أرشيف اللعبة ZIP (بديل)", () -> pickArchive()));

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
        realExeButton = button("فحص رأس ForzaHorizon5.exe الحقيقي (بدون تشغيل)", () -> testRealExe());
        root.addView(realExeButton);
        importButton=button("فحص دوال Windows وملفات DLL المحلية", () -> testPeImports());
        root.addView(importButton);
        entryButton = button("تحليل Forza EXE مباشرة (بدون تشغيل)", () -> testActualEntry());
        root.addView(entryButton);
        Button play = button("تشغيل Forza Horizon 5 — غير متاح بعد", () -> {});
        play.setEnabled(false);
        root.addView(play);
        root.addView(button("تصدير تقرير P3.7", () -> exportReport()));

        status = label("", 13, 0xFFD4E5F8);
        status.setPadding(dp(7), dp(9), dp(7), dp(3));
        root.addView(status, new LinearLayout.LayoutParams(-1, -2));
        ScrollView page = new ScrollView(this);
        page.setFillViewport(false);
        page.setBackgroundColor(0xFF0B1120);
        page.addView(root);
        setContentView(page);
        updateStatus("P3.7: نعالج أسماء ++C الطويلة ونفحص دوال Windows المكتوبة داخل EXE مع ترويسات DLL الست. دون تشغيل اللعبة.");
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
    private void pickDirectExe() {
        Intent intent=new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION |
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        startActivityForResult(intent,SELECT_DIRECT_EXE);
    }
    private void pickFolder() {
        if(archiveBusy || entryBusy || exeBusy || importBusy) {
            updateStatus("فحص آخر شغال، اختَر المجلد بعد انتهائه.");
            return;
        }
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION |
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        startActivityForResult(intent, SELECT_FOLDER);
    }
    private void exportReport() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/json");
        intent.putExtra(Intent.EXTRA_TITLE, "FH5_PORT_P3_7_REPORT.json");
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
                updateStatus("تم حفظ تقرير P3.7. ارفع FH5_PORT_P3_7_REPORT.json فقط.");
            } catch (Exception e) {
                updateStatus("فشل حفظ التقرير: " + e.getClass().getSimpleName());
            }
            return;
        }
        try {
            getContentResolver().takePersistableUriPermission(
                uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
        } catch (SecurityException ignored) { }
        if (request == SELECT_DIRECT_EXE) {
            if(archiveBusy || entryBusy || exeBusy) {
                updateStatus("انتظر انتهاء الفحص الحالي قبل اختيار ملف EXE.");
                return;
            }
            String displayName="";
            try(Cursor cursor=getContentResolver().query(uri,
                     new String[]{OpenableColumns.DISPLAY_NAME},null,null,null)) {
                if(cursor!=null && cursor.moveToFirst()) {
                    int column=cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    if(column>=0)displayName=cursor.getString(column);
                }
            } catch(Exception ignored) { }
            if(displayName==null ||
               !"ForzaHorizon5.exe".equalsIgnoreCase(displayName)) {
                updateStatus("اختَر ملف ForzaHorizon5.exe نفسه من المجلد المستخرج.");
                return;
            }
            prefs.edit().putString(GAME_DIRECT_EXE,uri.toString())
                .putBoolean(AUTO_EXE_FROM_FOLDER,false).apply();
            updateStatus("تم اختيار EXE المستخرج. صار الفحص يقرأ الملف مباشرة بدون ZIP. اضغط فحص التعليمات.");
            return;
        }
        if (request == SELECT_ARCHIVE) {
            if (archiveBusy) {
                updateStatus("يوجد فحص جارٍ. اختر الأرشيف بعد اكتماله.");
                return;
            }
            archiveBusy = true;
            final Uri selectedUri = uri;
            prefs.edit().putString(GAME_ARCHIVE, selectedUri.toString())
                .remove(GAME_DIRECT_EXE).putBoolean(AUTO_EXE_FROM_FOLDER,false).apply();
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
            if(archiveBusy || exeBusy || entryBusy || importBusy) {
                updateStatus("فحص آخر شغال. اختَر مجلد فورزا بعد انتهاء الفحص.");
                return;
            }
            // User-granted tree access includes descendant documents even if
            // Android's single-file picker hides .exe extensions.
            prefs.edit().putString(GAME_FOLDER,uri.toString()).apply();
            archiveBusy=true;
            updateStatus("جاري العثور على ForzaHorizon5.exe داخل المجلد المحدد بدون نسخ أو تعديل...");
            final Uri treeUri=uri;
            Thread discover=new Thread(() -> {
                String message;
                try {
                    SafGameFolderProbe.Found found=SafGameFolderProbe.find(
                        getContentResolver(),treeUri);
                    prefs.edit()
                        .putString(GAME_DIRECT_EXE,found.documentUri.toString())
                        .putBoolean(AUTO_EXE_FROM_FOLDER,true).apply();
                    message="✅ تم العثور على ForzaHorizon5.exe تلقائياً!"
                        +"\nحجم الملف: "+found.byteSize+" بايت"
                        +"\nالفحص الآن يستخدم EXE مباشرة بدون ZIP."
                        +"\nاضغط تحليل Forza EXE مباشرة (بدون تشغيل).";
                } catch(Exception ex) {
                    String reason=ex.getMessage();
                    if(reason==null ||
                       !reason.matches("(saf|pe)_[a-z0-9_]{2,90}"))
                        reason="saf_folder_read_or_provider_failure";
                    prefs.edit().remove(GAME_DIRECT_EXE)
                        .putBoolean(AUTO_EXE_FROM_FOLDER,false).apply();
                    message="تعذّر اكتشاف EXE من المجلد: "+reason
                        +"\nحدد مجلد Forza Horizon 5 الداخلي نفسه، مو Downloads.";
                }
                final String discoveredStatusMessage=message;
                runOnUiThread(() -> {
                    archiveBusy=false;
                    updateStatus(discoveredStatusMessage);
                });
            },"fh5-extracted-folder-saf-discovery");
            discover.start();
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
        if (exeBusy || archiveBusy || importBusy) {
            updateStatus("أكمل فهرسة الأرشيف أولاً قبل اختبار EXE.");
            return;
        }
        boolean directMode=!prefs.getString(GAME_DIRECT_EXE,"").isEmpty();
        String saved=directMode?prefs.getString(GAME_DIRECT_EXE,""):
            prefs.getString(GAME_ARCHIVE,"");
        if (saved.isEmpty()) {
            updateStatus("اختَر EXE المستخرج أو أرشيف Forza ZIP من داخل التطبيق.");
            return;
        }
        exeBusy=true;
        realExeButton.setEnabled(false);
        updateStatus(directMode?"نفحص PE64 المستخرج مباشرةً بدون ZIP أو تنفيذ...":
            "نفحص PE64 من داخل ZIP64 دون استخراج أو تنفيذ...");
        Thread worker=new Thread(() -> {
            JSONObject info=new JSONObject();
            String message;
            try (ParcelFileDescriptor pfd=getContentResolver()
                    .openFileDescriptor(Uri.parse(saved),"r")) {
                if(pfd==null)throw new java.io.IOException("zip_document_unavailable");
                try(FileInputStream stream=new FileInputStream(pfd.getFileDescriptor())) {
                    GameCodeSource codeSource=new GameCodeSource(stream.getChannel(),directMode);
                    GameExeHeaderProbe.Result r=codeSource.inspectHeader();
                    info.put("stage",r.stage);
                    info.put("code_source",codeSource.kind());
                    info.put("direct_random_access_mode",directMode);
                    info.put("source_file_size_bytes",stream.getChannel().size());
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


    /** P2.3 original-game entrypoint sample: read and translation-only.
     * No executable game mapping or launch is allowed by this feature. */

    /** Strict read-only one-hop PE branch target check, no native code execution. */
    private JSONObject probeBranchRva(GameCodeSource codeSource,long targetRva,long imageSize) {
        JSONObject output=new JSONObject();
        try {
            if(targetRva<=0 || targetRva>=imageSize) {
                output.put("status","BRANCH_TARGET_NOT_DIRECT_OR_OUTSIDE_IMAGE");
                return output;
            }
            GameExeHeaderProbe.EntryResult sample=
                codeSource.inspectAtRva(targetRva,128);
            JSONObject parsed=X86Disasm.inspect(sample.entrySample,
                targetRva,sample.pe.imageSize);
            output.put("status",parsed.optString("status","unknown").equals("decoded")
                ?"EXECUTABLE_TARGET_SECTION_DECODED":"TARGET_DECODE_FAILED");
            output.put("target_rva",targetRva);
            output.put("section_index",sample.sectionIndex);
            output.put("sampled_bytes",sample.sampleLength);
            output.put("decoded_instruction_count",parsed.optInt("decoded_instruction_count",0));
            output.put("first_basic_block_mnemonics",
                parsed.optJSONArray("first_basic_block_mnemonics"));
            output.put("first_transfer_kind",parsed.optString("first_transfer_kind","none"));
            output.put("first_transfer_target_kind",
                parsed.optString("first_transfer_target_kind","none"));
            if(parsed.optBoolean("first_transfer_target_within_exe_image",false)
                && !parsed.isNull("first_transfer_target_rva"))
                output.put("first_transfer_target_rva",
                    parsed.optLong("first_transfer_target_rva",-1));
            // Expose only structural metadata for the next JNE.
            output.put("conditional_two_successors",
                parsed.optBoolean("conditional_two_successors",false));
            if(parsed.optBoolean("conditional_two_successors",false)) {
                output.put("conditional_not_taken_rva",
                    parsed.optLong("conditional_not_taken_rva",-1));
                output.put("not_taken_next_mnemonic",
                    parsed.optString("not_taken_next_mnemonic","none"));
                output.put("not_taken_next_is_jump",
                    parsed.optBoolean("not_taken_next_is_jump",false));
                output.put("not_taken_jump_target_kind",
                    parsed.optString("not_taken_jump_target_kind","none"));
                if(!parsed.isNull("not_taken_jump_target_rva"))
                    output.put("not_taken_jump_target_rva",
                        parsed.optLong("not_taken_jump_target_rva",-1));
            }
            output.put("sample_compressed_bytes_read",sample.compressedBytesRead);
        } catch(java.io.IOException ex) {
            String reason=ex.getMessage();
            if(reason==null || !reason.matches("(pe|zip|zip64)_[a-z0-9_]{2,90}"))
                reason="bounded_read_or_section_error";
            try {
                output.put("status","TARGET_UNMAPPED_OR_UNAVAILABLE");
                output.put("reason",reason);
            } catch(Exception ignored) { }
        } catch(Exception ex) {
            try {
                output.put("status","TARGET_ANALYSIS_ERROR");
                output.put("exception_class",ex.getClass().getSimpleName());
            } catch(Exception ignored) { }
        }
        try {
            output.put("game_code_executed",false);
            output.put("raw_game_bytes_exported",false);
        } catch(Exception ignored) { }
        return output;
    }


    /** P3.1: strictly two static successor probes of the second JNE.
     * A decoded target is NOT a branch executed on the user's device. */
    private JSONObject inspectPostJoinJne(GameCodeSource codeSource,JSONObject callTarget,
                                           long imageSize,long callRva) {
        JSONObject out=new JSONObject();
        try {
            out.put("stage","P3_1_SECOND_JNE_STATIC_SUCCESSORS");
            out.put("original_game_code_executed",false);
            out.put("runtime_condition_evaluated",false);
            out.put("raw_game_bytes_exported",false);
            out.put("max_extra_successor_probes",PostJoinBranch.MAX_SUCCESSOR_PROBES);
            out.put("max_sample_bytes_per_successor",
                PostJoinBranch.SAMPLE_BYTES_PER_SUCCESSOR);
            if(!"EXECUTABLE_TARGET_SECTION_DECODED".equals(
                 callTarget.optString("status","")) ||
               !"conditional_jump".equals(callTarget.optString("first_transfer_kind","")) ||
               !"direct".equals(callTarget.optString("first_transfer_target_kind","")) ||
               !callTarget.optBoolean("conditional_two_successors",false)) {
                out.put("status","SECOND_JNE_NOT_CONFIRMED_DIRECT");
                return out;
            }
            long takenRva=callTarget.optLong("first_transfer_target_rva",-1);
            long fallthroughRva=callTarget.optLong("conditional_not_taken_rva",-1);
            out.put("status","SECOND_JNE_STATIC_BRANCH_TARGETS_CLASSIFIED");
            out.put("source_call_function_rva",callRva);
            out.put("taken_rva",
                JumpJoin.inImage(takenRva,imageSize)?takenRva:JSONObject.NULL);
            out.put("not_taken_fallthrough_rva",
                JumpJoin.inImage(fallthroughRva,imageSize)?fallthroughRva:JSONObject.NULL);
            out.put("static_successor_pair",
                PostJoinBranch.classifyPair(takenRva,fallthroughRva,imageSize));
            out.put("not_taken_next_instruction",
                callTarget.optString("not_taken_next_mnemonic","none"));
            out.put("not_taken_adjacent_direct_jump",
                callTarget.optBoolean("not_taken_next_is_jump",false)
                && "direct".equals(callTarget.optString("not_taken_jump_target_kind","")));
            if(callTarget.optBoolean("not_taken_next_is_jump",false)
               && "direct".equals(callTarget.optString("not_taken_jump_target_kind",""))
               && JumpJoin.inImage(callTarget.optLong("not_taken_jump_target_rva",-1),imageSize))
                out.put("not_taken_adjacent_jump_target_rva",
                    callTarget.optLong("not_taken_jump_target_rva",-1));
            String t=PostJoinBranch.classifyTarget(takenRva,imageSize,callRva,-1);
            JSONObject takenNode=new JSONObject();
            if("SAFE_DIRECT_IN_IMAGE_TARGET".equals(t)) {
                takenNode=probeBranchRva(codeSource,takenRva,imageSize);
            } else takenNode.put("status",t);
            out.put("taken_target",takenNode);
            String f=PostJoinBranch.classifyTarget(
                fallthroughRva,imageSize,callRva,takenRva);
            JSONObject notTakenNode=new JSONObject();
            if("SAFE_DIRECT_IN_IMAGE_TARGET".equals(f)) {
                notTakenNode=probeBranchRva(codeSource,fallthroughRva,imageSize);
            } else notTakenNode.put("status",f);
            out.put("not_taken_fallthrough",notTakenNode);
            out.put("successor_probes_completed",
                ("SAFE_DIRECT_IN_IMAGE_TARGET".equals(t)?1:0)+
                ("SAFE_DIRECT_IN_IMAGE_TARGET".equals(f)?1:0));
            out.put("no_recursive_followups",true);
        } catch(Exception ex) {
            try {
                out.put("status","POST_JOIN_JNE_PROBE_FAILED");
                out.put("exception_class",ex.getClass().getSimpleName());
                out.put("original_game_code_executed",false);
            } catch(Exception ignored) { }
        }
        return out;
    }

    /** Only an explicitly direct in-image JMP target can be followed. */
    private long eligibleNextJumpRva(JSONObject node,long imageSize) {
        if(node==null || !"EXECUTABLE_TARGET_SECTION_DECODED".equals(
            node.optString("status","")))
            return -1;
        if(!"unconditional_jump".equals(node.optString("first_transfer_kind","")))
            return -1;
        if(!"direct".equals(node.optString("first_transfer_target_kind","")))
            return -1;
        long rva=node.optLong("first_transfer_target_rva",-1);
        return JumpJoin.inImage(rva,imageSize)?rva:-1;
    }

    /** Hard stop at one more JMP per JNE arm. No recursion/cycle execution. */
    private JSONObject inspectNextJump(GameCodeSource codeSource,long nextRva,
                                       long imageSize,long firstArmRva,
                                       long secondArmRva,long callTargetRva) {
        JSONObject result=new JSONObject();
        try {
            if(!JumpJoin.inImage(nextRva,imageSize)) {
                result.put("status","NO_RESOLVED_IN_IMAGE_DIRECT_JMP");
            } else if(JumpJoin.previouslyVisited(nextRva,firstArmRva,
                                          secondArmRva,callTargetRva)) {
                result.put("status","TARGET_ALREADY_VISITED_CYCLE_OR_CROSS_LINK");
                result.put("target_rva",nextRva);
            } else {
                result=probeBranchRva(codeSource,nextRva,imageSize);
                result.put("one_hop_only",true);
            }
            result.put("original_game_code_executed",false);
            result.put("raw_game_bytes_exported",false);
        } catch(Exception ex) {
            try {
                result.put("status","FOLLOWUP_TARGET_PROBE_FAILED");
                result.put("error_class",ex.getClass().getSimpleName());
                result.put("original_game_code_executed",false);
            } catch(Exception ignored) {}
        }
        return result;
    }


    /** Read-only PE64 Import Directory inspection; NOT a DLL loader. */
    private void testPeImports() {
        if(importBusy || archiveBusy || exeBusy || entryBusy) {
            updateStatus("يوجد فحص آخر جارٍ. أكمله قبل تحليل مكتبات Windows.");
            return;
        }
        String chosen=prefs.getString(GAME_DIRECT_EXE,"");
        if(chosen.isEmpty()) {
            updateStatus("اختَر مجلد فورزا المستخرج أولاً. فحص DLL الحالي يحتاج EXE مباشر.");
            return;
        }
        importBusy=true;
        importButton.setEnabled(false);
        updateStatus("P3.7: فحص أسماء دوال Windows الطويلة وترويسات DLL المحلية، دون تشغيل اللعبة...");
        final String uri=chosen;
        Thread worker=new Thread(() -> {
            JSONObject result=new JSONObject();
            String visible;
            try(ParcelFileDescriptor pfd=getContentResolver()
                    .openFileDescriptor(Uri.parse(uri),"r")) {
                if(pfd==null)throw new java.io.IOException("pe_import_document_unavailable");
                try(FileInputStream in=new FileInputStream(pfd.getFileDescriptor())) {
                    PeImportProbe.Result scan=PeImportProbe.inspectDirect(in.getChannel());
                    JSONArray names=new JSONArray();
                    for(String dll:scan.dllNames)names.put(dll);
                    result.put("stage","P3_7_LONG_SYMBOL_BOUNDED_IMPORT_PROBE");
                    result.put("status",scan.status);
                    result.put("source","EXTRACTED_PE64_DIRECT");
                    result.put("source_size_bytes",scan.sourceFileBytes);
                    result.put("import_directory_rva",scan.directoryRva);
                    result.put("import_directory_size_bytes",scan.directoryBytes);
                    result.put("static_imports_present",scan.importsPresent);
                    result.put("static_import_scan_complete",scan.complete);
                    result.put("descriptors_scanned",scan.descriptorCount);
                    result.put("unique_dll_names",scan.uniqueNameCount);
                    result.put("dll_names",names);
                    // P3.6: retrieve functions imported from each original Windows DLL.
                    // No import binding, load, code execution, or raw IAT exported.
                    int functionNamed=0,functionOrdinal=0;
                    String symbolStatus="NOT_SCANNED";
                    try {
                        PeImportSymbolProbe.Report symbols=
                            PeImportSymbolProbe.inspectDirect(in.getChannel());
                        JSONArray symbolDlls=new JSONArray();
                        for(PeImportSymbolProbe.Dll dll:symbols.dlls) {
                            JSONObject item=new JSONObject();
                            item.put("dll",dll.dll);
                            item.put("named_function_imports",dll.namedImports);
                            item.put("ordinal_function_imports",dll.ordinalImports);
                            item.put("thunk_table_complete",dll.thunkTableComplete);
                            JSONArray examples=new JSONArray();
                            for(String name:dll.exampleFunctions)examples.put(name);
                            item.put("example_function_names",examples);
                            symbolDlls.put(item);
                        }
                        result.put("dll_function_import_inventory",symbolDlls);
                        result.put("import_symbol_scan_complete",symbols.complete);
                        result.put("import_symbol_dlls_scanned",symbols.dllsChecked);
                        result.put("symbol_name_samples_truncated",symbols.sampleNamesTruncated);
                        result.put("symbol_names_over_scan_budget",symbols.namesOverScanBudget);
                        result.put("max_symbol_name_scan_bytes",
                            PeImportSymbolProbe.MAX_SYMBOL_SCAN_BYTES);
                        result.put("max_symbol_name_display_bytes",
                            PeImportSymbolProbe.MAX_SYMBOL_SAMPLE_BYTES);
                        functionNamed=symbols.totalNamedImports;
                        functionOrdinal=symbols.totalOrdinalImports;
                        symbolStatus=symbols.status;
                    } catch(java.io.IOException symbolError) {
                        symbolStatus=symbolError.getMessage();
                        if(symbolStatus==null ||
                           !symbolStatus.matches("pe_(symbol|import)_[a-z0-9_]{2,90}"))
                            symbolStatus="IMPORT_SYMBOL_READ_FAILED";
                        result.put("import_symbol_scan_complete",false);
                        result.put("import_symbol_error_code",symbolStatus);
                    }
                    result.put("import_symbol_scan_status",symbolStatus);
                    result.put("named_function_imports",functionNamed);
                    result.put("ordinal_function_imports",functionOrdinal);
                    result.put("symbol_name_samples_per_dll_max",
                        PeImportSymbolProbe.MAX_SAMPLE_NAMES);
                    result.put("import_address_table_bound",false);
                    // P3.5: verify immediate sibling filenames only under
                    // the previously user-approved SAF folder. A match does
                    // not validate DLL architecture, imports or loadability.
                    java.util.Set<String> fileNames=java.util.Collections.emptySet();
                    boolean verifiedFolder=false;
                    String folderReason="FOLDER_NOT_SELECTED";
                    String tree=prefs.getString(GAME_FOLDER,"");
                    if(!tree.isEmpty()) {
                        try {
                            fileNames=SafGameFolderProbe.listSiblingDllNames(
                                getContentResolver(),Uri.parse(tree),Uri.parse(uri));
                            verifiedFolder=true;
                            folderReason="EXE_SIBLINGS_ENUMERATED";
                        } catch(java.io.IOException err) {
                            folderReason=err.getMessage();
                            if(folderReason==null ||
                               !folderReason.matches("saf_[a-z0-9_]{2,90}"))
                                folderReason="SAF_DIRECTORY_UNAVAILABLE";
                        }
                    }
                    DllDependencyPlanner.Report plan=DllDependencyPlanner.assess(
                        scan.dllNames,fileNames,verifiedFolder);
                    JSONArray inventory=new JSONArray();
                    for(DllDependencyPlanner.Entry item:plan.entries) {
                        JSONObject dep=new JSONObject();
                        dep.put("dll",item.name);
                        dep.put("compatibility_group",item.group);
                        dep.put("beside_exe_filename_status",item.localStatus);
                        inventory.put(dep);
                    }
                    result.put("dll_compatibility_inventory",inventory);
                    result.put("exe_folder_listed",verifiedFolder);
                    result.put("exe_folder_scan_status",folderReason);
                    JSONArray binaryHeaders=new JSONArray();
                    int validLocal64=0,headersVisited=0;
                    String headerScanStatus=verifiedFolder?"NOT_STARTED":"FOLDER_NOT_VERIFIED";
                    if(verifiedFolder && !tree.isEmpty()) {
                        try {
                            java.util.List<SafGameFolderProbe.LocalDll> dlls=
                                SafGameFolderProbe.inspectSiblingDllHeaders(
                                    getContentResolver(),Uri.parse(tree),Uri.parse(uri),
                                    new java.util.HashSet<>(scan.dllNames));
                            for(SafGameFolderProbe.LocalDll dll:dlls) {
                                JSONObject row=new JSONObject();
                                row.put("dll",dll.dll);
                                row.put("header_status",dll.headerStatus);
                                row.put("file_size_bytes",dll.fileSize);
                                binaryHeaders.put(row);
                                headersVisited++;
                                if("PE64_AMD64_DLL_HEADER_VERIFIED".equals(dll.headerStatus))
                                    validLocal64++;
                            }
                            headerScanStatus="LOCAL_DLL_PE_HEADERS_CHECKED";
                        } catch(java.io.IOException headerError) {
                            headerScanStatus=headerError.getMessage();
                            if(headerScanStatus==null ||
                               !headerScanStatus.matches("saf_[a-z0-9_]{2,90}"))
                                headerScanStatus="SAF_DLL_HEADER_QUERY_FAILED";
                        }
                    }
                    result.put("local_dll_pe_headers",binaryHeaders);
                    result.put("local_dll_header_scan_status",headerScanStatus);
                    result.put("local_dll_header_files_checked",headersVisited);
                    result.put("local_amd64_pe_dll_headers_valid",validLocal64);
                    result.put("local_dll_code_executed",false);
                    result.put("import_names_matched_beside_exe",plan.localCount);
                    result.put("import_names_not_found_beside_exe",plan.notLocalCount);
                    result.put("import_names_unchecked",plan.notCheckedCount);
                    result.put("windows_api_set_contracts",plan.apiSetCount);
                    result.put("sibling_check_depth",0);
                    result.put("binary_abi_or_export_validation_completed",false);
                    result.put("windows_loader_ready",false);
                    result.put("max_descriptors",PeImportProbe.MAX_DLL_DESCRIPTORS);
                    result.put("max_dll_name_bytes",PeImportProbe.MAX_DLL_NAME_BYTES);
                    result.put("delay_load_directory_not_scanned",true);
                    result.put("runtime_loadlibrary_calls_not_scanned",true);
                    result.put("local_dll_files_verified",false);
                    result.put("windows_api_available",false);
                    result.put("dlls_loaded_into_process",false);
                    result.put("original_game_code_executed",false);
                    result.put("original_game_bytes_exported",false);
                    StringBuilder sample=new StringBuilder();
                    for(int i=0;i<Math.min(6,scan.dllNames.size());i++) {
                        if(i>0)sample.append(", ");
                        sample.append(scan.dllNames.get(i));
                    }
                    visible="نتيجة فحص DLL: "+scan.status
                        +"\nعدد المكتبات: "+scan.uniqueNameCount
                        +"\nالدوال المستوردة بالاسم: "+functionNamed
                        +"\nالدوال المستوردة بالرقم: "+functionOrdinal
                        +"\nحالة فحص الدوال: "+symbolStatus
                        +"\nأسماء دوال العرض المختصرة: "+result.optInt("symbol_name_samples_truncated",0)
                        +"\nأسماء فوق حد قراءة 1024 بايت: "+result.optInt("symbol_names_over_scan_budget",0)
                        +"\nترويسات DLL المحلية x64 المتحققة: "+validLocal64+"/"+headersVisited
                        +"\nملفات DLL موجودة بجانب EXE: "+plan.localCount
                        +"\nغير موجودة بجانبه: "+plan.notLocalCount
                        +"\nغير مفحوصة: "+plan.notCheckedCount
                        +"\nعقود Windows API Set: "+plan.apiSetCount
                        +"\nوجود اسم DLL لا يثبت إمكان تحميله أو تشغيل فورزا.";
                }
            } catch(Exception ex) {
                String reason=ex.getMessage();
                if(reason==null||!reason.matches("pe_import_[a-z0-9_]{2,95}"))
                    reason="pe_import_source_or_parser_error";
                try {
                    result.put("stage","P3_5_DEPENDENCY_FOLDER_INVENTORY_READ_ONLY");
                    result.put("status","P3_7_IMPORT_SYMBOL_SCAN_FAILED");
                    result.put("error_code",reason);
                    result.put("original_game_code_executed",false);
                } catch(Exception ignored) { }
                visible="تعذر فحص جدول DLL: "+reason;
            }
            final JSONObject report=result;
            final String message=visible;
            runOnUiThread(() -> {
                importBusy=false;
                importButton.setEnabled(true);
                peImportsResult=report;
                updateStatus(message);
            });
        },"fh5-static-import-directory");
        worker.start();
    }

    private void testActualEntry() {
        if (entryBusy || archiveBusy || exeBusy || importBusy) {
            updateStatus("يوجد فحص آخر جارٍ. أكمله أولاً.");
            return;
        }
        boolean directMode=!prefs.getString(GAME_DIRECT_EXE,"").isEmpty();
        String saved=directMode?prefs.getString(GAME_DIRECT_EXE,""):
            prefs.getString(GAME_ARCHIVE,"");
        if (saved.isEmpty()) {
            updateStatus("اختَر ملف ForzaHorizon5.exe المستخرج أو أرشيف اللعبة ZIP قبل الفحص.");
            return;
        }
        entryBusy=true;
        entryButton.setEnabled(false);
        updateStatus("P3.3: نفحص دوال فورزا من EXE المكتشف داخل المجلد، بدون تنفيذ كود اللعبة.");
        Thread worker=new Thread(() -> {
            JSONObject info=new JSONObject();
            String message;
            try(ParcelFileDescriptor pfd=getContentResolver()
                    .openFileDescriptor(Uri.parse(saved),"r")) {
                if(pfd==null)throw new java.io.IOException("pe_or_zip_document_unavailable");
                try(FileInputStream file=new FileInputStream(pfd.getFileDescriptor())) {
                    GameCodeSource codeSource=new GameCodeSource(file.getChannel(),directMode);
                    GameExeHeaderProbe.EntryResult e=codeSource.inspectEntry();
                    info.put("game_code_source",codeSource.kind());
                    info.put("direct_exe_selected",directMode);
                    info.put("source_file_size_bytes",file.getChannel().size());
                    info.put("direct_random_access_mode",directMode);
                    info.put("original_game_executed",false);
                    JSONObject translated=X64Proof.inspectActualEntry(e.entrySample);
                    JSONObject disassembled=X86Disasm.inspect(
                        e.entrySample,e.pe.entryPointRva,e.pe.imageSize);
                    JSONObject targetProbe=new JSONObject();
                    targetProbe.put("status","SKIPPED_NO_CONFIRMED_DIRECT_TARGET");
                    if(disassembled.optBoolean("first_transfer_target_within_exe_image",false)
                        && !disassembled.isNull("first_transfer_target_rva")) {
                        long targetRva=disassembled.optLong("first_transfer_target_rva",-1);
                        if(targetRva>0 && targetRva<e.pe.imageSize &&
                            targetRva!=e.pe.entryPointRva) {
                            try {
                                GameExeHeaderProbe.EntryResult target=
                                    codeSource.inspectAtRva(targetRva,512);
                                JSONObject decodedTarget=X86Disasm.inspect(
                                    target.entrySample,targetRva,target.pe.imageSize);
                                targetProbe.put("status","TARGET_SECTION_MAPPED_AND_DECODED");
                                targetProbe.put("target_rva",targetRva);
                                targetProbe.put("target_section_index",target.sectionIndex);
                                targetProbe.put("bytes_sampled",target.sampleLength);
                                targetProbe.put("deep_inspection_max_instructions",64);
                                targetProbe.put("target_instruction_count",
                                    decodedTarget.optInt("decoded_instruction_count",0));
                                targetProbe.put("target_push_count",
                                    decodedTarget.optInt("push_instruction_count",0));
                                targetProbe.put("target_xmm_instruction_count",
                                    decodedTarget.optInt("xmm_register_instruction_count",0));
                                targetProbe.put("target_first_transfer_kind",
                                    decodedTarget.optString("first_transfer_kind","none"));
                                targetProbe.put("uncompressed_bytes_streamed",target.bytesInflated);
                                targetProbe.put("compressed_bytes_read_from_archive",target.compressedBytesRead);
                                targetProbe.put("capstone_target_disassembly",decodedTarget);
                                JSONObject paths=new JSONObject();
                                paths.put("status","NO_CONDITIONAL_BRANCH_IDENTIFIED");
                                paths.put("runtime_condition_evaluated",false);
                                paths.put("original_game_code_executed",false);
                                if(decodedTarget.optBoolean("conditional_two_successors",false)) {
                                    paths.put("status","CONDITIONAL_TAKEN_AND_NOT_TAKEN_IDENTIFIED");
                                    paths.put("not_taken_fallthrough_rva",
                                        decodedTarget.optLong("conditional_not_taken_rva",-1));
                                    paths.put("not_taken_next_mnemonic",
                                        decodedTarget.optString("not_taken_next_mnemonic","none"));
                                    long takenRva=decodedTarget.optLong("first_transfer_target_rva",-1);
                                    JSONObject taken=probeBranchRva(
                                        codeSource,takenRva,e.pe.imageSize);
                                    paths.put("taken",taken);
                                    JSONObject notTaken;
                                    long otherRva=-1;
                                    if(decodedTarget.optBoolean("not_taken_next_is_jump",false)) {
                                        paths.put("not_taken_jump_target_kind",
                                            decodedTarget.optString("not_taken_jump_target_kind","none"));
                                        otherRva=decodedTarget.optLong("not_taken_jump_target_rva",-1);
                                        notTaken=probeBranchRva(
                                            codeSource,otherRva,e.pe.imageSize);
                                    } else {
                                        notTaken=new JSONObject().put("status",
                                            "NO_DIRECT_JUMP_AT_FALLTHROUGH");
                                    }
                                    paths.put("not_taken_jump",notTaken);
                                    // P2.9: each branch target itself starts with JMP.
                                    // Resolve the two next destinations without recursively
                                    // exploring arbitrary game control flow.
                                    long takenNext=eligibleNextJumpRva(taken,e.pe.imageSize);
                                    long notTakenNext=eligibleNextJumpRva(notTaken,e.pe.imageSize);
                                    paths.put("taken_second_jmp_target_rva",
                                        takenNext>0?takenNext:JSONObject.NULL);
                                    paths.put("not_taken_second_jmp_target_rva",
                                        notTakenNext>0?notTakenNext:JSONObject.NULL);
                                    paths.put("branch_paths_were_executed",false);
                                    boolean bothKnown=JumpJoin.inImage(takenNext,e.pe.imageSize)
                                        && JumpJoin.inImage(notTakenNext,e.pe.imageSize);
                                    paths.put("both_next_targets_direct_and_in_image",bothKnown);
                                    paths.put("static_next_jump_join_status",
                                        JumpJoin.classify(takenNext,notTakenNext,e.pe.imageSize));
                                    JumpJoin.GraphResult graph=JumpJoin.classifyGraph(
                                        takenRva,otherRva,takenNext,notTakenNext,e.pe.imageSize);
                                    paths.put("graph_status",graph.status);
                                    paths.put("graph_reconvergence_rva",
                                        graph.joinRva>0?graph.joinRva:JSONObject.NULL);
                                    paths.put("graph_true_cycle_detected",graph.cycleDetected);
                                    paths.put("cross_link_is_not_necessarily_a_cycle",true);
                                    JSONObject takenSecondNode;
                                    JSONObject notTakenSecondNode;
                                    if(bothKnown && takenNext==notTakenNext) {
                                        JSONObject shared=inspectNextJump(codeSource,
                                            takenNext,e.pe.imageSize,takenRva,otherRva,targetRva);
                                        paths.put("shared_next_jump_target_probe",shared);
                                        paths.put("duplicate_target_read_avoided",true);
                                        takenSecondNode=shared;
                                        notTakenSecondNode=shared;
                                    } else {
                                        takenSecondNode=inspectNextJump(codeSource,takenNext,
                                            e.pe.imageSize,takenRva,otherRva,targetRva);
                                        paths.put("taken_next_jump_target_probe",takenSecondNode);
                                        if(!graph.cycleDetected && graph.joinRva==takenRva &&
                                           notTakenNext==takenRva) {
                                            notTakenSecondNode=new JSONObject()
                                                .put("status","RECONVERGENCE_AT_ALREADY_DECODED_TAKEN_BRANCH")
                                                .put("target_rva",takenRva)
                                                .put("original_game_code_executed",false);
                                        } else if(!graph.cycleDetected && graph.joinRva==otherRva &&
                                                  takenNext==otherRva) {
                                            notTakenSecondNode=inspectNextJump(codeSource,
                                                notTakenNext,e.pe.imageSize,takenRva,otherRva,targetRva);
                                        } else {
                                            notTakenSecondNode=inspectNextJump(codeSource,
                                                notTakenNext,e.pe.imageSize,takenRva,otherRva,targetRva);
                                        }
                                        paths.put("not_taken_next_jump_target_probe",notTakenSecondNode);
                                    }
                                    // One additional bounded read-only inspection of the first
                                    // DIRECT in-image CALL appearing after the mapped JNE join.
                                    JSONObject afterJoinCall=new JSONObject();
                                    afterJoinCall.put("status","NO_SAFE_DIRECT_CALL_AFTER_JOIN");
                                    if(graph.joinRva>0 && !graph.cycleDetected) {
                                        JSONObject following=graph.joinRva==takenRva?
                                            takenSecondNode:notTakenSecondNode;
                                        if("call".equals(following.optString("first_transfer_kind","")) &&
                                           "direct".equals(following.optString("first_transfer_target_kind",""))) {
                                            long callRva=following.optLong("first_transfer_target_rva",-1);
                                            if(JumpJoin.inImage(callRva,e.pe.imageSize) &&
                                               callRva!=takenRva && callRva!=otherRva &&
                                               callRva!=targetRva && callRva!=takenNext &&
                                               callRva!=notTakenNext) {
                                                afterJoinCall=probeBranchRva(codeSource,
                                                    callRva,e.pe.imageSize);
                                                afterJoinCall.put("call_site_rva",
                                                    graph.joinRva==takenRva?takenNext:notTakenNext);
                                                afterJoinCall.put("followed_call_rva",callRva);
                                                afterJoinCall.put("followed_call_is_static_only",true);
                                            }
                                        }
                                    }
                                    paths.put("first_direct_call_after_join_probe",afterJoinCall);
                                    long verifiedCallRva=afterJoinCall.optLong("followed_call_rva",-1);
                                    JSONObject secondJne=inspectPostJoinJne(
                                        codeSource,afterJoinCall,e.pe.imageSize,
                                        verifiedCallRva);
                                    paths.put("second_jne_successors",secondJne);
                                    paths.put("maximum_followed_new_targets",7);
                                    paths.put("maximum_followup_depth",3);
                                }
                                targetProbe.put("conditional_branch_paths",paths);
                                targetProbe.put("target_executed",false);
                                targetProbe.put("raw_target_bytes_exported",false);
                            } catch(java.io.IOException targetErr) {
                                targetProbe.put("status","TARGET_SECTION_UNAVAILABLE_OR_UNSUPPORTED");
                                String reason=targetErr.getMessage();
                                if(reason==null || !reason.matches("(pe|zip|zip64)_[a-z0-9_]{2,90}"))
                                    reason="target_read_or_bounds_error";
                                targetProbe.put("reason",reason);
                                targetProbe.put("target_executed",false);
                                targetProbe.put("raw_target_bytes_exported",false);
                            }
                        }
                    }
                    info.put("stage","P3_4_DIRECT_PE_STATIC_ANALYSIS");
                    info.put("status","P3_4_DIRECT_PE_STATIC_ANALYSIS_COMPLETED");
                    info.put("amd64",e.pe.amd64);
                    info.put("pe32plus",e.pe.pe32plus);
                    info.put("entry_point_rva",e.pe.entryPointRva);
                    info.put("mapped_section_index",e.sectionIndex);
                    info.put("original_exe_file_entry_offset",e.entryFileOffset);
                    info.put("original_instruction_bytes_read",e.sampleLength);
                    info.put("first_opcode_family",e.leadingOpcodeFamily);
                    info.put("uncompressed_bytes_streamed",e.bytesInflated);
                    info.put("compressed_bytes_read_from_archive",e.compressedBytesRead);
                    info.put("translation_only_probe",translated);
                    info.put("capstone_x64_disassembly",disassembled);
                    info.put("first_direct_transfer_target_probe",targetProbe);
                    info.put("game_code_executed",false);
                    info.put("exe_fully_extracted",false);
                    info.put("game_file_crc_fully_checked",false);
                    info.put("original_instruction_bytes_exported",false);
                    info.put("private_game_paths_exported",false);
                    message="P3.3: فحصنا تعليمات فورزا من "+(directMode?"EXE مباشر!":"ZIP64!") +
                        "\nالقسم: "+e.sectionIndex+
                        "\nنوع أول تعليمة: "+e.leadingOpcodeFamily+
                        "\nحالة المترجم المصغّر: "+translated.optString("status","unknown")+
                        "\nتعليمات معروفة بالبداية: "+translated.optInt("recognizedInstructionCount",0)+
                        "\nبايتات متعرف عليها: "+translated.optInt("recognizedPrefixBytes",0)+
                        "\nأول موضع غير مدعوم بالمترجم المصغّر: "+translated.optInt("firstUnsupportedOffset",0)+
                        "\nتعليمات مفككة بـCapstone: "+disassembled.optInt("decoded_instruction_count",0)+
                        "\nحالة مفكّك التعليمات: "+disassembled.optString("status","unknown")+
                        "\nأول انتقال: "+disassembled.optString("first_transfer_kind","unknown")+
                        "\nهدف أول انتقال: "+targetProbe.optString("status","unknown")+
                        "\nتعليمات الدالة المستهدفة: "+targetProbe.optInt("target_instruction_count",0)+
                        "\nPUSH: "+targetProbe.optInt("target_push_count",0)+
                        "\nتعليمات XMM: "+targetProbe.optInt("target_xmm_instruction_count",0)+
                        "\nترجمة تجريبية فقط؛ لم نشغّل كود اللعبة.";
                }
            } catch(Exception ex) {
                String kind="zip_entry_or_storage_error";
                if(ex instanceof java.io.IOException) {
                    String raw=ex.getMessage();
                    if(raw!=null && raw.matches("(zip|zip64|pe)_[a-z0-9_]{2,90}"))
                        kind=raw;
                }
                try {
                    info.put("status","P3_4_DIRECT_PE_STATIC_ANALYSIS_FAILED");
                    info.put("error_kind",kind);
                    info.put("exception_class",ex.getClass().getSimpleName());
                    info.put("game_code_executed",false);
                    info.put("original_instruction_bytes_exported",false);
                    info.put("private_game_paths_exported",false);
                } catch(Exception ignored) {}
                message="تعذر تحليل نقطة دخول فورزا الأصلية: "+kind;
            }
            final JSONObject completed=info;
            final String resultMessage=message;
            runOnUiThread(() -> {
                entryBusy=false;
                actualEntryProbe=completed;
                entryButton.setEnabled(true);
                updateStatus(resultMessage);
            });
        },"fh5-original-entry-probe");
        worker.start();
    }

    private JSONObject buildReport() {
        JSONObject data = new JSONObject();
        try {
            data.put("project", "FH5 Native Port")
                .put("stage", "P3.7")
                .put("application_id", getPackageName())
                .put("native_arm64_apk", true)
                .put("android_sdk", Build.VERSION.SDK_INT)
                .put("device_model", Build.MODEL)
                .put("game_zip_selected", prefs.contains(GAME_ARCHIVE))
                .put("game_folder_selected", prefs.contains(GAME_FOLDER))
                .put("direct_exe_selected", prefs.contains(GAME_DIRECT_EXE))
                .put("direct_exe_auto_found_in_folder",
                    prefs.getBoolean(AUTO_EXE_FROM_FOLDER,false))
                .put("preferred_game_code_source",
                    prefs.contains(GAME_DIRECT_EXE)?"EXTRACTED_PE64_DIRECT":"ZIP64_ARCHIVED_EXE")
                .put("archive_header", archiveInfo)
                .put("vulkan_surface_result", gpuResult)
                .put("synthetic_x64_execution_result", x64Result)
                .put("real_forza_exe_header_result",realExeMetadata)
                .put("real_forza_pe_imports",peImportsResult)
                .put("real_forza_entrypoint_result",actualEntryProbe)
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
