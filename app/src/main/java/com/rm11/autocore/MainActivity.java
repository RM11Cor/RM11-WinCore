package com.rm11.autocore;

import android.app.Activity;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.Map;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** First-stage diagnostic app. No Windows engine is bundled or claimed. */
public final class MainActivity extends Activity {
    private static final int PICK_TREE = 701;
    private static final int PICK_RUNTIME_REPORT = 918;
    private static final int LIMIT = 20000;
    private static final int MAX_DEPTH = 14;
    private final ExecutorService scanExecutor = Executors.newSingleThreadExecutor();
    private TextView resultView;
    private TextView deviceView;
    private TextView runtimeReportView;
    private Button shareButton;
    private Button rescanButton;
    private String reportText = "";
    private Uri lastTree;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(Color.rgb(10, 15, 27));
        getWindow().setNavigationBarColor(Color.rgb(10, 15, 27));
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(Color.rgb(10, 15, 27));
        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(dp(22), dp(28), dp(22), dp(28));
        body.setLayoutDirection(View.LAYOUT_DIRECTION_RTL);
        scroll.addView(body);

        TextView title = label("RM11 AutoCore", 27, Color.WHITE, true);
        title.setGravity(Gravity.CENTER);
        body.addView(title);
        TextView subtitle = label("v2.4.13 • فحص Windows Runtime الموحد — 10 مراحل", 15, 0xFF90A7C8, false);
        subtitle.setGravity(Gravity.CENTER);
        body.addView(subtitle);
        TextView warning = label("هذه نسخة فحص حقيقية وليست محرك تشغيل Windows بعد. لا تعدّل ولا تنسخ ملفات الألعاب.",
                15, 0xFFFFDA88, false);
        warning.setPadding(dp(14), dp(15), dp(14), dp(15));
        warning.setBackground(boxColor(0xFF2D281D));
        LinearLayout.LayoutParams w = margins(0, 20, 0, 15);
        body.addView(warning, w);

        Button pickButton = action("إضافة مجلد لعبة وفحصه");
        pickButton.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION
                    | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
            startActivityForResult(intent, PICK_TREE);
        });
        body.addView(pickButton, margins(0, 3, 0, 10));

        rescanButton = action("إعادة فحص آخر مجلد");
        rescanButton.setEnabled(false);
        rescanButton.setOnClickListener(v -> { if (lastTree != null) scan(lastTree); });
        body.addView(rescanButton, margins(0, 0, 0, 10));

        Button probeButton = action("فحص الجهاز وVulkan وRAM");
        probeButton.setOnClickListener(v -> {
            try {
                deviceView.setText(DeviceCapabilityProbe.collect(this).asDisplayText());
                deviceView.setVisibility(View.VISIBLE);
            } catch (RuntimeException e) {
                deviceView.setText("تعذر قراءة بيانات الجهاز: " + e.getClass().getSimpleName());
                deviceView.setVisibility(View.VISIBLE);
            }
        });
        body.addView(probeButton, margins(0, 0, 0, 12));
        deviceView = label("", 15, 0xFFD1E0F5, false);
        deviceView.setTextIsSelectable(true);
        deviceView.setBackground(boxColor(0xFF1D302D));
        deviceView.setPadding(dp(14), dp(16), dp(14), dp(16));
        deviceView.setVisibility(View.GONE);
        body.addView(deviceView, margins(0, 0, 0, 12));

        Button nativeVulkanButton = action("اختبار تعريف Vulkan الفعلي (GPU)");
        TextView nativeVulkanView = label("", 15, 0xFFD1E0F5, false);
        nativeVulkanView.setTextIsSelectable(true);
        nativeVulkanView.setBackground(boxColor(0xFF19313B));
        nativeVulkanView.setPadding(dp(14), dp(16), dp(14), dp(16));
        nativeVulkanView.setVisibility(View.GONE);
        Button shareVulkanButton = action("مشاركة نتيجة Vulkan الحقيقي");
        shareVulkanButton.setEnabled(false);
        final String[] lastGpuReport = {""};
        nativeVulkanButton.setOnClickListener(v -> {
            nativeVulkanButton.setEnabled(false);
            nativeVulkanView.setVisibility(View.VISIBLE);
            nativeVulkanView.setText("جاري اختبار Vulkan الحقيقي في معالج الخلفية...");
            scanExecutor.execute(() -> {
                VulkanNativeProbe.Result result = VulkanNativeProbe.inspect();
                runOnUiThread(() -> {
                    lastGpuReport[0] = result.displayText + "\n\nRaw JSON:\n" + result.rawJson;
                    nativeVulkanView.setText(result.displayText);
                    nativeVulkanButton.setEnabled(true);
                    shareVulkanButton.setEnabled(true);
                });
            });
        });
        shareVulkanButton.setOnClickListener(v -> {
            if (lastGpuReport[0].isEmpty()) return;
            Intent send = new Intent(Intent.ACTION_SEND);
            send.setType("text/plain");
            send.putExtra(Intent.EXTRA_TEXT, lastGpuReport[0]);
            startActivity(Intent.createChooser(send, "مشاركة تقرير Vulkan الفعلي"));
        });
        body.addView(nativeVulkanButton, margins(0, 0, 0, 8));
        body.addView(nativeVulkanView, margins(0, 0, 0, 8));
        body.addView(shareVulkanButton, margins(0, 0, 0, 14));

        Button renderVulkanButton = action("اختبار رسم Vulkan الفعلي (180 إطار)");
        renderVulkanButton.setOnClickListener(v ->
                startActivity(new Intent(this, VulkanRenderActivity.class)));
        body.addView(renderVulkanButton, margins(0, 0, 0, 14));

        Button suiteButton = action("فحص GPU الشامل — خمس مراحل واختبار واحد");
        suiteButton.setOnClickListener(v ->
                startActivity(new Intent(this, VulkanSuiteActivity.class)));
        body.addView(suiteButton, margins(0, 0, 0, 14));

        Button importRuntime = action("استيراد تقرير Windows — 10 اختبارات (Termux)");
        importRuntime.setOnClickListener(v -> {
            Intent pick = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            pick.addCategory(Intent.CATEGORY_OPENABLE);
            pick.setType("text/plain");
            startActivityForResult(pick, PICK_RUNTIME_REPORT);
        });
        body.addView(importRuntime, margins(0, 0, 0, 10));
        runtimeReportView = label("لا يوجد تقرير Windows مستورد. شغّل فحص Termux مرة واحدة، ثم اختر التقرير.",
                14, 0xFFD1E0F5, false);
        runtimeReportView.setTextIsSelectable(true);
        runtimeReportView.setBackground(boxColor(0xFF19313B));
        runtimeReportView.setPadding(dp(12), dp(12), dp(12), dp(12));
        body.addView(runtimeReportView, margins(0, 0, 0, 14));

        shareButton = action("مشاركة تقرير الفحص");
        shareButton.setEnabled(false);
        shareButton.setOnClickListener(v -> {
            if (reportText.isEmpty()) return;
            Intent send = new Intent(Intent.ACTION_SEND);
            send.setType("text/plain");
            send.putExtra(Intent.EXTRA_TEXT, reportText);
            startActivity(Intent.createChooser(send, "مشاركة تقرير RM11"));
        });
        body.addView(shareButton, margins(0, 0, 0, 16));

        resultView = label("اختر مجلد أي لعبة Windows، حتى لو النظام لم يشاهدها من قبل.\n\n"
                + "راح أحلل بنية المجلد وبيانات EXE الداخلية عندما تتوفر، بدون قائمة ألعاب مسبقة؛ "
                + "ولا أفترض أن وجود مكتبة Steam يعني توفر ترخيص أو أن نسخة معينة مدعومة.",
                16, 0xFFD1E0F5, false);
        resultView.setTextIsSelectable(true);
        resultView.setPadding(dp(17), dp(18), dp(17), dp(18));
        resultView.setBackground(boxColor(0xFF172438));
        body.addView(resultView);
        setContentView(scroll);

        String stored = getPreferences(MODE_PRIVATE).getString("last_tree_uri", "");
        if (!stored.isEmpty()) {
            try {
                Uri restored = Uri.parse(stored);
                for (android.content.UriPermission permission : getContentResolver().getPersistedUriPermissions()) {
                    if (permission.isReadPermission() && permission.getUri().equals(restored)) {
                        lastTree = restored;
                        rescanButton.setEnabled(true);
                        break;
                    }
                }
            } catch (RuntimeException ignored) { /* stale URI ignored */ }
        }
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == PICK_RUNTIME_REPORT) {
            if (resultCode != RESULT_OK || data == null || data.getData() == null) return;
            try (InputStream in = getContentResolver().openInputStream(data.getData())) {
                if (in == null) throw new IllegalArgumentException("report unavailable");
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                byte[] bytes = new byte[4096];
                int n;
                while ((n = in.read(bytes)) >= 0) {
                    if (output.size() + n > 65536) throw new IllegalArgumentException("report over 64 KiB");
                    output.write(bytes, 0, n);
                }
                String source = output.toString("UTF-8");
                RuntimeReportReader.Result parsed = RuntimeReportReader.read(source);
                runtimeReportView.setText(parsed.summary + "\n\n" + source);
            } catch (Exception error) {
                runtimeReportView.setText("تعذر قراءة تقرير Windows: " + error.getMessage());
            }
            return;
        }
        if (requestCode != PICK_TREE || resultCode != RESULT_OK || data == null || data.getData() == null) return;
        Uri uri = data.getData();
        if ((data.getFlags() & Intent.FLAG_GRANT_READ_URI_PERMISSION) == 0) {
            resultView.setText("لم يمنح منتقي الملفات صلاحية القراءة.");
            return;
        }
        try {
            getContentResolver().takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
        } catch (SecurityException e) {
            resultView.setText("تعذر حفظ إذن المجلد: " + e.getMessage());
            return;
        }
        lastTree = uri;
        getPreferences(MODE_PRIVATE).edit().putString("last_tree_uri", uri.toString()).apply();
        rescanButton.setEnabled(true);
        scan(uri);
    }

    private void scan(Uri treeUri) {
        resultView.setText("جاري تحليل ملفات اللعبة وبيانات EXE وDLL... لا يتم تشغيل أو نسخ أو تعديل أي ملف.");
        shareButton.setEnabled(false);
        scanExecutor.execute(() -> {
            try {
                ScanResult scan = enumerate(treeUri);
                GameManifestReader.Result metadata = inspectMetadata(scan);
                inspectCandidateExecutables(scan, metadata);
                GameDetector.Detection detected = GameDetector.analyze(scan.entries, scan.truncated, metadata);
                CompatibilityPlanner.Plan plan = CompatibilityPlanner.build(detected, metadata, scan.entries);
                String report = report(detected, metadata, plan);
                storeReport(treeUri, detected, metadata, plan);
                runOnUiThread(() -> {
                    reportText = report;
                    resultView.setText(report);
                    shareButton.setEnabled(true);
                });
            } catch (Exception e) {
                runOnUiThread(() -> resultView.setText("تعذر فحص المجلد: " + e.getClass().getSimpleName()
                        + ": " + e.getMessage() + "\nقد تكون صلاحية التخزين أو مزوّد الملفات هي السبب."));
            }
        });
    }

    private static final class Node {
        final String docId, path;
        final int depth;
        Node(String docId, String path, int depth) {
            this.docId = docId; this.path = path; this.depth = depth;
        }
    }
    private static final class ScanResult {
        final List<GameDetector.Entry> entries;
        final boolean truncated;
        final Map<String, Uri> exeUris, metadataUris;
        ScanResult(List<GameDetector.Entry> entries, boolean truncated, Map<String, Uri> exeUris, Map<String, Uri> metadataUris) {
            this.entries = entries; this.truncated = truncated; this.exeUris = exeUris; this.metadataUris = metadataUris;
        }
    }

    private void inspectCandidateExecutables(ScanResult scan, GameManifestReader.Result metadata) {
        for (GameDetector.Entry selected : GameDetector.candidates(scan.entries, 6,
                metadata == null ? "" : metadata.title)) {
            Uri uri = scan.exeUris.get(selected.path);
            if (uri == null) continue;
            try (ParcelFileDescriptor fd = getContentResolver().openFileDescriptor(uri, "r")) {
                if (fd == null) continue;
                try (FileInputStream stream = new FileInputStream(fd.getFileDescriptor())) {
                    PeVersionReader.Info info = PeVersionReader.read(stream.getChannel());
                    PeImportReader.Info pe = PeImportReader.read(stream.getChannel());
                    for (int i = 0; i < scan.entries.size(); i++) {
                        GameDetector.Entry e = scan.entries.get(i);
                        if (e.path.equals(selected.path)) {
                            scan.entries.set(i, new GameDetector.Entry(e.path, false, e.size,
                                    info.productName, info.fileDescription, info.productVersion,
                                    pe.architecture, pe.importedDlls));
                            break;
                        }
                    }
                }
            } catch (Exception ignored) { // SAF providers can deny seekable reads; retain path-based inference.
            }
        }
    }

    /** Read small, allowlisted metadata files. Never read game data packs or full EXEs. */
    private GameManifestReader.Result inspectMetadata(ScanResult scan) {
        List<GameManifestReader.Document> docs = new ArrayList<>();
        for (Map.Entry<String, Uri> item : scan.metadataUris.entrySet()) {
            if (docs.size() >= GameManifestReader.MAX_DOCUMENTS) break;
            try (InputStream input = getContentResolver().openInputStream(item.getValue())) {
                if (input == null) continue;
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                byte[] buf = new byte[4096];
                int total = 0, count;
                while (total < GameManifestReader.MAX_BYTES &&
                        (count = input.read(buf, 0, Math.min(buf.length, GameManifestReader.MAX_BYTES - total))) != -1) {
                    if (count == 0) break;
                    output.write(buf, 0, count);
                    total += count;
                }
                docs.add(new GameManifestReader.Document(item.getKey(),
                        new String(output.toByteArray(), StandardCharsets.UTF_8)));
            } catch (Exception ignored) { // Some SAF providers refuse individual files.
            }
        }
        return GameManifestReader.analyze(docs);
    }

    private ScanResult enumerate(Uri treeUri) {
        List<GameDetector.Entry> entries = new ArrayList<>();
        Map<String, Uri> exeUris = new HashMap<>();
        Map<String, Uri> metadataUris = new HashMap<>();
        ArrayDeque<Node> queue = new ArrayDeque<>();
        queue.add(new Node(DocumentsContract.getTreeDocumentId(treeUri), "", 0));
        boolean truncated = false;
        while (!queue.isEmpty() && entries.size() < LIMIT) {
            Node dir = queue.removeFirst();
            Uri children = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, dir.docId);
            String[] columns = {DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    DocumentsContract.Document.COLUMN_MIME_TYPE,
                    DocumentsContract.Document.COLUMN_SIZE};
            try (Cursor cursor = getContentResolver().query(children, columns, null, null, null)) {
                if (cursor == null) throw new IllegalStateException("مزوّد الملفات لم يرجع قائمة ملفات");
                while (cursor.moveToNext()) {
                    if (entries.size() >= LIMIT) { truncated = true; break; }
                    String id = cursor.getString(0), name = cursor.getString(1), mime = cursor.getString(2);
                    if (id == null || name == null) continue;
                    boolean folder = DocumentsContract.Document.MIME_TYPE_DIR.equals(mime);
                    String path = dir.path.isEmpty() ? name : dir.path + "/" + name;
                    long size = cursor.isNull(3) ? -1 : cursor.getLong(3);
                    entries.add(new GameDetector.Entry(path, folder, size));
                    if (!folder && name.toLowerCase(java.util.Locale.ROOT).endsWith(".exe")) {
                        exeUris.put(path, DocumentsContract.buildDocumentUriUsingTree(treeUri, id));
                    }
                    if (!folder && GameManifestReader.accepts(path, size)
                            && metadataUris.size() < GameManifestReader.MAX_DOCUMENTS) {
                        metadataUris.put(path, DocumentsContract.buildDocumentUriUsingTree(treeUri, id));
                    }
                    if (folder) {
                        if (dir.depth + 1 < MAX_DEPTH) queue.addLast(new Node(id, path, dir.depth + 1));
                        else truncated = true;
                    }
                }
            }
        }
        if (!queue.isEmpty()) truncated = true;
        return new ScanResult(entries, truncated, exeUris, metadataUris);
    }

    private static String report(GameDetector.Detection d, GameManifestReader.Result m,
                                 CompatibilityPlanner.Plan plan) {
        StringBuilder out = new StringBuilder();
        out.append("RM11 AutoCore • تقرير فحص أولي v2.4.10\n\n")
            .append("اللعبة: ").append(d.title).append("\n")
            .append("معرّف مستنتج: ").append(d.gameId).append("\n")
            .append("إصدار ملف التشغيل: ").append(d.version).append("\n")
            .append("ملف التشغيل المرشح: ").append(d.exe.isEmpty() ? "لم يُعثر عليه" : d.exe).append("\n")
            .append("بنية ملف التشغيل: ").append(d.architecture).append("\n")
            .append("محرك اللعبة المحتمل: ").append(d.engine).append("\n")
            .append("الرسومات المعتادة: ").append(d.graphics).append("\n")
            .append("المنصة المحتملة: ").append(d.platform).append("\n")
            .append("معرّف Steam من الملفات: ").append(m.steamAppId.isEmpty() ? "غير موجود" : m.steamAppId).append("\n")
            .append("مصدر اسم اللعبة: ").append(m.evidenceSource.isEmpty() ? "بيانات EXE أو المجلد" : m.evidenceSource).append("\n")
            .append("متطلبات Windows / CPU / RAM الرسمية: تحتاج قاعدة بيانات المطور أو تحققاً خارجياً\n")
            .append("ثقة التعرف: ").append(d.certainty).append("\n")
            .append("عناصر تمت معاينتها: ").append(d.scannedCount).append("\n")
            .append("الفحص مكتمل؟ ").append(d.truncated ? "لا، فحص محدود" : "نعم ضمن العمق المحدد").append("\n\n")
            .append("الأدلة:\n");
        for (String item : d.evidence) out.append("• ").append(item).append("\n");
        out.append("\n━━━━ خطة RM11 Auto Compatibility ━━━━\n")
           .append("حالة الخطة: ").append(plan.state).append("\n")
           .append("جاهزية التشغيل: ").append(plan.launchReadiness).append("\n")
           .append("متطلبات اللعبة الرسمية: ").append(plan.requirements).append("\n")
           .append("مؤشرات الحماية: ").append(plan.protection).append("\n")
           .append("نقطة التوقف: ").append(plan.blockers).append("\n")
           .append("مكونات التشغيل والرسوم (أدوار مبدئية وليست إصدارات):\n");
        for (CompatibilityPlanner.Component c : plan.components) {
            out.append("• ").append(c.id).append(": ").append(c.decision).append("\n")
               .append("  الوظيفة: ").append(c.purpose).append("\n")
               .append("  السبب: ").append(c.reason).append("\n");
        }
        for (String hint : plan.evidence) out.append("• ملاحظة: ").append(hint).append("\n");
        out.append("\nحالة ملف التوافق: غير مختبر\n")
           .append("محرك Windows: غير مدمج بالنسخة الحالية\n")
           .append("لا يوجد تعديل أو نسخ لملفات اللعبة.");
        return out.toString();
    }

    private void storeReport(Uri uri, GameDetector.Detection d, GameManifestReader.Result m,
                             CompatibilityPlanner.Plan plan) throws Exception {
        File dir = new File(getFilesDir(), "profiles");
        if (!dir.exists() && !dir.mkdirs()) throw new IllegalStateException("لا يمكن إنشاء دليل التقارير");
        String fileName = UUID.nameUUIDFromBytes(uri.toString().getBytes(StandardCharsets.UTF_8)) + ".json";
        JSONObject json = new JSONObject();
        json.put("schema", 4);
        json.put("deviceReadiness", DeviceCapabilityProbe.collect(this).toJson());
        json.put("folderUri", uri.toString());
        json.put("gameId", d.gameId);
        json.put("title", d.title);
        json.put("exeProductVersion", d.version);
        json.put("detectionMethod", "generic-pe-local-store-engine-metadata-and-folder-analysis");
        json.put("metadataTitleSource", m.evidenceSource);
        json.put("metadataConfidence", m.confidence);
        json.put("steamAppIdLocalHint", m.steamAppId);
        json.put("officialRequirementsVerified", false);
        json.put("suggestedExe", d.exe);
        json.put("exeArchitecture", d.architecture);
        json.put("engineHint", d.engine);
        json.put("graphicsHint", d.graphics);
        json.put("platformHint", d.platform);
        json.put("versionVerified", false);
        json.put("runtimeReady", false);
        json.put("compatibilityValidated", false);
        json.put("scanTruncated", d.truncated);
        json.put("scannedItems", d.scannedCount);
        json.put("evidence", new JSONArray(d.evidence));
        JSONObject preflight = new JSONObject();
        preflight.put("status", "unverified_preflight");
        preflight.put("state", plan.state);
        preflight.put("launchReadiness", plan.launchReadiness);
        preflight.put("requirements", plan.requirements);
        preflight.put("protection", plan.protection);
        preflight.put("storeHint", plan.store);
        preflight.put("blockers", plan.blockers);
        preflight.put("sourceType", "local-folder-evidence-only");
        preflight.put("officialRequirementsVerified", false);
        preflight.put("runtimeTested", false);
        preflight.put("autoInstallEnabled", false);
        JSONArray componentList = new JSONArray();
        for (CompatibilityPlanner.Component c : plan.components) {
            JSONObject one = new JSONObject();
            one.put("id", c.id);
            one.put("purpose", c.purpose);
            one.put("decision", c.decision);
            one.put("reason", c.reason);
            one.put("binaryVersion", JSONObject.NULL);
            one.put("compatibilityVerified", false);
            componentList.put(one);
        }
        preflight.put("components", componentList);
        preflight.put("evidence", new JSONArray(plan.evidence));
        json.put("compatibilityPreflight", preflight);
        try (FileOutputStream stream = new FileOutputStream(new File(dir, fileName))) {
            stream.write(json.toString(2).getBytes(StandardCharsets.UTF_8));
        }
    }

    private int dp(int dp) { return Math.round(getResources().getDisplayMetrics().density * dp); }
    private LinearLayout.LayoutParams margins(int left, int top, int right, int bottom) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(-1, -2);
        p.setMargins(dp(left), dp(top), dp(right), dp(bottom));
        return p;
    }
    private GradientDrawable boxColor(int color) {
        GradientDrawable shape = new GradientDrawable();
        shape.setColor(color);
        shape.setCornerRadius(dp(14));
        return shape;
    }
    private TextView label(String text, int sp, int color, boolean heavy) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextSize(sp);
        view.setTextColor(color);
        view.setGravity(Gravity.RIGHT);
        if (heavy) view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        view.setLineSpacing(dp(3), 1.0f);
        return view;
    }
    private Button action(String text) {
        Button b = new Button(this);
        b.setText(text);
        b.setTextColor(Color.WHITE);
        b.setAllCaps(false);
        b.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFF235AA1));
        return b;
    }

    @Override protected void onDestroy() {
        scanExecutor.shutdownNow();
        super.onDestroy();
    }
}
