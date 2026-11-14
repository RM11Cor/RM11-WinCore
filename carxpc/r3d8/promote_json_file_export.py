#!/usr/bin/env python3
"""R3D8: Export genuine on-device 07D JSON to Android Downloads automatically.

Run AFTER R3D4, R3D6 and R3D7 promoters in the existing source-pinned
CarX Android build. This changes ONLY the UI and report export, not guest
memory, Wine, FEX, syscall witness, or the report's diagnostic status.
"""
from pathlib import Path
import re,shutil,sys
if len(sys.argv)!=2:
    raise SystemExit("usage: promote_json_file_export.py /tmp/carxpc")

app=Path(sys.argv[1])
root=app/"app/src/main/java/com/r4/carxpc"
main=root/"MainActivity.java"
probe=root/"R3D4ProbeActivity.java"
gradle=app/"app/build.gradle"
source=Path("carxpc/r3d8/android/R3D8JsonReportStore.java")
target=root/source.name
assert all(p.is_file() for p in (main,probe,gradle,source))
assert not target.exists()
shutil.copyfile(source,target)

def one(s,old,new):
    count=s.count(old)
    assert count==1,("EXPECTED_EXACT_SOURCE_ANCHOR",old[:120],count)
    return s.replace(old,new,1)

s=gradle.read_text()
s,n=re.subn(r"\bversionCode\s+34\b","versionCode 35",s)
assert n==1,"R3D8_EXPECTS_R3D7_34"
s,n=re.subn(r"versionName\s+'[^']+'",
    "versionName '0.35-r3d8-auto-json-downloads-export'",s)
assert n==1
gradle.write_text(s)

s=main.read_text()
s=one(s,"10 | R3D7 — تشخيص تعليق أو انهيار FEX بعد N10",
      "10 | R3D8 — تقرير Wine 07D إلى ملف JSON")
main.write_text(s)

s=probe.read_text()
s=one(s,"import android.content.Intent;",
  "import android.content.Intent;\n"+
  "import android.content.ClipData;\n"+
  "import android.net.Uri;\n"+
  "import android.widget.ScrollView;\n"+
  "import java.io.OutputStream;")

s=one(s,
'''    private TextView output;
    private Button run;''',
'''    private TextView output;
    private TextView headline;
    private TextView fileStatus;
    private Button run;
    private Button saveFile;
    private Button shareFile;
    private Uri savedUri;
    private String savedFileName;''')

s=one(s,'setTitle("CarX R3D7 | FEX / Wine 07D");',
        'setTitle("CarX R3D8 | FEX / Wine 07D");')

s=one(s,
'''        layout.addView(output);
        run = new Button(this);''',
'''        headline = new TextView(this);
        headline.setTextSize(18);
        headline.setText("07D: NOT_TESTED — تشغيل تشخيص Wine");
        layout.addView(headline);
        run = new Button(this);''')

s=one(s,
'''        Button share = new Button(this);
        share.setText("مشاركة التقرير");
        layout.addView(share);
        setContentView(layout);
        run.setOnClickListener(v -> startProbe());
        share.setOnClickListener(v -> {
            if (lastReport == null) return;
            Intent send = new Intent(Intent.ACTION_SEND);
            send.setType("text/plain");
            send.putExtra(Intent.EXTRA_TEXT, lastReport);
            startActivity(Intent.createChooser(send, "مشاركة تقرير R3D4"));
        });''',
'''        saveFile = new Button(this);
        saveFile.setText("حفظ تقرير JSON في التنزيلات");
        saveFile.setEnabled(false);
        layout.addView(saveFile);
        shareFile = new Button(this);
        shareFile.setText("مشاركة ملف تقرير JSON");
        shareFile.setEnabled(false);
        layout.addView(shareFile);
        fileStatus = new TextView(this);
        fileStatus.setTextSize(15);
        fileStatus.setText("بعد انتهاء الفحص سيُحفظ ملف JSON تلقائياً في Downloads.");
        layout.addView(fileStatus);
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(false);
        scroll.addView(output);
        layout.addView(scroll, new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));
        setContentView(layout);
        run.setOnClickListener(v -> startProbe());
        saveFile.setOnClickListener(v -> {
            if (lastReport == null) return;
            if (savedUri != null) {
                fileStatus.setText("ملف التشخيص موجود: Downloads/" +
                    savedFileName + " — افتح تطبيق الملفات ثم التنزيلات.");
            } else if (!saveReportToDownloads()) {
                openSystemSavePicker();
            }
        });
        shareFile.setOnClickListener(v -> {
            if (lastReport == null) return;
            if (savedUri == null && !saveReportToDownloads()) {
                openSystemSavePicker();
                return;
            }
            Intent send = new Intent(Intent.ACTION_SEND);
            send.setType("application/json");
            send.putExtra(Intent.EXTRA_STREAM, savedUri);
            send.setClipData(ClipData.newRawUri("CarX 07D JSON", savedUri));
            send.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(Intent.createChooser(send, "إرسال ملف تشخيص CarX JSON"));
        });''')

s=one(s,
'''        lastReport = null;
        probeStartedAtMs=System.currentTimeMillis();
        File f = new File''',
'''        lastReport = null;
        savedUri = null;
        savedFileName = null;
        saveFile.setEnabled(false);
        shareFile.setEnabled(false);
        headline.setText("07D: RUNNING — جاري التشخيص");
        fileStatus.setText("سيُنشأ ملف JSON تلقائياً بعد ظهور النتيجة.");
        File f = new File''')

s=one(s,
'''            lastReport=report.toString(2);
            output.setText("07D: "+state+"\\n\\n"+lastReport);''',
'''            lastReport=report.toString(2);
            headline.setText("07D: "+state+" | آخر مرحلة: "+
                report.optString("last_probe_phase","UNKNOWN"));
            output.setText(lastReport);
            saveFile.setEnabled(true);
            shareFile.setEnabled(true);
            saveReportToDownloads();''')

s=one(s,
'''            output.setText("07D: REPORT_REJECTED "+t.getClass().getSimpleName());
        }
    }
}''',
'''            headline.setText("07D: REPORT_REJECTED");
            fileStatus.setText("تعذر إنشاء تقرير JSON: "+
                t.getClass().getSimpleName());
            output.setText("07D: REPORT_REJECTED "+t.getClass().getSimpleName());
        }
    }

    // Automatic user-accessible output: Downloads/CarX_PC_R3D8_07D_Diagnostics_*.json
    // Unlike plain text sharing, this creates a real attachable .json file.
    private boolean saveReportToDownloads() {
        if (lastReport == null) return false;
        try {
            R3D8JsonReportStore.Saved saved =
                R3D8JsonReportStore.save(this, lastReport, sessionNonce);
            savedUri = saved.uri;
            savedFileName = saved.filename;
            fileStatus.setText("تم حفظ التقرير JSON بنجاح في التنزيلات:\\n"+
                "Downloads/" + savedFileName +
                "\\nتقدر ترفق الملف مباشرة بالمحادثة.");
            return true;
        } catch (Throwable error) {
            savedUri = null;
            savedFileName = null;
            fileStatus.setText("فشل الحفظ التلقائي: "+
                error.getClass().getSimpleName() +
                "\\nاضغط (حفظ تقرير JSON) لاختيار المكان يدوياً.");
            return false;
        }
    }

    private static final int CREATE_JSON_DOCUMENT_REQUEST = 7831;
    private void openSystemSavePicker() {
        if (lastReport == null) return;
        Intent save = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        save.addCategory(Intent.CATEGORY_OPENABLE);
        save.setType("application/json");
        save.putExtra(Intent.EXTRA_TITLE,
            R3D8JsonReportStore.filename(sessionNonce));
        startActivityForResult(save, CREATE_JSON_DOCUMENT_REQUEST);
    }

    @Override protected void onActivityResult(int requestCode,int resultCode,
                                              Intent data) {
        super.onActivityResult(requestCode,resultCode,data);
        if (requestCode != CREATE_JSON_DOCUMENT_REQUEST ||
            resultCode != RESULT_OK || data == null ||
            data.getData() == null || lastReport == null) return;
        Uri uri=data.getData();
        try (OutputStream out=getContentResolver().openOutputStream(uri,"w")) {
            if (out == null) throw new java.io.IOException("EMPTY_DOCUMENT_STREAM");
            out.write(lastReport.getBytes(StandardCharsets.UTF_8));
            out.flush();
            savedUri = uri;
            savedFileName = "JSON محفوظ عبر منتقي ملفات أندرويد";
            fileStatus.setText("تم حفظ ملف التقرير JSON بالمكان الذي اخترته. "+
                "تقدر ترفقه بالمحادثة.");
        } catch (Throwable error) {
            savedUri = null;
            savedFileName = null;
            fileStatus.setText("فشل حفظ الملف: "+error.getClass().getSimpleName());
        }
    }
}''')

for marker in ["getHistoricalProcessExitReasons","child_process_exit_detail",
               "phase_events","last_probe_phase",
               "OBSERVED_SOURCE_LOCKED_X86_SYSCALL_IN_FEX_CALLBACK",
               "R3D8JsonReportStore.save","Intent.ACTION_CREATE_DOCUMENT",
               "Intent.EXTRA_STREAM","ScrollView","saveReportToDownloads();"]:
    assert marker in s,marker
assert 'send.setType("text/plain")' not in s
probe.write_text(s)
print("CARX_R3D8_REAL_JSON_AUTO_SAVE_AND_SHARE_SOURCE_PATCH_PASS")
print("CARX_R3D8_NO_GUEST_EXECUTION_OR_WITNESS_CHANGE")
