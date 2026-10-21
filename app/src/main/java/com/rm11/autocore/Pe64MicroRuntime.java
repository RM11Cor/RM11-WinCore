package com.rm11.autocore;

import android.content.Context;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/** Bounded micro-PE32+ smoke test: NOT a full Windows process or game launcher. */
public final class Pe64MicroRuntime {
    private Pe64MicroRuntime() { }
    private static final int LIMIT = 512 * 1024;
    private static final boolean LOADED;
    static {
        boolean ok;
        try { System.loadLibrary("rm11_pe64_micro"); ok = true; }
        catch (LinkageError | SecurityException e) { ok = false; }
        LOADED = ok;
    }
    private static native String nativeRun(byte[] peFile);

    public static String runBundledSmokeTest(Context context) {
        if (!LOADED) return "مكتبة ترجمة x86-64 إلى ARM64 غير متاحة داخل APK.";
        try (InputStream stream = context.getAssets().open("rm11-smoke-pe64.exe")) {
            ByteArrayOutputStream sink = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int n;
            while ((n = stream.read(buffer)) != -1) {
                if (sink.size() + n > LIMIT) return "ملف PE64 أكبر من حد الاختبار الآمن.";
                sink.write(buffer, 0, n);
            }
            JSONObject result = new JSONObject(nativeRun(sink.toByteArray()));
            boolean passed = result.optBoolean("executed", false) && result.optInt("result") == 42;
            return "RM11 v2.4.15 — Windows PE64 micro-execution\n\n"
                    + "ملف الاختبار: PE32+ x86-64 مستقل داخل APK\n"
                    + "فحص صيغة EXE: " + (result.optBoolean("peParsed") ? "PASS" : "FAIL") + "\n"
                    + "ترجمة x86-64 إلى ARM64: " + (result.optBoolean("translated") ? "PASS" : "FAIL") + "\n"
                    + "تنفيذ ARM64 JIT: " + (passed ? "PASS (42)" : "FAIL / NOT READY") + "\n"
                    + "حالة المعالجة: " + result.optString("status") + "\n"
                    + "تعليمات ARM64 المنتجة: " + result.optInt("armInstructions") + "\n"
                    + "تعليمات x86 المقروءة (bytes): " + result.optInt("x86Bytes") + "\n"
                    + "Entry RVA: 0x" + Integer.toHexString(result.optInt("entryRva")) + "\n\n"
                    + "FEXCore: غير مدمج | Wine/Proton: غير مدمج\n"
                    + "DXVK/Turnip: غير مدمجين | تشغيل الألعاب: غير جاهز\n\n"
                    + "النجاح يعني تشغيل ملف PE64 تعليمي بأوامر محدودة فقط،"
                    + " وليس تشغيل ألعاب Windows أو استدعاءات Win32.";
        } catch (Exception e) {
            return "تعذر فحص Windows PE64 التجريبي: " + e.getClass().getSimpleName()
                    + " — " + e.getMessage();
        }
    }
}
