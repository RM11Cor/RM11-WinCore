package com.rm11.autocore;

import org.json.JSONObject;

/** JNI bridge to the APK-bundled ARM64 host test. Not a Windows EXE runtime. */
public final class RuntimeNativeProbe {
    private RuntimeNativeProbe() { }

    private static final boolean NATIVE_LOADED;
    private static final String LOAD_ERROR;
    static {
        boolean loaded = false;
        String error = "";
        try {
            System.loadLibrary("rm11_runtime_bootstrap");
            loaded = true;
        } catch (LinkageError | SecurityException e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        }
        NATIVE_LOADED = loaded;
        LOAD_ERROR = error;
    }

    private static native String nativeProbe();

    /** Uses only this app's native library; never launches a game or imports external code. */
    public static String inspect() {
        if (!NATIVE_LOADED) {
            return "RM11 Native Runtime Host\nفشل تحميل مكتبة ARM64: " + LOAD_ERROR
                    + "\nWindows EXE: غير جاهز";
        }
        try {
            JSONObject data = new JSONObject(nativeProbe());
            boolean jit = data.optBoolean("jitOk", false);
            int returned = data.optInt("jitReturned", 0);
            boolean tested = jit && returned == 42;
            // These flags must only be set after real integration and runtime verification.
            boolean launchPrerequisites = RuntimePrerequisites.allVerified(
                    tested, false, false, false, false);
            return "RM11 Native Runtime Host v2.4.14\n\n"
                    + "ABI: " + data.optString("machine", "unknown") + "\n"
                    + "NDK native library: LOADED\n"
                    + "ARM64 JIT RW→RX execution: " + (tested ? "PASS (42)" : "FAIL / BLOCKED") + "\n"
                    + "OS error code: " + data.optInt("osError", -1) + "\n\n"
                    + "x86 translator (FEXCore): NOT INTEGRATED\n"
                    + "Wine/Proton Windows backend: NOT INTEGRATED\n"
                    + "DXVK/Turnip runtime bridge in RM11: NOT INTEGRATED\n"
                    + "Direct game file mapping: NOT INTEGRATED\n"
                    + "EXE readiness: " + (launchPrerequisites ? "PREREQUISITES VERIFIED" : "BLOCKED") + "\n\n"
                    + "هذا فحص تنفيذ شيفرة ARM64 مولّدة داخل التطبيق، وليس تشغيل Windows EXE."
                    + "\nلا يُعدّل ملفات الألعاب أو مفاتيح التوقيع.";
        } catch (Exception | LinkageError e) {
            return "RM11 Native Runtime Host: فشل الاختبار: "
                    + e.getClass().getSimpleName() + ": " + e.getMessage()
                    + "\nWindows EXE: غير جاهز";
        }
    }
}
