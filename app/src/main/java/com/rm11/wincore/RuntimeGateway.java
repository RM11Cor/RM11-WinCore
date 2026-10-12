package com.rm11.wincore;

/**
 * Explicit boundary: this APK is a diagnostics + static executable inspector app.
 * A Wine/Box64 engine is NOT packaged in this version. Do not claim launchers can run.
 * In a later milestone, this gateway will call into a separately licensed Wine runtime.
 */
public final class RuntimeGateway {
    private RuntimeGateway() {}

    public static boolean isInstalled() { return false; }
    public static String currentStatusArabic() {
        return "محرك Wine/Box64 غير مدمج بعد. استيراد ملف EXE لا يثبّته ولا يشغّله.";
    }
}
