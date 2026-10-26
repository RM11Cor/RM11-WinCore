package com.rm11.autocore.runtime;

/** Pure, unit-testable annotations for the Android-only FreeType pilot. */
public final class FontSandboxEvidence {
    private FontSandboxEvidence(){}
    public static String classify(String report){
        if(report==null || !report.contains("RM11_V445_SEPARATE_ANDROID_PROCESS=true"))
            return "RM11_V445_RESULT_INDETERMINATE";
        if(report.contains("RM11_V445_BARE_SONAME=NOT_FOUND")
            && report.contains("RM11_V445_SIGNED_ABSOLUTE=SUCCESS"))
            return "RM11_V445_ANDROID_LINKER_NAME_GAP_OBSERVED";
        if(report.contains("RM11_V445_BARE_SONAME=SUCCESS")
            && report.contains("RM11_V445_SIGNED_ABSOLUTE=SUCCESS"))
            return "RM11_V445_ANDROID_LINKER_BOTH_LOADERS_AVAILABLE";
        if(report.contains("RM11_V445_SIGNED_ABSOLUTE=FAILED"))
            return "RM11_V445_SIGNED_NATIVE_FREETYPE_DLOPEN_FAILED";
        return "RM11_V445_RESULT_INDETERMINATE";
    }
}
