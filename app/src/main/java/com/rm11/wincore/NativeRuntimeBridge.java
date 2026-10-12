package com.rm11.wincore;

/**
 * Calls our own packaged ARM64 native library through JNI. A smoke test only:
 * not a Wine/Box64 installer and not an executable launcher.
 */
public final class NativeRuntimeBridge {
    private static final String loadIssue;
    static {
        String issue = null;
        try {
            System.loadLibrary("rm11probe");
        } catch (UnsatisfiedLinkError | SecurityException e) {
            issue = e.getClass().getSimpleName() + ": " + e.getMessage();
        }
        loadIssue = issue;
    }
    private NativeRuntimeBridge() {}
    private static native String nativeSelfTest();
    private static native String nativeAdapterTest();

    /** Executes a versioned C ABI call to our separate packaged ARM64 .so. */
    public static String inspectAdapter() {
        if (loadIssue != null) return "[FAIL] JNI load failed: " + loadIssue;
        try {
            return nativeAdapterTest();
        } catch (UnsatisfiedLinkError | SecurityException e) {
            return "[FAIL] Adapter call failed: " + e.getMessage();
        } catch (Exception e) {
            return "[FAIL] Adapter exception: " + e.getClass().getSimpleName();
        }
    }

    public static String inspect() {
        if (loadIssue != null) return "[FAIL] Native APK library load error: " + loadIssue;
        try {
            return nativeSelfTest();
        } catch (UnsatisfiedLinkError | SecurityException e) {
            return "[FAIL] Native JNI invocation failed: " + e.getMessage();
        } catch (Exception e) {
            return "[FAIL] Native probe error: " + e.getClass().getSimpleName();
        }
    }
}
