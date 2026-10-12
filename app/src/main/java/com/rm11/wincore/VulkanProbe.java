package com.rm11.wincore;

/** Inspects the Vulkan driver exposed by the actual phone, not a presumed GPU specification. */
public final class VulkanProbe {
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
    private VulkanProbe() {}
    private static native String nativeInspect();

    public static String inspect() {
        if (loadIssue != null) return "تعذر تحميل فاحص Vulkan الأصلي: " + loadIssue;
        try {
            return nativeInspect();
        } catch (Throwable error) {
            return "فشل فحص Vulkan: " + error.getClass().getSimpleName() + " " + error.getMessage();
        }
    }
}
