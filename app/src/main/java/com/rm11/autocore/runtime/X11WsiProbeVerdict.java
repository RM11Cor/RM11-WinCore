package com.rm11.autocore.runtime;

/** Pure offline classification; a child loader result never proves presentation. */
public final class X11WsiProbeVerdict {
    private X11WsiProbeVerdict(){}
    public static String classify(String nativeOutput) {
        if(nativeOutput==null||nativeOutput.isEmpty())
            return "NO_CHILD_OUTPUT_OR_DRIVER_ABORT";
        if(nativeOutput.contains("RM11_V472_X11_VULKAN_WSI=INSTANCE_EXTENSIONS_ABSENT"))
            return "NATIVE_ANDROID_LOADER_CANNOT_PROVIDE_X11_WSI";
        if(nativeOutput.contains("RM11_V472_X11_VULKAN_WSI=INSTANCE_EXTENSIONS_PRESENT_SURFACE_UNVERIFIED"))
            return "X11_INSTANCE_EXTENSIONS_PRESENT_PRESENTATION_UNVERIFIED";
        if(nativeOutput.contains("RM11_V472_X11_VULKAN_WSI=LOADER_UNAVAILABLE"))
            return "ANDROID_VULKAN_LOADER_MISSING";
        if(nativeOutput.contains("RM11_V472_X11_VULKAN_WSI=TRUNCATED_UNVERIFIED"))
            return "INSTANCE_EXTENSIONS_OVERFLOW_UNVERIFIED";
        if(nativeOutput.contains("RM11_V472_X11_VULKAN_WSI=ENUMERATION_FAILED")
            ||nativeOutput.contains("RM11_V472_X11_VULKAN_WSI=ENUMERATION_INCOMPLETE")
            ||nativeOutput.contains("RM11_V472_X11_VULKAN_WSI=EXTENSION_QUERY_UNAVAILABLE"))
            return "INSTANCE_EXTENSION_QUERY_FAILED";
        return "PROBE_INCOMPLETE_OR_NATIVE_ABORT";
    }
}
