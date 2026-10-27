package com.rm11.autocore.runtime;

/** Device-driver exceptions are evidence, never success; no frame means no WSI proof. */
public final class X11VulkanBundleVerdict {
    private X11VulkanBundleVerdict(){}
    public static String classify(String output){
        if(output==null||output.isEmpty())return "CHILD_EMPTY_OR_DRIVER_ABORT";
        if(output.contains("RM11_V473_PRIVATE_LOADER=DLOPEN_FAILED"))
            return "PRIVATE_ELF_LINKAGE_FAILED";
        if(output.contains("RM11_V473_PROBE_STATUS=INSTANCE_CREATE_FAILED"))
            return "MESA_ICD_CREATE_INSTANCE_FAILED";
        if(output.contains("RM11_V473_PROBE_STATUS=INSTANCE_AND_DEVICE_QUERY_COMPLETE_WSI_UNVERIFIED")){
            if(output.contains("RM11_V473_KHR_XCB_SURFACE=true")
               ||output.contains("RM11_V473_KHR_XLIB_SURFACE=true"))
                return "X11_EXTENSION_PRESENT_DEVICE_QUERY_COMPLETE_PRESENTATION_UNVERIFIED";
            return "PHYSICAL_DEVICE_ENUMERATED_X11_EXTENSION_MISSING";
        }
        if(output.contains("RM11_V473_PROBE_STATUS=EXTENSIONS_FAILED_OR_EXCESS")
           ||output.contains("RM11_V473_PROBE_STATUS=EXTENSIONS_LIST_FAILED"))
            return "VULKAN_LOADER_INSTANCE_ENUMERATION_FAILED";
        return "CHILD_INCOMPLETE_OR_NATIVE_ABORT";
    }
}
