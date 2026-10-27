package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;
public final class X11VulkanBundleVerdictTest {
    @Test public void x11ExtensionAndDeviceIsNotPresentation() {
        String log="RM11_V473_KHR_XCB_SURFACE=true\n"
            +"RM11_V473_PHYSICAL_DEVICE_COUNT=1\n"
            +"RM11_V473_PROBE_STATUS=INSTANCE_AND_DEVICE_QUERY_COMPLETE_WSI_UNVERIFIED\n";
        assertEquals("X11_EXTENSION_PRESENT_DEVICE_QUERY_COMPLETE_PRESENTATION_UNVERIFIED",
            X11VulkanBundleVerdict.classify(log));
    }
    @Test public void missingWsiAndFailedLoaderNeverQualify() {
        assertEquals("PHYSICAL_DEVICE_ENUMERATED_X11_EXTENSION_MISSING",
            X11VulkanBundleVerdict.classify(
                "RM11_V473_KHR_XLIB_SURFACE=false\n"
               +"RM11_V473_PROBE_STATUS=INSTANCE_AND_DEVICE_QUERY_COMPLETE_WSI_UNVERIFIED\n"));
        assertEquals("PRIVATE_ELF_LINKAGE_FAILED",
            X11VulkanBundleVerdict.classify(
                "RM11_V473_PRIVATE_LOADER=DLOPEN_FAILED\n"));
        assertEquals("CHILD_EMPTY_OR_DRIVER_ABORT",X11VulkanBundleVerdict.classify(""));
    }
}
