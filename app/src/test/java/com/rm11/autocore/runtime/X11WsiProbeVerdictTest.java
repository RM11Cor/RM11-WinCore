package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

public final class X11WsiProbeVerdictTest {
    @Test public void androidSurfaceIsNotX11() {
        String onlyAndroid="RM11_V472_KHR_SURFACE=true\n"
             +"RM11_V472_KHR_XCB_SURFACE=false\n"
             +"RM11_V472_KHR_XLIB_SURFACE=false\n"
             +"RM11_V472_KHR_ANDROID_SURFACE=true\n"
             +"RM11_V472_X11_VULKAN_WSI=INSTANCE_EXTENSIONS_ABSENT\n";
        assertEquals("NATIVE_ANDROID_LOADER_CANNOT_PROVIDE_X11_WSI",
                     X11WsiProbeVerdict.classify(onlyAndroid));
    }
    @Test public void xcbExtensionIsOnlyPrecondition() {
        assertEquals("X11_INSTANCE_EXTENSIONS_PRESENT_PRESENTATION_UNVERIFIED",
          X11WsiProbeVerdict.classify(
             "RM11_V472_X11_VULKAN_WSI=INSTANCE_EXTENSIONS_PRESENT_SURFACE_UNVERIFIED\n"));
    }
    @Test public void nativeAbortHasNoSuccessVerdict() {
        assertEquals("NO_CHILD_OUTPUT_OR_DRIVER_ABORT",X11WsiProbeVerdict.classify(""));
        assertEquals("PROBE_INCOMPLETE_OR_NATIVE_ABORT",
            X11WsiProbeVerdict.classify("RM11_V472_ANDROID_VULKAN_LOADER_DLOPEN=SUCCESS\n"));
    }
}
