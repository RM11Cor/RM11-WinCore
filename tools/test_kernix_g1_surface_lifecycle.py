# SPDX-License-Identifier: MIT
"""Static G1 SurfaceView new-extent Vulkan WSI contract, never phone claims."""
import unittest
from pathlib import Path
R=Path(__file__).resolve().parents[1]
class G1SurfaceLifecycle(unittest.TestCase):
    def test_bounded_two_native_session_and_swapchain_recreate(self):
        a=R/"native-engine/android-g1-surface-lifecycle-probe-app"
        java=(a/"app/src/main/java/org/kernix/g1surface/MainActivity.java").read_text()
        jni=(R/"native-engine/android-host/kernix_g1_surface_lifecycle_probe_jni.c").read_text()
        ci=(R/".github/workflows/kernix-g1-surface-lifecycle-android-debug-apk.yml").read_text()
        wsi=(R/"native-engine/android-host/kernix_swapchain.c").read_text()
        for word in ("root.removeView(viewport)","viewport=makeSurface()",
                     "root.addView(viewport,2,","WINDOW_EXTENT_CHANGED=",
                     "NEW_SURFACE_CREATED=","G1_SURFACE_RECREATION_TWO_SESSION_PASS=",
                     "G1_SURFACE_CHANGED_DURING_NATIVE=1","generation.get()",
                     "PERSISTENT_RENDER_LOOP=0","WINE_PROTON_GAMES_EXECUTED=0"):
            self.assertIn(word,java)
        self.assertIn("nativeProbe(surface)",java)
        self.assertIn("Java_org_kernix_g1surface_MainActivity_nativeProbe",jni)
        self.assertIn("frame<48u",wsi)
        self.assertIn("vkCreateSwapchainKHR",wsi)
        self.assertIn("applicationId 'org.kernix.g1surface'",(a/"app/build.gradle").read_text())
        self.assertIn("-DKERNIX_G1_VISUAL_TEST",ci)
        self.assertIn("actions/upload-artifact@v4",ci)
        self.assertNotIn("assembleRelease",ci)
if __name__=="__main__":
    unittest.main()
