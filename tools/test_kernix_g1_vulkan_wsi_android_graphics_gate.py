# SPDX-License-Identifier: MIT
"""Source-only G1 Vulkan WSI Android stage gate.

A green CI build proves an Android-ABI Vulkan diagnostic APK compiles,
NOT that VK_KHR_swapchain works on a physical phone or games run.
"""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/"native-engine/android-g1-vulkan-wsi-probe-app"
CPP=ROOT/"native-engine/android-host/kernix_g1_vulkan_wsi_probe_jni.c"
WSI=ROOT/"native-engine/android-host/kernix_swapchain.c"
JAVA=APP/"app/src/main/java/org/kernix/g1vulkanprobe/MainActivity.java"
WORKFLOW=ROOT/".github/workflows/kernix-g1-vulkan-wsi-android-debug-apk.yml"

class AndroidWSIGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c=CPP.read_text()
        cls.wsi=WSI.read_text()
        cls.java=JAVA.read_text()
        cls.gradle=(APP/"app/build.gradle").read_text()
        cls.manifest=(APP/"app/src/main/AndroidManifest.xml").read_text()
        cls.ci=WORKFLOW.read_text()

    def test_native_struct_stage_and_queued_frame_not_displayed_claim(self):
        for x in (
            "kernix_swapchain_probe_v1",
            "ANativeWindow_fromSurface",
            "ANativeWindow_release",
            "Java_org_kernix_g1vulkanprobe_MainActivity_nativeProbe",
            "struct kernix_swapchain_report_v1",
            "(*env)->NewIntArray(env,12)",
            "out.frames_attempted",
            "out.frames_completed",
            "out.vk_error_code",
        ):
            self.assertIn(x,self.c)
        for x in (
            "#define KERNIX_SWAPCHAIN_CREATE_FAILED 8u",
            "vkCreateInstance",
            "vkCreateAndroidSurfaceKHR",
            "vkCreateDevice",
            "vkCreateSwapchainKHR",
            "vkAcquireNextImageKHR",
            "vkQueueSubmit",
            "vkQueuePresentKHR",
            "vkDestroySwapchainKHR",
            "vkDestroyDevice",
            "vkDestroySurfaceKHR",
            "vkDestroyInstance",
            "r->frames_attempted++",
            "r->frames_completed++",
            "frame<4u",
            "VK_ERROR_OUT_OF_DATE_KHR",
        ):
            self.assertIn(x,self.wsi)
        self.assertNotIn("Wine",self.c)

    def test_java_requires_second_post_touch_run_and_fails_closed(self):
        for x in (
            'System.loadLibrary("kernix_g1_wsi")',
            "NATIVE_LOADED=ok",
            "SurfaceView",
            "surfaceCreated",
            "surfaceChanged",
            "surfaceDestroyed",
            "onPause()",
            "onDestroy()",
            "AtomicBoolean running",
            "AtomicInteger generation",
            "AtomicInteger touches",
            "gpuWorker.execute",
            "surface.isValid()",
            "requiresTouch && touches.get()==0",
            "nativeResult[1]==0",
            "nativeResult[10]==4",
            "nativeResult[11]==4",
            "firstQueuedPass&&afterTouchQueuedPass",
            "G1_TWO_SESSIONS_QUEUE_PASS",
            "SWAPCHAIN_CREATE_FAILED_MINUS3",
            "PIXELS_VISIBLY_PRESENTED_NOT_ATTESTED=1",
            "PERSISTENT_RENDER_LOOP=0",
            "WINE_OR_WINDOWS_PE_OR_GAMES_EXECUTED=0",
        ):
            self.assertIn(x,self.java,x)
        self.assertNotIn("libraryPresent()",self.java)

    def test_debug_package_and_pipeline_do_not_touch_stable(self):
        self.assertIn("applicationId 'org.kernix.g1vulkanprobe'",self.gradle)
        self.assertIn("versionName '0.1-g1-vulkan-wsi-diagnostic'",self.gradle)
        self.assertIn("android.intent.category.LAUNCHER",self.manifest)
        self.assertIn('android:allowBackup="false"',self.manifest)
        for x in (
            "runs-on: ubuntu-24.04",
            "kernix_g1_vulkan_wsi_probe_jni.c",
            "kernix_swapchain.c",
            "VK_USE_PLATFORM_ANDROID_KHR",
            "aarch64-linux-android26-clang",
            "libkernix_g1_wsi.so",
            "gradle",
            ":app:assembleDebug",
            "apksigner",
            "actions/upload-artifact@v4",
        ):
            self.assertIn(x,self.ci,x)
        self.assertNotIn("assembleRelease",self.ci)
        self.assertNotIn("gh release create",self.ci)

if __name__=="__main__":
    unittest.main()
