# SPDX-License-Identifier: MIT
from pathlib import Path
import unittest
R=Path(__file__).resolve().parents[1]
class G1Steady180(unittest.TestCase):
 def test_isolated_bounded_single_swapchain(self):
  c=(R/"native-engine/android-host/kernix_g1_steady180_swapchain.c").read_text()
  j=(R/"native-engine/android-g1-steady180-probe-app/app/src/main/java/org/kernix/g1steady/MainActivity.java").read_text()
  n=(R/"native-engine/android-host/kernix_g1_steady180_probe_jni.c").read_text()
  w=(R/".github/workflows/kernix-g1-steady180-android-debug-apk.yml").read_text()
  for s in ("frame<180u","vkCreateSwapchainKHR","vkQueuePresentKHR","usleep(33000u)","atomic_load_explicit","kernix_g1_steady_cancel"): self.assertIn(s,c)
  for s in ("private static native void nativeCancel()","G1_STEADY_180_FRAMES_QUEUED","G1_STEADY_TWO_SESSIONS_QUEUE_PASS","onPause()","surfaceDestroyed","nativeResult[10]==180","nativeResult[11]==180","UNBOUNDED_RENDERER_PROVEN=0"): self.assertIn(s,j)
  self.assertIn("Java_org_kernix_g1steady_MainActivity_nativeCancel",n)
  self.assertIn("KERNIX-G1-Steady180-Android-DEBUG.apk",w)
  self.assertNotIn("assembleRelease",w)
if __name__=="__main__":
 unittest.main()
