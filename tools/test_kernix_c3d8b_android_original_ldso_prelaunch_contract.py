# SPDX-License-Identifier: MIT
"""C3-D8B static safety regression: no device, no signing or execution claim."""
from pathlib import Path
import re
import unittest

REPO = Path(__file__).resolve().parents[1]
APP = REPO / "native-engine/android-c3d8b-original-ldso-probe-app"
CPP = (REPO / "native-engine/android-host/"
       "kernix_g2e_c3d8b_android_original_ldso_prelaunch_child.cpp")


class AndroidC3D8BPrelaunchContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.java = (APP / "app/src/main/java/org/kernix/ldsohandoffprobe/MainActivity.java").read_text()
        cls.gradle = (APP / "app/build.gradle").read_text()
        cls.manifest = (APP / "app/src/main/AndroidManifest.xml").read_text()
        cls.cpp = CPP.read_text()

    def test_distinct_stable_package(self):
        self.assertIn("applicationId 'org.kernix.ldsohandoffprobe'", self.gradle)
        self.assertIn("namespace 'org.kernix.ldsohandoffprobe'", self.gradle)
        self.assertNotIn("org.kernix.host", self.gradle)
        self.assertNotIn("fexrebaseprobe", self.gradle)
        self.assertIn('android:allowBackup="false"', self.manifest)
        self.assertNotIn("INTERNET", self.manifest)

    def test_fixed_original_source_and_root_only(self):
        for value in (
            "9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412",
            "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae",
            "7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906",
            "c3d8b-original-guest",
        ):
            self.assertIn(value, self.java)
        self.assertIn('O_NOFOLLOW', self.cpp)
        self.assertIn('O_DIRECTORY', self.cpp)
        self.assertIn('/data/user/0/org.kernix.ldsohandoffprobe/files/', self.cpp)
        self.assertIn('/data/data/org.kernix.ldsohandoffprobe/files/', self.cpp)
        self.assertIn('native_page_size_not_4096_16K_needs_separate_gate', self.cpp)

    def test_exact_signed_child_and_optin_separate_process(self):
        flag = "--kernix-c3d8b-signed-original-ldso-prelaunch-android-v1"
        marker = "KERNIX_C3D8B_ANDROID_DEVICE_ORIGINAL_LDSO_PRELAUNCH_MEMORY_PASS"
        for value in (flag, marker):
            self.assertIn(value, self.java)
            self.assertIn(value, self.cpp)
        self.assertIn("runner.sha256", self.java)
        self.assertIn("sha256(runner).equals(expected)", self.java)
        self.assertIn("new ProcessBuilder(", self.java)
        self.assertIn("child.waitFor(25,TimeUnit.SECONDS)", self.java)
        self.assertIn("child.destroyForcibly()", self.java)
        self.assertIn("result.indexOf(MARKER)", self.java)
        self.assertIn("result.lastIndexOf(MARKER)", self.java)
        self.assertIn("UNEXPECTED_DEVICE_RESULT_PROTOCOL_REJECTED", self.java)

    def test_actual_wx_guard_and_negative_injection(self):
        for token in (
            "PrepareOriginalOwnedGuestHandoffNoExecute",
            "injected.originalMemoryReleased",
            "guardedGuestStackProtected",
            "allNativeWXRejected",
            "sourceCheckedPTLoadSegments",
            "originalMemoryReleased",
        ):
            self.assertIn(token, self.cpp)
        self.assertIn("O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC", self.cpp)
        self.assertIn("::sysconf(_SC_PAGESIZE)!=4096", self.cpp)

    def test_nonguest_runtime_is_honestly_labeled(self):
        for marker in (
            "FEX_GUEST_CONTEXT_CREATED=0",
            "ORIGINAL_LINUX_LDSO_EXECUTED=0",
            "WINE_OR_WINDOWS_PE_EXECUTED=0",
        ):
            self.assertIn(marker, self.cpp)
            self.assertIn(marker, self.java)
        self.assertNotIn("FEXCore::Context::", self.cpp)
        self.assertNotIn("ExecuteThread", self.cpp)
        self.assertNotIn("libFEXCore.so", self.java)
        self.assertNotIn("libFEXCore.so", self.cpp)
        self.assertNotIn("MAP_FIXED", self.cpp)

if __name__ == "__main__":
    unittest.main()
