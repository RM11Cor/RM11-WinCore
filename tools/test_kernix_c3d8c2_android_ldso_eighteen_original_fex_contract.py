# SPDX-License-Identifier: MIT
"""C3-D8C2 Android original ld-linux source/stack/SSE FEX source checks.

This is compile-source policy validation, NOT a handset execution result.
"""
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]
HOST=ROOT/"native-engine/android-host/kernix_g2e_c3d8c2_android_original_ldso_eighteen_fex_child.cpp"
APP=ROOT/"native-engine/android-c3d8c2-original-fex-ldso-eighteen-probe-app"
UI=APP/"app/src/main/java/org/kernix/originalfexldso18/MainActivity.java"
CI=ROOT/".github/workflows/kernix-g2e-c3d8c2-android-original-ldso-eighteen-fex-debug-apk.yml"

class C3D8C2AuthenticAndroid18Gate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cpp=HOST.read_text()
        cls.ui=UI.read_text()
        cls.workflow=CI.read_text()
        cls.gradle=(APP/"app/build.gradle").read_text()

    def test_source_original_18_instructions_with_nineteenth_bounded_hlt(self):
        for needle in (
            "std::array<uint8_t,64> kOriginal64",
            "kOriginalFivePushBytes=9",
            "kOriginalSixteenthSUBBytes=7",
            "kOriginalSeventeenthMOVBytes=7",
            "kOriginalEighteenthMOVAPSBytes=4",
            "kGuestStackBytes==192 && kNextInstructionOffset==63",
            "std::memcmp(source64,kOriginal64.data(),kOriginal64.size())",
            "targetByte[c8c2::kNextInstructionOffset]=c8c2::kInjectedHLT",
            "targetByte[c8c2::kNextInstructionOffset]=kOriginal64[c8c2::kNextInstructionOffset]",
            "OriginalFileBackedBytesRestored",
            "saved[6]",
            "storedRDI==originalRSP",
            "storedXMM[0]",
            "storedXMM[1]",
            "cpu.gregs[FEXCore::X86State::REG_RSP]!=originalRSP-c8c2::kGuestStackBytes",
            "ctx->ExecuteThread(thread)",
            "EnableExitOnHLT",
            "DenyAllGuestSyscalls",
            "OriginalFEXGuardedCallRetStack",
        ):
            self.assertIn(needle,self.cpp,needle)
        self.assertNotIn("MAP_FIXED",self.cpp)

    def test_exact_child_pass_lines_match_java_protocol(self):
        native=re.findall(r'std::puts\("([^"]+)"\);',self.cpp)
        self.assertEqual(native[0],
            "KERNIX_C3D8C2_ANDROID_DEVICE_SOURCE_ORIGINAL_LDSO_EIGHTEEN_FEX_INSTRUCTIONS_PASS")
        expected=re.findall(r'"([A-Z0-9_]+=[01])"',
            self.ui.split("String[] expectedLines={",1)[1]
                   .split("if(lines.length!=expectedLines.length)",1)[0])
        self.assertEqual(native[1:],expected)
        self.assertIn("SOURCE_NINETEENTH_RDTSC_EXECUTED=0",expected)
        self.assertIn("SOURCE_GUEST_192_STACK_AND_HOST_STACK_RESTORED=1",expected)
        self.assertIn("COMPLETE_LDSO_DYNAMIC_LINKER_STARTUP=0",expected)
        self.assertIn("WINE_OR_WINDOWS_PE_EXECUTED=0",expected)

    def test_distinct_app_and_bounded_output_and_pinned_elf_and_fex(self):
        self.assertIn("applicationId 'org.kernix.originalfexldso18'",self.gradle)
        for word in (
            "runner.sha256", "fexcore.sha256",
            "sha256(core).equals(expectedCore)",
            "sha256(runner).equals(expected)",
            "child.waitFor(25,TimeUnit.SECONDS)",
            "builder.redirectOutput(trace)",
            "traceTail(trace)",
            "new AlertDialog.Builder",):
            self.assertIn(word,self.ui)
        self.assertIn("--kernix-c3d8c2-source-original-ldso-eighteen-instructions-v1",self.cpp)
        self.assertIn("--kernix-c3d8c2-source-original-ldso-eighteen-instructions-v1",self.ui)
        self.assertIn("/data/user/0/org.kernix.originalfexldso18/files/",self.cpp)
        self.assertIn("FEX-Emu/FEX.git",self.workflow)
        self.assertIn("app:assembleDebug",self.workflow)
        self.assertIn("libFEXCore.so",self.workflow)
        self.assertIn("KERNIX-C3D8C2-Real-FEX-Original-Ldso-Eighteen-DEBUG.apk",self.workflow)
        self.assertNotIn("app:assembleRelease",self.workflow)
        self.assertNotIn("gh release create",self.workflow)

if __name__=="__main__":
    unittest.main()
