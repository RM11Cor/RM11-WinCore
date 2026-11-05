# SPDX-License-Identifier: MIT
"""C3-D8C3 fail-closed Android source-original 21 FEX guest opcode gate.

Static code-policy checks ONLY; never labels compilation or Android run success.
"""
from pathlib import Path
import re
import unittest

REPO=Path(__file__).resolve().parents[1]
CHILD=REPO/"native-engine/android-host/kernix_g2e_c3d8c3_android_original_ldso_twentyone_fex_child.cpp"
APP=REPO/"native-engine/android-c3d8c3-original-fex-ldso-21-probe-app"
JAVA=APP/"app/src/main/java/org/kernix/originalfexldso21/MainActivity.java"
WORKFLOW=REPO/".github/workflows/kernix-g2e-c3d8c3-android-original-ldso-21-fex-debug-apk.yml"


class Original21FEXAndroidGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cpp=CHILD.read_text()
        cls.java=JAVA.read_text()
        cls.gradle=(APP/"app/build.gradle").read_text()
        cls.manifest=(APP/"app/src/main/AndroidManifest.xml").read_text()
        cls.workflow=WORKFLOW.read_text()

    def test_exact_source_original_guest_code_and_native_data_ownership(self):
        for needle in (
            "std::array<uint8_t,80> kOriginal80",
            "kOriginalTwentiethANDBytes=7",
            "kOriginalTwentyFirstLEABytes=7",
            "kOriginalTwentiethStartOffset==65 && kNextInstructionOffset==79",
            "0x0f,0x31,",
            "0x80,0x25,0xde,0x8b,0x01,0x00,0xdf",
            "0x48,0x8d,0x35,0xc1,0x88,0x01,0x00",
            "std::memcmp(source80,kOriginal80.data(),kOriginal80.size())",
            "std::memcpy(&andRel,kOriginal80.data()",
            "std::memcpy(&leaRSIRel,kOriginal80.data()",
            "guestANDAt!=staged.Module(1)->loadBias+uint64_t{0x38e06}",
            "expectedRSI!=staged.Module(1)->loadBias+uint64_t{0x38af0}",
            "const uint8_t guestANDSeed=static_cast<uint8_t>(originalGuestANDByte|0x20u)",
            "postANDByte==expectedGuestANDByte",
            "*guestANDByte=originalGuestANDByte",
            "std::memcmp(targetByte,kOriginal80.data(),kOriginal80.size())",
            "OriginalFileBackedBytesRestored",
            "c8c3::kGuestStackBytes",
            "OriginalFEXGuardedCallRetStack",
            "ctx->ExecuteThread(thread);",
            "DenyAllGuestSyscalls",
            "EnableExitOnHLT",
        ):
            self.assertIn(needle,self.cpp,needle)
        self.assertNotIn("MAP_FIXED",self.cpp)
        self.assertIn(
            'c8c3::Stage("ORIGINAL_RX_RW_PTLOAD_WX_SEPARATED");\\n  constexpr std::array<uint8_t,80> kOriginal80{',
            self.cpp)
        source_bytes=self.cpp.split("constexpr std::array<uint8_t,80> kOriginal80{",1)[1].split("};",1)[0]
        self.assertNotIn("c8c3::Stage(",source_bytes)
        self.assertIn("0xf3,0x0f,0x1e,0xfa,0x55,",source_bytes)

        self.assertNotIn("kernix_g2e_c2_original_fex_actual_syscall_trap_arm64.cpp",self.cpp)

    def test_exact_success_protocol_matches_real_child_output(self):
        marker="KERNIX_C3D8C3_ANDROID_DEVICE_SOURCE_ORIGINAL_LDSO_21_FEX_INSTRUCTIONS_PASS"
        self.assertIn(marker,self.cpp)
        self.assertIn(marker,self.java)
        native=re.findall(r'std::puts\("([^"]+)"\);',self.cpp)
        self.assertEqual(native[0],marker)
        java_block=self.java.split("String[] expectedLines={",1)[1].split(
            "if(lines.length!=expectedLines.length)",1)[0]
        expected=re.findall(r'"([A-Z0-9_]+=[01])"',java_block)
        self.assertEqual(native[1:],expected)
        self.assertIn("ORIGINAL_NINETEENTH_RDTSC_EXECUTED=1",expected)
        self.assertIn("ORIGINAL_TWENTIETH_AND_GUEST_RW_DATA_EXECUTED=1",expected)
        self.assertIn("ORIGINAL_GUEST_RW_DATA_BYTE_RESTORED=1",expected)
        self.assertIn("COMPLETE_LDSO_DYNAMIC_LINKER_STARTUP=0",expected)
        self.assertIn("WINE_OR_WINDOWS_PE_EXECUTED=0",expected)

    def test_bionic_build_isolation_and_failure_diagnostics(self):
        self.assertIn("applicationId 'org.kernix.originalfexldso21'",self.gradle)
        self.assertIn("System.getenv(",self.gradle)
        self.assertIn("<intent-filter>",self.manifest)
        self.assertIn('android.intent.action.MAIN',self.manifest)
        self.assertIn('android.intent.category.LAUNCHER',self.manifest)
        self.assertNotIn("ineighteent-filter",self.manifest)
        self.assertIn("new AlertDialog.Builder",self.java)
        self.assertIn("sha256(runner).equals(expected)",self.java)
        self.assertIn("sha256(core).equals(expectedCore)",self.java)
        self.assertIn("child.waitFor(25,TimeUnit.SECONDS)",self.java)
        self.assertIn("builder.redirectOutput(trace)",self.java)
        self.assertIn("traceTail(trace)",self.java)
        self.assertIn("child.destroyForcibly()",self.java)
        self.assertIn("KERNIX_C3D8C3_STAGE=%s",self.cpp)
        self.assertIn('std::fflush(stderr)',self.cpp)
        self.assertIn("O_DIRECTORY|O_NOFOLLOW",self.cpp)
        self.assertIn("/data/user/0/org.kernix.originalfexldso21/files/",self.cpp)
        self.assertIn("FEX-Emu/FEX.git",self.workflow)
        self.assertIn("app:assembleDebug",self.workflow)
        self.assertNotIn("app:assembleRelease",self.workflow)
        self.assertNotIn("gh release create",self.workflow)


if __name__=="__main__":
    unittest.main()
