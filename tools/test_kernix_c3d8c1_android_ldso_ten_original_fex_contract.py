# SPDX-License-Identifier: MIT
"""C3-D8C1: source-only safety gates for bounded Android original ldso FEX.

Passing these tests is NOT a physical device/guest execution proof.
"""
from pathlib import Path
import re
import unittest
ROOT=Path(__file__).resolve().parents[1]
C=ROOT/"native-engine/android-host/kernix_g2e_c3d8c1_android_original_ldso_ten_fex_child.cpp"
A=ROOT/"native-engine/android-c3d8c1-original-fex-ldso-ten-probe-app"
J=A/"app/src/main/java/org/kernix/originalfexldso10/MainActivity.java"
W=ROOT/".github/workflows/kernix-g2e-c3d8c1-android-original-ldso-ten-fex-debug-apk.yml"

class TenOriginalX86LdsoAndroidFEXGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cpp=C.read_text()
        cls.java=J.read_text()
        cls.workflow=W.read_text()
        cls.gradle=(A/"app/build.gradle").read_text()

    def test_pinned_original_ten_and_real_source_xmm(self):
        for marker in (
            "std::array<uint8_t,37> kOriginal37",
            "0x66,0x48,0x0f,0x6e,0xc9",
            "0x66,0x48,0x0f,0x6e,0xd0",
            "0x66,0x0f,0x6c,0xca",
            "0x48,0x89,0xe5,0x41",
            "kNextInstructionOffset==36",
            "c8c1::kOriginalSixthEndOffset",
            "std::memcpy(&sixthDisp,kOriginal37.data()+15",
            "cpu.xmm.sse.data[1][0]!=expectedLEAResult",
            "cpu.xmm.sse.data[1][1]!=expectedRAX",
            "cpu.xmm.sse.data[2][0]!=expectedRAX",
            "cpu.xmm.sse.data[2][1]!=0",
            "cpu.gregs[FEXCore::X86State::REG_RBP]!=originalRSP-16",
            "ctx->ExecuteThread(thread);",
            "EnableExitOnHLT",
            "DenyAllGuestSyscalls",
            "OriginalFEXGuardedCallRetStack",
            "OriginalFileBackedBytesRestored",
        ):
            # Two equivalent signatures for calculated tenth offset:
            if marker=="kNextInstructionOffset==36":
                self.assertIn("kOriginalTenthMOVBytes=3",self.cpp)
            else:
                self.assertIn(marker,self.cpp)

    def test_unique_exact_android_device_protocol_matches_child(self):
        success=("KERNIX_C3D8C1_ANDROID_DEVICE_SOURCE_ORIGINAL_LDSO_"
                 "TEN_FEX_INSTRUCTIONS_PASS")
        self.assertIn(success,self.cpp)
        self.assertIn(success,self.java)
        guest_stdout=re.findall(r'std::puts\("([^"]+)"\);',self.cpp)
        self.assertEqual(guest_stdout[0],success)
        expected=re.findall(r'"([A-Z0-9_]+=[01])"',
                            self.java.split("String[] expectedLines={",1)[1]
                                     .split("if(lines.length!=expectedLines.length)",1)[0])
        self.assertEqual(guest_stdout[1:],expected)
        self.assertEqual(guest_stdout[-2:],[
            "COMPLETE_LDSO_DYNAMIC_LINKER_STARTUP=0",
            "WINE_OR_WINDOWS_PE_EXECUTED=0"])

    def test_isolated_signed_debug_app_and_25s_watchdog(self):
        self.assertIn("applicationId 'org.kernix.originalfexldso10'",self.gradle)
        self.assertIn("runner.sha256",self.java)
        self.assertIn("fexcore.sha256",self.java)
        self.assertIn("sha256(core).equals(expectedCore)",self.java)
        self.assertIn("sha256(runner).equals(expected)",self.java)
        self.assertIn("new AlertDialog.Builder",self.java)
        self.assertIn("child.waitFor(25,TimeUnit.SECONDS)",self.java)
        self.assertIn("builder.redirectOutput(trace)",self.java)
        self.assertIn("traceTail(trace)",self.java)
        self.assertIn('new ProcessBuilder(',self.java)
        self.assertIn("ORIGINAL_LDSO_MOV_RBP_RSP_EXECUTED=1",self.cpp)
        self.assertIn("SOURCE_ELEVENTH_PUSH_R15_EXECUTED=0",self.cpp)
        self.assertIn("KERNIX-C3D8C1-Real-FEX-Original-Ldso-Ten-DEBUG.apk",self.workflow)
        self.assertIn("FEX-Emu/FEX.git",self.workflow)
        self.assertIn("app:assembleDebug",self.workflow)
        self.assertNotIn("app:assembleRelease",self.workflow)
        self.assertNotIn("gh release create",self.workflow)
        self.assertNotIn("MAP_FIXED",self.cpp)

    def test_app_private_fixed_source_only(self):
        self.assertIn("--kernix-c3d8c1-source-original-ldso-ten-instructions-v1",self.cpp)
        self.assertIn("--kernix-c3d8c1-source-original-ldso-ten-instructions-v1",self.java)
        self.assertIn("/data/user/0/org.kernix.originalfexldso10/files/",self.cpp)
        self.assertIn("O_DIRECTORY|O_NOFOLLOW",self.cpp)
        self.assertIn("0xf3,0x0f,0x1e,0xfa,0x55",self.cpp)
        self.assertIn("targetByte[c8c1::kNextInstructionOffset]=c8c1::kInjectedHLT",self.cpp)
        self.assertIn("originalGuestStackBytes.data()",self.cpp)
        self.assertIn('c8c1::Stage("FEX_EXECUTETHREAD_RETURNED")',self.cpp)

if __name__=="__main__":
    unittest.main()
