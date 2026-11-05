# SPDX-License-Identifier: MIT
"""C3-D8C4 source-contract gate for first 24 original ld-linux x86 instructions.

A green static contract or CI APK build does not prove execution on a phone.
"""
from pathlib import Path
import re
import unittest

REPO=Path(__file__).resolve().parents[1]
CHILD=REPO/"native-engine/android-host/kernix_g2e_c3d8c4_android_original_ldso_twentyfour_fex_child.cpp"
APP=REPO/"native-engine/android-c3d8c4-original-fex-ldso-24-probe-app"
JAVA=APP/"app/src/main/java/org/kernix/originalfexldso24/MainActivity.java"
WORKFLOW=REPO/".github/workflows/kernix-g2e-c3d8c4-android-original-ldso-24-fex-debug-apk.yml"


class Original24AndroidFEXGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cpp=CHILD.read_text()
        cls.java=JAVA.read_text()
        cls.gradle=(APP/"app/build.gradle").read_text()
        cls.manifest=(APP/"app/src/main/AndroidManifest.xml").read_text()
        cls.workflow=WORKFLOW.read_text()

    def test_original_source_bytes_24th_and_25th_boundary(self):
        self.assertIn("kNextInstructionOffset==95",self.cpp)
        self.assertIn(
            "std::array<uint8_t,c8c4::kNextInstructionOffset+1> kOriginal96",
            self.cpp)
        block=self.cpp.split("kOriginal96{",1)[1].split("};",1)[0]
        raw=bytes(int(x,16) for x in re.findall(r"0x([0-9a-fA-F]{2})",block))
        self.assertEqual(len(raw),96)
        self.assertEqual(raw[79:85],bytes.fromhex("41 b8 ff ff ff 6f"))
        self.assertEqual(raw[85:91],bytes.fromhex("41 b9 29 00 00 70"))
        self.assertEqual(raw[91:95],bytes.fromhex("48 c1 e2 20"))
        self.assertEqual(raw[95],0x48)
        self.assertIn("targetByte[c8c4::kNextInstructionOffset]=c8c4::kInjectedHLT",self.cpp)
        self.assertIn("targetByte[c8c4::kNextInstructionOffset]=kOriginal96[c8c4::kNextInstructionOffset]",self.cpp)

    def test_real_guest_registers_and_source_relative_lea_rsi(self):
        for symbol in (
            "const uint64_t expectedRSI=originalTarget+c8c4::kOriginalTwentyFirstStartOffset+",
            "c8c4::kOriginalTwentyFirstLEABytes+",
            "cpu.gregs[FEXCore::X86State::REG_R8]==0x6fffffffULL",
            "cpu.gregs[FEXCore::X86State::REG_R9]==0x70000029ULL",
            "cpu.gregs[FEXCore::X86State::REG_R8]!=0x6fffffffULL",
            "cpu.gregs[FEXCore::X86State::REG_R9]!=0x70000029ULL",
            "const uint64_t shiftedTscEDX=",
            "shiftedTscEDX & uint64_t{UINT32_MAX}",
            "guestTSC!=0",
            "originalRWDataUpdatedCorrectly",
            "*guestANDByte=originalGuestANDByte",
            "kGuestStackBytes==192",
            "OriginalFileBackedBytesRestored",
            "ctx->ExecuteThread(thread)",
            "DenyAllGuestSyscalls",
            "OriginalFEXGuardedCallRetStack",
            "EnableExitOnHLT",
        ):
            self.assertIn(symbol,self.cpp,symbol)
        self.assertNotIn(
            "const uint64_t expectedRSI=originalTarget+c8c4::kNextInstructionOffset+",
            self.cpp)
        self.assertNotIn("MAP_FIXED",self.cpp)

    def test_phone_success_requires_exact_child_stdout(self):
        marker="KERNIX_C3D8C4_ANDROID_DEVICE_SOURCE_ORIGINAL_LDSO_24_FEX_INSTRUCTIONS_PASS"
        self.assertIn(marker,self.cpp)
        self.assertIn(marker,self.java)
        outputs=re.findall(r'std::puts\("([^"]+)"\);',self.cpp)
        self.assertEqual(outputs[0],marker)
        java_lines=self.java.split("String[] expectedLines={",1)[1].split(
            "if(lines.length!=expectedLines.length)",1)[0]
        expected=re.findall(r'"([A-Z0-9_]+=[01])"',java_lines)
        self.assertEqual(outputs[1:],expected)
        self.assertIn("SOURCE_TWENTY_FIFTH_MOV_GUEST_RW_EXECUTED=0",expected)
        self.assertIn("GUEST_LINUX_SYSCALLS_FORWARDED=0",expected)
        self.assertIn("COMPLETE_LDSO_DYNAMIC_LINKER_STARTUP=0",expected)
        self.assertIn("WINE_OR_WINDOWS_PE_EXECUTED=0",expected)

    def test_app_isolated_debug_signed_and_bounded(self):
        self.assertIn("applicationId 'org.kernix.originalfexldso24'",self.gradle)
        self.assertIn("System.getenv(",self.gradle)
        self.assertIn("<intent-filter>",self.manifest)
        self.assertIn("android.intent.action.MAIN",self.manifest)
        self.assertIn("android.intent.category.LAUNCHER",self.manifest)
        for symbol in (
            "runner.sha256", "fexcore.sha256",
            "sha256(runner).equals(expected)",
            "sha256(core).equals(expectedCore)",
            "new AlertDialog.Builder",
            "child.waitFor(25,TimeUnit.SECONDS)",
            "builder.redirectOutput(trace)",
            "traceTail(trace)",
        ):
            self.assertIn(symbol,self.java)
        self.assertIn("--kernix-c3d8c4-source-original-ldso-24-instructions-v1",self.java)
        self.assertIn("--kernix-c3d8c4-source-original-ldso-24-instructions-v1",self.cpp)
        self.assertIn("/data/user/0/org.kernix.originalfexldso24/files/",self.cpp)
        self.assertIn("O_DIRECTORY|O_NOFOLLOW",self.cpp)
        self.assertIn("FEX-Emu/FEX.git",self.workflow)
        self.assertIn("app:assembleDebug",self.workflow)
        self.assertIn("libFEXCore.so",self.workflow)
        self.assertNotIn("app:assembleRelease",self.workflow)
        self.assertNotIn("gh release create",self.workflow)

if __name__=="__main__":
    unittest.main()
