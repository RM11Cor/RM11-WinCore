# SPDX-License-Identifier: MIT
"""C3-D8C5 Android first 25 authentic original x86 ldso guest op source gate.

Static checks and an APK build are NOT physical Android guest execution.
"""
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]
CHILD=ROOT/"native-engine/android-host/kernix_g2e_c3d8c5_android_original_ldso_twentyfive_fex_child.cpp"
APP=ROOT/"native-engine/android-c3d8c5-original-fex-ldso-25-probe-app"
JAVA=APP/"app/src/main/java/org/kernix/originalfexldso25/MainActivity.java"
WORKFLOW=ROOT/".github/workflows/kernix-g2e-c3d8c5-android-original-ldso-25-fex-debug-apk.yml"

class Original25thFEXAndroidContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cpp=CHILD.read_text()
        cls.java=JAVA.read_text()
        cls.workflow=WORKFLOW.read_text()
        cls.manifest=(APP/"app/src/main/AndroidManifest.xml").read_text()
        cls.gradle=(APP/"app/build.gradle").read_text()

    def test_original_source_and_bounded_25th_qword_mov(self):
        c=self.cpp
        self.assertIn("kOriginalTwentyFifthStartOffset==95 && kNextInstructionOffset==102",c)
        self.assertIn("std::array<uint8_t,c8c5::kNextInstructionOffset+1> kOriginal103",c)
        block=c.split("kOriginal103{",1)[1].split("};",1)[0]
        raw=bytes(int(x,16) for x in re.findall(r"0x([0-9a-fA-F]{2})",block))
        self.assertEqual(len(raw),103)
        self.assertEqual(raw[95:102],bytes.fromhex("48 89 0d 6a 88 01 00"))
        self.assertEqual(raw[102],0x49)
        self.assertIn("targetByte[c8c5::kNextInstructionOffset]=c8c5::kInjectedHLT",c)
        self.assertIn("targetByte[c8c5::kNextInstructionOffset]=kOriginal103[c8c5::kNextInstructionOffset]",c)

    def test_true_original_guest_8_byte_rw_write_and_restore(self):
        for requirement in (
            "c8c5::kOriginalTwentyFifthStartOffset+3",
            "originalTarget+c8c5::kNextInstructionOffset+",
            "staged.Module(1)->loadBias+uint64_t{0x38ab0}",
            "std::array<uint8_t,8> originalGuestQWORDBytes",
            "guestQWORDSentinel=0x5a4b45524e495858ULL",
            "postGuestQWORD==expectedLEAResult",
            "postGuestQWORD!=guestQWORDSentinel",
            "sourceTwentyFifthMOVRWQWORDProven",
            "std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(guestQWORDAt)),",
            "originalGuestQWORDBytes.data(),originalGuestQWORDBytes.size()",
            "std::memcmp(guestQWORDBytes,originalGuestQWORDBytes.data()",
            "OriginalFileBackedBytesRestored",
            "kGuestStackBytes==192",
            "DenyAllGuestSyscalls",
            "OriginalFEXGuardedCallRetStack",
            "EnableExitOnHLT",
            "ctx->ExecuteThread(thread)",
        ):
            self.assertIn(requirement,self.cpp,requirement)
        self.assertNotIn("MAP_FIXED",self.cpp)
        self.assertNotIn("#define main",self.cpp)

    def test_strict_java_native_device_protocol(self):
        marker="KERNIX_C3D8C5_ANDROID_DEVICE_SOURCE_ORIGINAL_LDSO_25_FEX_INSTRUCTIONS_PASS"
        out=re.findall(r'std::puts\("([^"]+)"\);',self.cpp)
        self.assertEqual(out[0],marker)
        self.assertIn(marker,self.java)
        java_lines=self.java.split("String[] expectedLines={",1)[1].split(
            "if(lines.length!=expectedLines.length)",1)[0]
        expected=re.findall(r'"([A-Z0-9_]+=[01])"',java_lines)
        self.assertEqual(out[1:],expected)
        self.assertIn("ORIGINAL_GUEST_RW_QWORD_EIGHT_ORIGINAL_BYTES_RESTORED=1",expected)
        self.assertIn("SOURCE_TWENTYSIXTH_MOV_R14_EXECUTED=0",expected)
        self.assertIn("COMPLETE_LDSO_DYNAMIC_LINKER_STARTUP=0",expected)
        self.assertIn("WINE_OR_WINDOWS_PE_EXECUTED=0",expected)

    def test_isolated_android_build_source_and_binary_integrity(self):
        self.assertIn("applicationId 'org.kernix.originalfexldso25'",self.gradle)
        self.assertIn("System.getenv(",self.gradle)
        self.assertIn("<intent-filter>",self.manifest)
        self.assertIn("android.intent.action.MAIN",self.manifest)
        self.assertIn("android.intent.category.LAUNCHER",self.manifest)
        for needle in (
            "sha256(runner).equals(expected)",
            "sha256(core).equals(expectedCore)",
            "new AlertDialog.Builder",
            "child.waitFor(25,TimeUnit.SECONDS)",
            "builder.redirectOutput(trace)",
            "traceTail(trace)",
        ):
            self.assertIn(needle,self.java)
        self.assertIn("--kernix-c3d8c5-source-original-ldso-25-instructions-v1",self.cpp)
        self.assertIn("--kernix-c3d8c5-source-original-ldso-25-instructions-v1",self.java)
        self.assertIn("/data/user/0/org.kernix.originalfexldso25/files/",self.cpp)
        self.assertIn("O_DIRECTORY|O_NOFOLLOW",self.cpp)
        self.assertIn("FEX-Emu/FEX.git",self.workflow)
        self.assertIn("app:assembleDebug",self.workflow)
        self.assertIn("libFEXCore.so",self.workflow)
        self.assertNotIn("app:assembleRelease",self.workflow)
        self.assertNotIn("gh release create",self.workflow)

if __name__=="__main__":
    unittest.main()
