# SPDX-License-Identifier: MIT
"""C3-D8C6 source-authentic first 28 Linux x86-64 ldso FEX Android gate.

Static source contract and a compiled APK alone are not proof of running
28 original guest instructions on a user's phone.
"""
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]
CHILD=ROOT/"native-engine/android-host/kernix_g2e_c3d8c6_android_original_ldso_twentyeight_fex_child.cpp"
APP=ROOT/"native-engine/android-c3d8c6-original-fex-ldso-28-probe-app"
JAVA=APP/"app/src/main/java/org/kernix/originalfexldso28/MainActivity.java"
WORKFLOW=ROOT/".github/workflows/kernix-g2e-c3d8c6-android-original-ldso-28-fex-debug-apk.yml"

class Original28AndroidFEXGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cpp=CHILD.read_text()
        cls.java=JAVA.read_text()
        cls.gradle=(APP/"app/build.gradle").read_text()
        cls.manifest=(APP/"app/src/main/AndroidManifest.xml").read_text()
        cls.workflow=WORKFLOW.read_text()

    def test_source_whitelist_and_bounded_29th_original_rw_store(self):
        c=self.cpp
        self.assertIn("kOriginalTwentyFifthEndOffset==102",c)
        self.assertIn("kOriginalTwentyEighthStartOffset==108",c)
        self.assertIn("kNextInstructionOffset==115",c)
        self.assertIn("std::array<uint8_t,c8c6::kNextInstructionOffset+1> kOriginal116",c)
        block=c.split("kOriginal116{",1)[1].split("};",1)[0]
        raw=bytes(int(t,16) for t in re.findall(r"0x([0-9a-fA-F]{2})",block))
        self.assertEqual(len(raw),116)
        self.assertEqual(raw[95:102],bytes.fromhex("48 89 0d 6a 88 01 00"))
        self.assertEqual(raw[102:105],bytes.fromhex("49 89 ce"))
        self.assertEqual(raw[105:108],bytes.fromhex("48 09 d0"))
        self.assertEqual(raw[108:115],bytes.fromhex("48 8d 15 05 7c 01 00"))
        self.assertEqual(raw[115],0x48)
        self.assertIn("targetByte[c8c6::kNextInstructionOffset]=c8c6::kInjectedHLT",c)
        self.assertIn("targetByte[c8c6::kNextInstructionOffset]=kOriginal116[c8c6::kNextInstructionOffset]",c)

    def test_instruction_specific_rips_and_genuine_gpr_plus_rw_proof(self):
        c=self.cpp
        for symbol in (
            "c8c6::kOriginalTwentyFifthStartOffset+3",
            "originalTarget+c8c6::kOriginalTwentyFifthEndOffset+",
            "c8c6::kOriginalTwentyEighthStartOffset+3",
            "originalTarget+c8c6::kNextInstructionOffset+",
            "staged.Module(1)->loadBias+uint64_t{0x38ab0}",
            "staged.Module(1)->loadBias+uint64_t{0x37e58}",
            "sourceR14==expectedLEAResult",
            "sourceR14!=r14Witness",
            "sourceRDX==expectedRDX",
            "sourceRDX!=rdxWitness",
            "guestTSC!=0",
            "sourceNewGPRProof",
            "sourceTwentyFifthMOVRWQWORDProven",
            "postGuestQWORD==expectedLEAResult",
            "std::array<uint8_t,8> originalGuestQWORDBytes",
            "originalGuestQWORDBytes.data(),originalGuestQWORDBytes.size()",
            "OriginalFileBackedBytesRestored",
            "kGuestStackBytes==192",
            "DenyAllGuestSyscalls",
            "OriginalFEXGuardedCallRetStack",
            "EnableExitOnHLT",
            "ctx->ExecuteThread(thread)",
        ):
            self.assertIn(symbol,c,symbol)
        self.assertNotIn("MAP_FIXED",c)
        self.assertNotIn("#define main",c)
        self.assertNotIn("FEX_LINUX_ARM64_CI",c)

    def test_exact_java_native_success_contract(self):
        marker="KERNIX_C3D8C6_ANDROID_DEVICE_SOURCE_ORIGINAL_LDSO_28_FEX_INSTRUCTIONS_PASS"
        out=re.findall(r'std::puts\("([^"]+)"\);',self.cpp)
        self.assertTrue(out)
        self.assertEqual(out[0],marker)
        self.assertIn(marker,self.java)
        java_block=self.java.split("String[] expectedLines={",1)[1].split(
            "if(lines.length!=expectedLines.length)",1)[0]
        values=re.findall(r'"([A-Z0-9_]+=[01])"',java_block)
        self.assertEqual(out[1:],values)
        self.assertIn("SOURCE_TWENTYNINTH_MOV_GUEST_RW_EXECUTED=0",values)
        self.assertIn("ORIGINAL_GUEST_RW_QWORD_EIGHT_BYTES_RESTORED=1",values)
        self.assertIn("GUEST_LINUX_SYSCALLS_FORWARDED=0",values)
        self.assertIn("COMPLETE_LDSO_DYNAMIC_LINKER_STARTUP=0",values)
        self.assertIn("WINE_OR_WINDOWS_PE_EXECUTED=0",values)

    def test_app_private_optin_watchdog_original_binary_sha(self):
        self.assertIn("applicationId 'org.kernix.originalfexldso28'",self.gradle)
        self.assertIn("versionName '0.1-c3d8c6-original-fex-ldso-28'",self.gradle)
        self.assertIn("System.getenv(",self.gradle)
        self.assertIn("<intent-filter>",self.manifest)
        self.assertIn("android.intent.action.MAIN",self.manifest)
        self.assertIn("android.intent.category.LAUNCHER",self.manifest)
        for term in (
            "sha256(runner).equals(expected)",
            "sha256(core).equals(expectedCore)",
            "new AlertDialog.Builder",
            "child.waitFor(25,TimeUnit.SECONDS)",
            "builder.redirectOutput(trace)",
            "traceTail(trace)",
        ):
            self.assertIn(term,self.java)
        self.assertIn("--kernix-c3d8c6-source-original-ldso-28-instructions-v1",self.java)
        self.assertIn("--kernix-c3d8c6-source-original-ldso-28-instructions-v1",self.cpp)
        self.assertIn("/data/user/0/org.kernix.originalfexldso28/files/",self.cpp)
        self.assertIn("O_DIRECTORY|O_NOFOLLOW",self.cpp)
        self.assertIn("FEX-Emu/FEX.git",self.workflow)
        self.assertIn("app:assembleDebug",self.workflow)
        self.assertIn("libFEXCore.so",self.workflow)
        self.assertNotIn("app:assembleRelease",self.workflow)
        self.assertNotIn("gh release create",self.workflow)

if __name__=="__main__":
    unittest.main()
