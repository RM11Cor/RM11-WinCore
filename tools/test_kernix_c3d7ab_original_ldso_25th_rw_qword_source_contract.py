# SPDX-License-Identifier: MIT
"""C3-D7AB original source x86 25th RW qword MOV [RIP+disp32],RCX gate.

This is source-only. Linux ARM64 FEX ExecuteThread evidence requires CI PASS.
Do not infer Android, glibc/ldso startup, Wine or games from this contract.
"""
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/"native-engine/android-host/tests/kernix_g2e_c3d7ab_real_original_ldso_25th_rw_qword_mov_rcx_fex_arm64.cpp"
WORKFLOW=ROOT/".github/workflows/kernix-g2e-c3d7ab-original-ldso-25th-rw-qword-mov-rcx-fex-linux-arm64.yml"

class Original25thGuestRWQWordContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code=SOURCE.read_text()
        cls.workflow=WORKFLOW.read_text()

    def test_original_103_bytes_instruction_boundaries(self):
        c=self.code
        self.assertIn("kOriginalTwentyFifthStartOffset==95 && kNextInstructionOffset==102",c)
        self.assertIn("std::array<uint8_t,c7ab::kNextInstructionOffset+1> kOriginal103",c)
        block=c.split("kOriginal103{",1)[1].split("};",1)[0]
        original=bytes(int(s,16) for s in re.findall(r"0x([0-9a-fA-F]{2})",block))
        self.assertEqual(len(original),103)
        self.assertEqual(original[79:85],bytes.fromhex("41 b8 ff ff ff 6f"))
        self.assertEqual(original[85:91],bytes.fromhex("41 b9 29 00 00 70"))
        self.assertEqual(original[91:95],bytes.fromhex("48 c1 e2 20"))
        self.assertEqual(original[95:102],bytes.fromhex("48 89 0d 6a 88 01 00"))
        self.assertEqual(original[102],0x49)
        self.assertIn(
            "targetByte[c7ab::kNextInstructionOffset]=c7ab::kInjectedHLT",c)
        self.assertIn(
            "targetByte[c7ab::kNextInstructionOffset]=kOriginal103[c7ab::kNextInstructionOffset]",c)

    def test_signed_source_riprel_real_eight_byte_write_and_exact_restore(self):
        c=self.code
        for needle in (
            "c7ab::kOriginalTwentyFifthStartOffset+3",
            "originalTarget+c7ab::kNextInstructionOffset+",
            "staged.Module(1)->loadBias+uint64_t{0x38ab0}",
            "guestQWORDAt+sizeof(uint64_t)-1",
            "std::array<uint8_t,8> originalGuestQWORDBytes",
            "0x5a4b45524e495858ULL",
            "std::memcpy(&seededQWORD,guestQWORDBytes,sizeof(seededQWORD))",
            "postGuestQWORD==expectedLEAResult",
            "postGuestQWORD!=guestQWORDSentinel",
            "sourceTwentyFifthMOVRWQWORDProven",
            "std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(guestQWORDAt)),",
            "originalGuestQWORDBytes.data(),originalGuestQWORDBytes.size()",
            "std::memcmp(guestQWORDBytes,originalGuestQWORDBytes.data(),",
            "OriginalFileBackedBytesRestored",
            "kGuestStackBytes==192",
            "DenyAllGuestSyscalls",
            "OriginalFEXGuardedCallRetStack",
            "EnableExitOnHLT",
            "ctx->ExecuteThread(thread)",
        ):
            self.assertIn(needle,c,needle)
        self.assertNotIn("MAP_FIXED",c)

    def test_real_linux_only_ci_requires_strict_pass_marker(self):
        w=self.workflow
        for needle in (
            "runs-on: ubuntu-24.04-arm",
            "kernix_g2e_c3d7ab_real_original_ldso_25th_rw_qword_mov_rcx_fex_arm64.cpp",
            "02e24ca5c01ed0c864466ed573db347336f70170",
            "KERNIX_G2EC3D7AB_SOURCE_PINNED_FEX_TWENTYFIVE_REAL_ORIGINAL_LDSO_RW_QWORD_MOV_RCX_LINUX_ARM64_PASS",
            "original_twenty_fifth_mov_guest_rw_qword_source_rcx_executed=1",
            "original_twenty_fifth_guest_rw_qword_post_equals_rebased_source_rcx=1",
            "original_twenty_fifth_guest_rw_qword_original_eight_bytes_restored=1",
            "original_twenty_sixth_mov_r14_executed=0",
            "original_guest_windows_released=1",
            '"android_device_tested":False',
            '"windows_game_executed":False',
        ):
            self.assertIn(needle,w,needle)

if __name__=="__main__":
    unittest.main()
