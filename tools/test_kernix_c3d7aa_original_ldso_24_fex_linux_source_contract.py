# SPDX-License-Identifier: MIT
"""C3-D7AA source-only Linux ARM64 FEX guest 24-opcode release gate.

Success here is a source invariant; NOT proof that native FEX guest ran.
Only the Linux ARM64 FEX workflow may establish 24-instruction execution.
"""
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/"native-engine/android-host/tests/kernix_g2e_c3d7aa_real_original_ldso_24_instructions_mov_r8_r9_shl_rdx_fex_arm64.cpp"
WORKFLOW=ROOT/".github/workflows/kernix-g2e-c3d7aa-original-ldso-mov-r8-r9-shl-rdx-fex-linux-arm64.yml"

class Original24OpcodeGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code=SOURCE.read_text(encoding="utf-8")
        cls.workflow=WORKFLOW.read_text(encoding="utf-8")

    def test_exact_96_original_ldso_opcodes_and_fifth_boundary(self):
        self.assertIn("kNextInstructionOffset==95",self.code)
        self.assertIn("std::array<uint8_t,c7aa::kNextInstructionOffset+1> kOriginal96",self.code)
        block=self.code.split("kOriginal96{",1)[1].split("};",1)[0]
        raw=bytes(int(x,16) for x in re.findall(r"0x([0-9a-fA-F]{2})",block))
        self.assertEqual(len(raw),96)
        self.assertEqual(raw[79:85],bytes.fromhex("41 b8 ff ff ff 6f"))
        self.assertEqual(raw[85:91],bytes.fromhex("41 b9 29 00 00 70"))
        self.assertEqual(raw[91:95],bytes.fromhex("48 c1 e2 20"))
        self.assertEqual(raw[95],0x48)
        self.assertIn("targetByte[c7aa::kNextInstructionOffset]=c7aa::kInjectedHLT",self.code)
        self.assertIn("targetByte[c7aa::kNextInstructionOffset]=kOriginal96[c7aa::kNextInstructionOffset]",self.code)

    def test_guest_register_evidence_and_cleanup(self):
        for s in (
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
            "original_twenty_fifth_mov_guest_rw_executed=0",
            "all_three_original_file_backed_ptload_bytes_restored=1",
        ):
            self.assertIn(s,self.code,s)
        self.assertNotIn("MAP_FIXED",self.code)

    def test_linux_arm64_ci_gates_real_execution_not_android(self):
        for s in (
            "runs-on: ubuntu-24.04-arm",
            "original-ldso-24_instructions_mov_r8_r9_shl_rdx_fex_arm64.cpp",
            "02e24ca5c01ed0c864466ed573db347336f70170",
            "ld-linux-x86-64.so.2",
            "KERNIX_G2EC3D7AA_SOURCE_PINNED_FEX_TWENTYFOUR_REAL_ORIGINAL_LDSO_R8_R9_SHL_RDX_LINUX_ARM64_PASS",
            "KERNIX_C3D7AA_BEGIN_TWENTYFOUR_REAL_ORIGINAL_LDSO",
            "original_twenty_second_mov_r8d_source_immediate_executed=1",
            "original_twenty_third_mov_r9d_source_immediate_executed=1",
            "original_twenty_fourth_shl_rdx_32_from_rdtsc_executed=1",
            "original_twenty_fifth_mov_guest_rw_executed=0",
            '"android_device_tested":False',
            '"windows_game_executed":False',
        ):
            self.assertIn(s,self.workflow,s)

if __name__=="__main__":
    unittest.main()
