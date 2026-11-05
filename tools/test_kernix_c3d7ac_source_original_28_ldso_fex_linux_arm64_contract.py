# SPDX-License-Identifier: MIT
"""C3-D7AC source-only exact-first-28 original x86 ld-linux FEX gate.

Passing this does not prove execution. Only the actual pinned Linux ARM64
FEX ExecuteThread CI run may prove original 26/27/28 guest instructions.
"""
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/"native-engine/android-host/tests/kernix_g2e_c3d7ac_real_original_ldso_28_mov_r14_or_tsc_lea_rdx_fex_arm64.cpp"
WORKFLOW=ROOT/".github/workflows/kernix-g2e-c3d7ac-original-ldso-28-r14-or-rdx-fex-linux-arm64.yml"

class Original28GuestOpcodes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cpp=SOURCE.read_text()
        cls.workflow=WORKFLOW.read_text()

    def test_original_116_source_bytes_and_instruction_own_rips(self):
        c=self.cpp
        self.assertIn("kOriginalTwentyFifthEndOffset==102",c)
        self.assertIn("kOriginalTwentyEighthStartOffset==108",c)
        self.assertIn("kNextInstructionOffset==115",c)
        self.assertIn("std::array<uint8_t,c7ac::kNextInstructionOffset+1> kOriginal116",c)
        block=c.split("kOriginal116{",1)[1].split("};",1)[0]
        by=bytes(int(x,16) for x in re.findall(r"0x([0-9a-fA-F]{2})",block))
        self.assertEqual(len(by),116)
        self.assertEqual(by[95:102],bytes.fromhex("48 89 0d 6a 88 01 00"))
        self.assertEqual(by[102:105],bytes.fromhex("49 89 ce"))
        self.assertEqual(by[105:108],bytes.fromhex("48 09 d0"))
        self.assertEqual(by[108:115],bytes.fromhex("48 8d 15 05 7c 01 00"))
        self.assertEqual(by[115],0x48)
        self.assertIn(
            "targetByte[c7ac::kNextInstructionOffset]=c7ac::kInjectedHLT",c)
        self.assertIn(
            "targetByte[c7ac::kNextInstructionOffset]=kOriginal116[c7ac::kNextInstructionOffset]",c)

    def test_individual_source_relative_rip_ownership(self):
        c=self.cpp
        self.assertIn("c7ac::kOriginalTwentyFifthStartOffset+3",c)
        self.assertIn("originalTarget+c7ac::kOriginalTwentyFifthEndOffset+",c)
        self.assertNotIn(
            "originalTarget+c7ac::kNextInstructionOffset+\n"
            "      static_cast<uint64_t>(static_cast<int64_t>(movRWRel))",c)
        self.assertIn("c7ac::kOriginalTwentyEighthStartOffset+3",c)
        self.assertIn("originalTarget+c7ac::kNextInstructionOffset+",c)
        self.assertIn("staged.Module(1)->loadBias+uint64_t{0x37e58}",c)
        self.assertIn("staged.Module(1)->loadBias+uint64_t{0x38ab0}",c)

    def test_real_guest_register_and_memory_restoration(self):
        c=self.cpp
        for term in (
            "sourceR14==expectedLEAResult",
            "sourceR14!=r14Witness",
            "sourceRDX==expectedRDX",
            "sourceRDX!=rdxWitness",
            "guestTSC!=0",
            "sourceNewGPRProof",
            "postGuestQWORD==expectedLEAResult",
            "sourceTwentyFifthMOVRWQWORDProven",
            "std::array<uint8_t,8> originalGuestQWORDBytes",
            "originalGuestQWORDBytes.data(),originalGuestQWORDBytes.size()",
            "std::memcmp(guestQWORDBytes,originalGuestQWORDBytes.data(),",
            "OriginalFileBackedBytesRestored",
            "kGuestStackBytes==192",
            "DenyAllGuestSyscalls",
            "OriginalFEXGuardedCallRetStack",
            "EnableExitOnHLT",
            "ctx->ExecuteThread(thread)",
            "unmodified_original_twentyeight_instructions_executed=1",
            "original_twenty_ninth_mov_guest_rw_executed=0",
        ):
            self.assertIn(term,c,term)
        self.assertNotIn("MAP_FIXED",c)

    def test_ci_requires_exact_native_output_not_android(self):
        c=self.cpp
        w=self.workflow
        begin=c.index('  std::puts(\n    "KERNIX_G2EC3D7AC_SOURCE_PINNED_FEX_TWENTYEIGHT')
        end=c.index('  return 0;\n}',begin)
        output="".join(re.findall(r'"([^"]+)"',c[begin:end]))
        marker=w.index('          marker=("KERNIX_G2EC3D7AC_SOURCE_PINNED_FEX_TWENTYEIGHT')
        marker_end=w.index('          start="KERNIX_C3D7AC_BEGIN_',marker)
        expected="".join(re.findall(r'"([^"]+)"',w[marker:marker_end]))
        self.assertEqual(output,expected)
        self.assertIn("runs-on: ubuntu-24.04-arm",w)
        self.assertIn("02e24ca5c01ed0c864466ed573db347336f70170",w)
        self.assertIn("KERNIX_C3D7AC_BEGIN_TWENTYEIGHT",w)
        self.assertIn('"android_device_tested":False',w)
        self.assertIn('"windows_game_executed":False',w)
        self.assertNotIn("gh release create",w)

if __name__=="__main__":
    unittest.main()
