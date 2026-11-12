#!/usr/bin/env python3
"""Synthetic x86-64 code-flow adversarial tests. No proprietary game bytes."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from x64_control_flow_gate import inspect_cfg

class ReachableOriginalPeCfgTests(unittest.TestCase):
    def code(self,hex_string):
        return inspect_cfg(bytes.fromhex(hex_string),0x1100)

    def test_basic_arithmetic_genuine_local_ret(self):
        r=self.code("48 89 c8 48 01 d0 c3")
        self.assertEqual(r.reachable_instruction_count,3)
        self.assertEqual(r.return_instructions,1)
        self.assertEqual(r.unreachable_bytes,0)
        self.assertTrue(r.structurally_self_contained_candidate)
        self.assertFalse(r.safe_report()["original_carx_gameplay_method_identity_proven"])

    def test_conditional_both_successors_reachable(self):
        # test rcx,rcx; je return; mov rax,rdx; ret.
        r=self.code("48 85 c9 74 03 48 89 d0 c3")
        self.assertEqual(r.return_instructions,1)
        self.assertEqual(r.local_branches,1)
        self.assertEqual(r.unreachable_bytes,0)
        self.assertTrue(r.structurally_self_contained_candidate)
        self.assertGreaterEqual(r.basic_block_count,3)

    def test_external_direct_call_must_remain_blocking(self):
        r=self.code("e8 10 00 00 00 c3")
        self.assertEqual(r.external_direct_calls,1)
        self.assertEqual(r.return_instructions,1)
        self.assertFalse(r.structurally_self_contained_candidate)
        self.assertFalse(r.no_unresolved_control_flow)

    def test_external_direct_jump_not_return(self):
        r=self.code("e9 20 00 00 00")
        self.assertEqual(r.external_branches,1)
        self.assertEqual(r.return_instructions,0)
        self.assertFalse(r.no_unresolved_control_flow)

    def test_indirect_call_cannot_be_inferred(self):
        r=self.code("ff d0 c3") # call rax; ret
        self.assertEqual(r.indirect_calls,1)
        self.assertFalse(r.structurally_self_contained_candidate)

    def test_indirect_jump_must_not_fallthrough(self):
        r=self.code("ff e0 c3") # jmp rax; ret (ret is unreachable)
        self.assertEqual(r.indirect_branches,1)
        self.assertEqual(r.return_instructions,0)
        self.assertGreater(r.unreachable_bytes,0)

    def test_rip_relative_original_pe_global_not_auto_resolved(self):
        r=self.code("48 8b 05 10 00 00 00 c3")
        self.assertEqual(r.rip_relative_memory_instructions,1)
        self.assertEqual(r.rip_target_outside_sample,1)
        self.assertFalse(r.structurally_self_contained_candidate)

    def test_rip_relative_inside_source_still_needs_data_lifetime(self):
        r=self.code("48 8d 05 01 00 00 00 c3 11 22")
        self.assertEqual(r.rip_relative_memory_instructions,1)
        self.assertEqual(r.rip_target_outside_sample,0)
        self.assertGreater(r.unreachable_bytes,0)
        self.assertFalse(r.structurally_self_contained_candidate)

    def test_unreachable_int3_padding_not_falsely_executed(self):
        r=self.code("c3 cc cc cc")
        self.assertEqual(r.trap_instructions,0)
        self.assertEqual(r.return_instructions,1)
        self.assertEqual(r.unreachable_bytes,3)
        self.assertFalse(r.structurally_self_contained_candidate)

    def test_reachable_trap_blocks_callable_claim(self):
        r=self.code("0f 0b c3") # ud2; ret unreachable
        self.assertEqual(r.trap_instructions,1)
        self.assertEqual(r.return_instructions,0)
        self.assertFalse(r.no_unresolved_control_flow)

    def test_overlapping_target_into_middle_of_instruction_refused(self):
        r=self.code("74 01 48 89 c8 c3")
        self.assertGreater(r.overlapping_decode_attempts,0)
        self.assertFalse(r.no_unresolved_control_flow)

    def test_fallthrough_beyond_available_code_not_ret(self):
        r=self.code("90 90")
        self.assertEqual(r.unexpected_fallthrough_exits,1)
        self.assertFalse(r.no_unresolved_control_flow)

    def test_unsupported_short_loop_not_fabricated_conditional(self):
        r=self.code("e2 fe c3")
        self.assertEqual(r.indirect_branches,1)
        self.assertFalse(r.structurally_self_contained_candidate)

    def test_direct_local_call_and_ret_within_sample(self):
        # call sub; ret; mov rax,rcx; ret
        r=self.code("e8 01 00 00 00 c3 48 89 c8 c3")
        self.assertEqual(r.local_direct_calls,1)
        self.assertEqual(r.return_instructions,2)
        self.assertEqual(r.unreachable_bytes,0)
        self.assertTrue(r.structurally_self_contained_candidate)

    def test_infinite_local_loop_does_not_count_complete_method(self):
        r=self.code("eb fe")
        self.assertEqual(r.local_branches,1)
        self.assertEqual(r.return_instructions,0)
        self.assertFalse(r.structurally_self_contained_candidate)

    def test_bad_decode_byte_does_not_count_as_executable(self):
        r=self.code("0f")
        self.assertEqual(r.decode_failures,1)
        self.assertFalse(r.no_unresolved_control_flow)

    def test_original_source_epilogue_without_prologue_rejected(self):
        # A source region which only restores a predecessor's Win64
        # stack frame cannot be an independent callable function.
        r=self.code("48 83 c4 30 5b c3") # add rsp,48;pop rbx;ret
        self.assertTrue(r.unmatched_epilogue_stack_restore)
        self.assertFalse(r.structurally_self_contained_candidate)
        self.assertEqual(r.return_instructions,1)

    def test_prologue_balanced_stack_is_not_false_epilogue(self):
        r=self.code("53 48 83 ec 30 48 83 c4 30 5b c3")
        self.assertFalse(r.unmatched_epilogue_stack_restore)
        self.assertTrue(r.structurally_self_contained_candidate)

    def test_epilogue_restoring_saved_register_without_local_prologue(self):
        r=self.code("48 8b 5c 24 50 48 83 c4 40 5f c3")
        self.assertTrue(r.unmatched_epilogue_stack_restore)
        self.assertFalse(r.structurally_self_contained_candidate)

    def test_reject_zero_size(self):
        with self.assertRaises(ValueError):
            inspect_cfg(b"")

    def test_reject_source_size_over_budget(self):
        with self.assertRaises(ValueError):
            inspect_cfg(b"\x90"*65537)

    def test_reject_unmapped_rva(self):
        with self.assertRaises(ValueError):
            inspect_cfg(b"\xc3",0x200)

    def test_reject_32bit_rva_overflow(self):
        with self.assertRaises(ValueError):
            inspect_cfg(b"\xc3",0x100000000)

    def test_report_never_emits_machine_code_or_disassembly(self):
        r=self.code("48 89 c8 48 01 d0 c3")
        txt=str(r.safe_report())
        self.assertNotIn("48 89 c8",txt)
        self.assertNotIn("mov rax",txt)
        self.assertFalse(r.safe_report()["android_arm64_execution_proven"])

if __name__=="__main__":
    unittest.main(verbosity=2)
