#!/usr/bin/env python3
"""Self-contained synthetic Win64 AOT parent/child reachability tests.

Actual game snippets are never committed; these tests prove only structural
segment-aware control flow and deliberately reject false complete methods.
"""
from __future__ import annotations
import sys
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from x64_multisegment_cfg import inspect_multisegment_cfg

class OriginalSourceParentChildCfgTests(unittest.TestCase):
    def test_parent_direct_jump_to_child_mapped(self):
        # parent 0x1200: jmp 0x1100; child: mov rax,rcx;ret
        parent=bytes.fromhex("e9 fb fe ff ff")
        child=bytes.fromhex("48 89 c8 c3")
        r=inspect_multisegment_cfg({0x1200:parent,0x1100:child},[0x1200])
        self.assertEqual(r.cross_segment_direct_branch_edges,1)
        self.assertEqual(r.unmapped_direct_branch_edges,0)
        self.assertEqual(r.reachable_ret_instructions,1)
        self.assertEqual(r.unreachable_original_code_bytes,0)
        self.assertFalse(r.safe_report()["actual_original_carx_code_executed"])

    def test_parent_local_call_into_child_then_return(self):
        # parent 0x1200: call 0x1100; ret; child: mov rax,rcx;ret
        parent=bytes.fromhex("e8 fb fe ff ff c3")
        child=bytes.fromhex("48 89 c8 c3")
        r=inspect_multisegment_cfg({0x1100:child,0x1200:parent},[0x1200])
        self.assertEqual(r.cross_segment_direct_call_edges,1)
        self.assertEqual(r.reachable_ret_instructions,2)
        self.assertEqual(r.unmapped_direct_call_edges,0)

    def test_external_call_outside_all_original_ranges_is_unresolved(self):
        r=inspect_multisegment_cfg(
            {0x1200:bytes.fromhex("e8 10 00 00 00 c3"),
             0x1100:bytes.fromhex("c3")},[0x1200])
        self.assertEqual(r.unmapped_direct_call_edges,1)
        self.assertEqual(r.reachable_ret_instructions,1)
        self.assertGreater(r.unreachable_original_code_bytes,0)

    def test_parent_metadata_is_not_imaginary_control_flow(self):
        # No actual x86 branch reaches the supposed child source range.
        r=inspect_multisegment_cfg(
            {0x1100:bytes.fromhex("c3"),0x1200:bytes.fromhex("c3")},
            [0x1200])
        self.assertEqual(r.cross_segment_direct_call_edges,0)
        self.assertEqual(r.cross_segment_direct_branch_edges,0)
        self.assertEqual(r.unreachable_original_code_bytes,1)
        self.assertTrue(r.source_region_entry_points_not_a_verified_method)

    def test_both_seeds_are_separate_experimental_entries(self):
        r=inspect_multisegment_cfg(
            {0x1100:bytes.fromhex("c3"),0x1200:bytes.fromhex("c3")},
            [0x1200,0x1100])
        self.assertEqual(r.reachable_ret_instructions,2)
        self.assertEqual(r.unreachable_original_code_bytes,0)
        self.assertEqual(r.cross_segment_direct_branch_edges,0)

    def test_rip_relative_original_data_outside_all_segments_is_unresolved(self):
        r=inspect_multisegment_cfg(
            {0x1200:bytes.fromhex("48 8b 05 10 00 00 00 c3")},
            [0x1200])
        self.assertEqual(r.rip_relative_original_data_dependencies,1)
        self.assertEqual(r.unmapped_rip_relative_targets,1)

    def test_indirect_original_unity_call_unresolved(self):
        r=inspect_multisegment_cfg(
            {0x1200:bytes.fromhex("ff d0 c3")},[0x1200])
        self.assertEqual(r.indirect_call_edges,1)
        self.assertEqual(r.reachable_ret_instructions,1)

    def test_jump_to_middle_of_instruction_in_other_region_rejected(self):
        # parent jmp child+1, child starts a 3-byte mov rax,rcx
        parent=bytes.fromhex("e9 fc fe ff ff")
        child=bytes.fromhex("48 89 c8 c3")
        r=inspect_multisegment_cfg(
            {0x1200:parent,0x1100:child},[0x1100,0x1200])
        self.assertEqual(r.cross_segment_direct_branch_edges,1)
        self.assertGreater(r.instruction_overlap_conflicts,0)

    def test_unmapped_fallthrough_after_last_source_byte(self):
        r=inspect_multisegment_cfg(
            {0x1200:bytes.fromhex("90")},[0x1200])
        self.assertEqual(r.unmapped_fallthrough_edges,1)
        self.assertEqual(r.reachable_ret_instructions,0)

    def test_truncated_original_opcode_detected(self):
        r=inspect_multisegment_cfg(
            {0x1200:bytes.fromhex("0f")},[0x1200])
        self.assertEqual(r.truncated_x86_decode,1)

    def test_original_pe_range_overlap_rejected(self):
        with self.assertRaises(ValueError):
            inspect_multisegment_cfg(
                {0x1100:bytes.fromhex("90 90"),0x1101:bytes.fromhex("c3")},
                [0x1100])

    def test_missing_parent_code_entry_rejected(self):
        with self.assertRaises(ValueError):
            inspect_multisegment_cfg({0x1100:bytes.fromhex("c3")},[0x1200])

    def test_reject_empty_source(self):
        with self.assertRaises(ValueError):
            inspect_multisegment_cfg({},[0x1200])

    def test_reject_empty_rva_entry_list(self):
        with self.assertRaises(ValueError):
            inspect_multisegment_cfg({0x1200:bytes.fromhex("c3")},[])

    def test_reject_original_parent_fragment_over_4096(self):
        with self.assertRaises(ValueError):
            inspect_multisegment_cfg({0x1200:b"\x90"*4097},[0x1200])

    def test_reject_more_than_8_verified_fragments(self):
        with self.assertRaises(ValueError):
            inspect_multisegment_cfg(
                {0x1000+i*16:b"\xc3" for i in range(9)},[0x1000])

    def test_safe_report_contains_no_proprietary_bytes_or_method_claims(self):
        r=inspect_multisegment_cfg({0x1200:bytes.fromhex("48 89 c8 c3")},[0x1200])
        rep=r.safe_report()
        self.assertFalse(rep["proprietary_machine_code_emitted"])
        self.assertFalse(rep["actual_android_arm64_gamecode_executed"])
        self.assertNotIn("48 89 c8",str(rep))
        self.assertTrue(rep["unwind_chain_is_not_proof_of_control_flow_connection"])

if __name__=="__main__":
    unittest.main(verbosity=2)
