#!/usr/bin/env python3
"""No original game bytes. Verify that merged xdata + CFG rejects false G0 wins."""
from __future__ import annotations
import struct
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from win64_unwind_boundary import decode_unwind_info
from x64_control_flow_gate import inspect_cfg
from win64_callable_source_gate import evaluate_win64_source_function

BASE=0x1100
def source(hexbytes:str="48 89 c8 48 01 d0 c3",
           unwind:bytes=b"\x01\x00\x00\x00",
           status:str="COMPLETE_UNWIND_CHAIN_READ"):
    code=bytes.fromhex(hexbytes)
    cfg=inspect_cfg(code,BASE)
    return evaluate_win64_source_function(
        BASE,len(code),cfg,[decode_unwind_info(unwind)],status)

class Win64XdataPlusCfgAdmissionTests(unittest.TestCase):
    def test_local_code_and_valid_unwind_is_candidate_not_game_proof(self):
        r=source()
        self.assertEqual(r.status,
            "STRUCTURALLY_LOCAL_CANDIDATE_NEEDS_REFERENCE_EXECUTION")
        self.assertFalse(r.confirmed_original_il2cpp_method)
        self.assertFalse(r.confirmed_reference_behavior)
        self.assertFalse(r.confirmed_android_arm64_game_execution)
        self.assertEqual(r.blockers,())

    def test_parent_chained_code_requires_parent_body(self):
        unwind=b"\x21\x00\x00\x00"+struct.pack("<III",0x1200,0x1250,0x2200)
        r=source(unwind=unwind,status="CHAIN_DEPTH_LIMIT_REACHED")
        self.assertIn("chained_parent_source_function_body_not_exported",r.blockers)
        self.assertTrue(r.contains_chained_parent)
        self.assertFalse(r.confirmed_original_il2cpp_method)

    def test_real_complete_chain_still_requires_parent(self):
        chained=decode_unwind_info(
            b"\x21\x00\x00\x00"+struct.pack("<III",0x1200,0x1250,0x2200))
        parent=decode_unwind_info(b"\x01\x00\x00\x00")
        code=bytes.fromhex("48 89 c8 c3")
        r=evaluate_win64_source_function(
            BASE,len(code),inspect_cfg(code,BASE),[chained,parent],
            "COMPLETE_UNWIND_CHAIN_READ")
        self.assertEqual(r.unwind_record_count,2)
        self.assertTrue(r.contains_chained_parent)
        self.assertIn("chained_parent_source_function_body_not_exported",r.blockers)

    def test_original_rip_global_data_is_blocked(self):
        r=source(hexbytes="48 8b 05 10 00 00 00 c3")
        self.assertIn(
            "original_PE_RIP_relative_data_or_relocation_dependency",r.blockers)
        self.assertFalse(r.confirmed_reference_behavior)

    def test_external_call_even_with_good_xdata_blocked(self):
        r=source(hexbytes="e8 10 00 00 00 c3")
        self.assertIn("original_external_or_indirect_call_dependencies",r.blockers)

    def test_undecoded_instruction_fails_closed(self):
        r=source(hexbytes="0f")
        self.assertIn("reachable_x64_instruction_boundary_conflict",r.blockers)

    def test_unwind_prologue_larger_than_sample_is_fragment(self):
        raw=b"\x01\x40\x00\x00"
        r=source(unwind=raw)
        self.assertIn("source_unwind_prologue_longer_than_fragment",r.blockers)

    def test_partial_metadata_rejected_as_unverified_even_on_ret(self):
        r=source(status="UNWIND_SOURCE_READ_OR_FORMAT_UNSUPPORTED")
        self.assertEqual(r.first_blocker,
                         "source_unwind_chain_incomplete_or_unverified")
        self.assertFalse(r.confirmed_android_arm64_game_execution)

    def test_real_seh_handler_dependency_does_not_vanish(self):
        seh=b"\x09\x00\x00\x00"+struct.pack("<I",0x3100)
        r=source(unwind=seh)
        self.assertIn("win64_exception_handler_dependency_unresolved",r.blockers)

    def test_no_reachable_ret_cannot_count_as_callable(self):
        r=source(hexbytes="90 90")
        self.assertIn("no_reachable_return_from_source_entry",r.blockers)

    def test_unreachable_trailing_padding_blocks_full_function_label(self):
        r=source(hexbytes="c3 cc cc")
        self.assertIn("unreachable_code_or_padding_in_source_region",r.blockers)

    def test_win64_stack_size_above_guest_is_not_auto_support(self):
        # UWOP_ALLOC_LARGE opinfo 1 followed by little-endian uint32 9000.
        raw=b"\x01\x08\x03\x00\x08\x11"+struct.pack("<I",9000)+b"\x00\x00"
        r=source(unwind=raw)
        self.assertIn(
            "original_win64_stack_exceeds_current_aot_guest_memory",r.blockers)

    def test_mismatched_cfg_rva_fails(self):
        cfg=inspect_cfg(b"\xc3",BASE)
        with self.assertRaises(ValueError):
            evaluate_win64_source_function(
                BASE+1,1,cfg,[decode_unwind_info(b"\x01\x00\x00\x00")],
                "COMPLETE_UNWIND_CHAIN_READ")

    def test_unknown_unwind_record_objects_rejected(self):
        cfg=inspect_cfg(b"\xc3",BASE)
        with self.assertRaises(ValueError):
            evaluate_win64_source_function(
                BASE,1,cfg,[object()],"COMPLETE_UNWIND_CHAIN_READ")

    def test_source_report_never_exposes_machine_code(self):
        r=source()
        txt=str(r.safe_report())
        self.assertNotIn("48 89 c8",txt)
        self.assertNotIn("GameAssembly.dll",txt)
        self.assertFalse(r.safe_report()["confirmed_real_carx_frame"])

if __name__=="__main__":
    unittest.main(verbosity=2)
