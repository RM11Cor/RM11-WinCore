#!/usr/bin/env python3
"""Synthetic strict Win64 .xdata unwind parser tests; no original game bytes."""
from __future__ import annotations
import sys
from pathlib import Path
import struct
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import win64_unwind_boundary as uw

class Win64UnwindParserTests(unittest.TestCase):
    def test_push_rbx_and_small_stack_alloc(self):
        raw=bytes([1,6,2,0,6,0x42,1,0x30])
        r=uw.decode_unwind_info(raw)
        self.assertEqual(r.stack_bytes_deallocated_by_unwind,48)
        self.assertEqual(r.prologue_bytes,6)
        self.assertEqual(r.raw_code_slots,2)
        self.assertEqual(tuple(x.opcode for x in r.unwind_operations),
                         ("UWOP_ALLOC_SMALL","UWOP_PUSH_NONVOL"))
        self.assertFalse(r.complete_local_method_proven)

    def test_large_stack_allocation_short_extra_slot(self):
        raw=bytes([1,8,2,0,8,0x01,0x08,0x00])
        r=uw.decode_unwind_info(raw)
        self.assertEqual(r.stack_bytes_deallocated_by_unwind,64)
        self.assertEqual(r.record_bytes_consumed,8)

    def test_large_stack_allocation_far_four_bytes(self):
        raw=bytes([1,8,3,0,8,0x11])+struct.pack("<I",0x1234)+bytes(2)
        r=uw.decode_unwind_info(raw)
        self.assertEqual(r.stack_bytes_deallocated_by_unwind,0x1234)
        self.assertEqual(r.record_bytes_consumed,12)

    def test_save_nonvolatile_register_memory_offset(self):
        raw=bytes([1,7,2,0,7,0x34,3,0])
        r=uw.decode_unwind_info(raw)
        self.assertEqual(r.unwind_operations[0].save_offset_bytes,24)
        self.assertEqual(r.stack_bytes_deallocated_by_unwind,0)

    def test_save_xmm_128_offset(self):
        raw=bytes([1,6,2,0,6,0x28,5,0])
        r=uw.decode_unwind_info(raw)
        self.assertEqual(r.unwind_operations[0].opcode,"UWOP_SAVE_XMM128")
        self.assertEqual(r.unwind_operations[0].save_offset_bytes,80)

    def test_frame_register_and_frame_pointer(self):
        raw=bytes([1,4,1,0x15,4,0x03,0,0])
        r=uw.decode_unwind_info(raw)
        self.assertEqual(r.frame_register,"RBP")
        self.assertEqual(r.frame_offset_scaled16,16)
        self.assertEqual(r.unwind_operations[0].opcode,"UWOP_SET_FPREG")

    def test_seh_handler_record(self):
        raw=bytes([0x09,0,0,0])+struct.pack("<I",0x123456)
        r=uw.decode_unwind_info(raw)
        self.assertEqual(r.handler_rva,0x123456)
        self.assertIsNone(r.chained_runtime_function)
        self.assertFalse(r.safe_report()["full_original_callable_game_method_proven"])

    def test_chained_unwind_record(self):
        raw=bytes([0x21,4,0,0])+struct.pack("<III",0x1000,0x10F0,0x2000)
        r=uw.decode_unwind_info(raw)
        self.assertEqual(r.chained_runtime_function,(0x1000,0x10F0,0x2000))
        self.assertTrue(r.safe_report()["chained_runtime_function_present"])

    def test_machine_frame_stack_size(self):
        raw=bytes([1,1,1,0,1,0x0A,0,0])
        r=uw.decode_unwind_info(raw)
        self.assertEqual(r.stack_bytes_deallocated_by_unwind,40)

    def test_invalid_format_version_fails_closed(self):
        with self.assertRaises(uw.UnsupportedWin64Unwind):
            uw.decode_unwind_info(bytes([2,0,0,0]))

    def test_reserved_flags_fails_closed(self):
        with self.assertRaises(uw.UnsupportedWin64Unwind):
            uw.decode_unwind_info(bytes([0x41,0,0,0]))

    def test_missing_chained_record_rejected(self):
        with self.assertRaises(uw.UnsupportedWin64Unwind):
            uw.decode_unwind_info(bytes([0x21,0,0,0])+bytes(4))

    def test_chained_and_ehandler_together_rejected(self):
        with self.assertRaises(uw.UnsupportedWin64Unwind):
            uw.decode_unwind_info(bytes([0x29,0,0,0])+bytes(12))

    def test_unwind_code_outside_prolog_rejected(self):
        with self.assertRaises(uw.UnsupportedWin64Unwind):
            uw.decode_unwind_info(bytes([1,4,1,0,8,0x02,0,0]))

    def test_unwind_code_order_must_descend(self):
        with self.assertRaises(uw.UnsupportedWin64Unwind):
            uw.decode_unwind_info(bytes([1,10,2,0,4,0x02,8,0x02]))

    def test_unwind_code_extra_slots_missing(self):
        with self.assertRaises(uw.UnsupportedWin64Unwind):
            uw.decode_unwind_info(bytes([1,6,1,0,6,0x01,0,0]))

    def test_unknown_unwind_opcode_rejected(self):
        with self.assertRaises(uw.UnsupportedWin64Unwind):
            uw.decode_unwind_info(bytes([1,6,1,0,6,0x06,0,0]))

    def test_zero_ehandler_rva_rejected(self):
        with self.assertRaises(uw.UnsupportedWin64Unwind):
            uw.decode_unwind_info(bytes([0x09,0,0,0])+bytes(4))

    def test_invalid_routine_boundary_in_chain(self):
        with self.assertRaises(uw.UnsupportedWin64Unwind):
            uw.decode_unwind_info(bytes([0x21,0,0,0])+
                                  struct.pack("<III",0x1000,0x999,0x100))

    def test_truncated_header(self):
        with self.assertRaises(uw.UnsupportedWin64Unwind):
            uw.decode_unwind_info(bytes([1,4,0]))

    def test_no_sneaky_unwind_source_code_claim(self):
        r=uw.decode_unwind_info(bytes([1,0,0,0]))
        self.assertFalse(r.safe_report()["x64_prologue_epilogue_semantics_executed"])
        self.assertFalse(r.safe_report()["full_original_callable_game_method_proven"])
        self.assertEqual(len(r.unwind_operations),0)

if __name__=="__main__":
    unittest.main(verbosity=2)
