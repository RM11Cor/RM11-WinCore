#!/usr/bin/env python3
"""End-to-end synthetic v1.3 original parent/child source ZIP CFG tests.

No original CarX proprietary byte content in repo or fixtures.
"""
from __future__ import annotations
import hashlib,json,struct,sys,tempfile,unittest
from pathlib import Path
from zipfile import ZipFile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from triage_original_carx_parent_child_cfg import owner_source_parent_child_cfg
def sha(b):return hashlib.sha256(b).hexdigest()

class OriginalWin64ParentChildCodeTriageTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)

    def archive(self,malformed_parent_hash=False,unresolved=False):
        child=bytes.fromhex("48 89 c8 c3")
        parent=(bytes.fromhex("e8 10 00 00 00 c3") if unresolved
                else bytes.fromhex("e9 fb fe ff ff"))
        child_xdata=bytes([0x21,0,0,0])+struct.pack(
            "<III",0x1200,0x1200+len(parent),0x2200)
        parent_xdata=bytes([0x01,0,0,0])
        items={
            "code/rva_00001100.bin":child,
            "parents/rva_00001200.bin":parent,
            "unwind/rva_00002100.bin":child_xdata,
            "unwind/rva_00002200.bin":parent_xdata,
        }
        source_parent={
            "begin_rva":0x1200,"end_rva":0x1200+len(parent),
            "unwind_rva":0x2200,
            "zip_member":"parents/rva_00001200.bin",
            "length_bytes":len(parent),
            "sha256":"0"*64 if malformed_parent_hash else sha(parent),
        }
        chain=[{
            "unwind_rva":0x2100,"zip_member":"unwind/rva_00002100.bin",
            "length_bytes":len(child_xdata),"sha256":sha(child_xdata),
            "version":1,"flags":4,"code_slots":0,
            "has_chained_runtime_function":True,
            "chained_runtime_function":{
                "begin_rva":0x1200,"end_rva":0x1200+len(parent),
                "unwind_rva":0x2200,
            },
            "parent_code_status":"EXPORTED_VERIFIED_BOUNDED_FRAGMENT",
            "original_parent_code":source_parent,
        },{
            "unwind_rva":0x2200,"zip_member":"unwind/rva_00002200.bin",
            "length_bytes":len(parent_xdata),"sha256":sha(parent_xdata),
            "version":1,"flags":0,"code_slots":0,
            "has_chained_runtime_function":False,
        }]
        manifest={
            "schema":"rm11carx.original-win64-gameassembly-bounded-function-samples.v3",
            "version":"1.3-parent-code-bounded",
            "sampler_policy":"one_source_function_per_distinct_unwind_rva",
            "sampled_distinct_unwind_rva_count":1,
            "max_parent_code_fragment_bytes":4096,
            "max_parent_code_total_bytes":2*1024*1024,
            "unwind_records_exported_unique":2,
            "unique_parent_source_code_fragments":1,
            "original_parent_code_bytes_exported":len(parent),
            "parent_code_reference_extraction_issues":0,
            "functions":[{
                "relative_rva":0x1100,
                "length_bytes":len(child),
                "zip_member":"code/rva_00001100.bin",
                "sha256":sha(child),
                "win64_unwind_info_rva":0x2100,
                "unwind_records":chain,
                "unwind_status":"COMPLETE_UNWIND_CHAIN_READ",
            }],
        }
        dest=self.root/"fixture.zip"
        with ZipFile(dest,"w") as z:
            for name,data in items.items():z.writestr(name,data)
            z.writestr("manifest.json",json.dumps(manifest))
        return dest

    def test_actual_x86_parent_jump_to_child_is_linked(self):
        report=owner_source_parent_child_cfg(self.archive())
        self.assertEqual(report["source_group_stats"]["source_groups_verified"],1)
        self.assertEqual(report["source_group_stats"][
            "groups_with_cross_segment_x86_control_flow_from_root"],1)
        record=report["ranked_original_source_candidate_structures"][0]
        root=record["actual_root_entry_reachable_cfg"]
        self.assertEqual(root["cross_segment_direct_branch_edges"],1)
        self.assertEqual(root["unmapped_direct_branch_edges"],0)
        self.assertEqual(root["reachable_ret_instructions"],1)
        self.assertFalse(report["original_carx_android_arm64_execution"])

    def test_unresolved_original_call_is_visible_not_invented(self):
        report=owner_source_parent_child_cfg(self.archive(unresolved=True))
        r=report["ranked_original_source_candidate_structures"][0][
            "actual_root_entry_reachable_cfg"]
        self.assertEqual(r["unmapped_direct_call_edges"],1)
        self.assertEqual(r["cross_segment_direct_branch_edges"],0)
        self.assertFalse(report["original_gameplay_method_identified"])

    def test_bad_actual_source_parent_hash_aborts_all_cfg(self):
        with self.assertRaises(ValueError):
            owner_source_parent_child_cfg(
                self.archive(malformed_parent_hash=True))

    def test_no_raw_game_code_or_disassembly_in_report(self):
        report=owner_source_parent_child_cfg(self.archive())
        text=json.dumps(report)
        self.assertNotIn("e9 fb fe ff ff",text)
        self.assertNotIn("mov rax",text)
        self.assertTrue(report["unwind_chain_not_a_control_flow_edge"])
        self.assertFalse(report["original_proprietary_code_in_report"])

if __name__=="__main__":
    unittest.main(verbosity=2)
