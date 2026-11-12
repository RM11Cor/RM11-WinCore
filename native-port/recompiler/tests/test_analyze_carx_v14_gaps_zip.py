#!/usr/bin/env python3
"""Original source gap extraction v1.4 synthetic end-to-end regression.

No original CarX x86 code is included in GitHub fixtures.
"""
from __future__ import annotations
import hashlib,json,struct,sys,tempfile,unittest
from pathlib import Path
from zipfile import ZipFile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from analyze_carx_win64_xdata_zip import analyze
from triage_original_carx_parent_child_cfg import owner_source_parent_child_cfg
from screen_carx_pdata_zip import screen

def digest(data:bytes)->str:
    return hashlib.sha256(data).hexdigest()

class OriginalSourceGapV14EndToEnd(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root=Path(t.name)

    def archive(self,change=None):
        # Original Win64 PE fragment model:
        # parent RVA 0x1200: NOP -> gap[0x1201..0x1203): NOP NOP
        # child RVA 0x1203: NOP NOP NOP RET.
        # With the gap, source root reaches child RET by actual x86
        # instructions. Without it, root has a missing fallthrough edge.
        child=b"\x90\x90\x90\xc3"
        parent=b"\x90"
        missing=b"\x90\x90"
        chain=bytes([0x21,0,0,0])+struct.pack("<III",0x1200,0x1201,0x2200)
        plain=b"\x01\x00\x00\x00"
        members={
            "code/rva_00001203.bin":child,
            "parents/rva_00001200.bin":parent,
            "gaps/rva_00001201.bin":missing,
            "unwind/rva_00002100.bin":chain,
            "unwind/rva_00002200.bin":plain,
        }
        original_parent={
            "begin_rva":0x1200,"end_rva":0x1201,"unwind_rva":0x2200,
            "zip_member":"parents/rva_00001200.bin",
            "length_bytes":len(parent),"sha256":digest(parent),
        }
        gap={
            "begin_rva":0x1201,"end_rva":0x1203,
            "zip_member":"gaps/rva_00001201.bin",
            "length_bytes":len(missing),"sha256":digest(missing),
            "gap_source_status":"EXPORTED_RAW_PE_EXECUTABLE_INTERVAL",
        }
        meta={
            "schema":"rm11carx.original-win64-gameassembly-bounded-function-samples.v4",
            "version":"1.4-inter-region-executable-source-gaps",
            "max_parent_code_fragment_bytes":4096,
            "max_parent_code_total_bytes":2*1024*1024,
            "max_executable_inter_region_gap_bytes":4096,
            "max_executable_inter_region_gap_total_bytes":2*1024*1024,
            "sampler_policy":"one_source_function_per_distinct_unwind_rva",
            "sampled_distinct_unwind_rva_count":1,
            "unwind_records_exported_unique":2,
            "unique_parent_source_code_fragments":1,
            "original_parent_code_bytes_exported":1,
            "parent_code_reference_extraction_issues":0,
            "unique_executable_inter_region_gap_fragments":1,
            "original_executable_gap_code_bytes_exported":2,
            "executable_gap_extraction_issues":0,
            "functions":[{
                "relative_rva":0x1203,
                "length_bytes":4,
                "zip_member":"code/rva_00001203.bin",
                "sha256":digest(child),
                "win64_unwind_info_rva":0x2100,
                "unwind_records":[{
                    "unwind_rva":0x2100,
                    "zip_member":"unwind/rva_00002100.bin",
                    "length_bytes":16,"sha256":digest(chain),
                    "version":1,"flags":4,"code_slots":0,
                    "chained_runtime_function":{
                        "begin_rva":0x1200,"end_rva":0x1201,
                        "unwind_rva":0x2200,
                    },
                    "parent_code_status":"EXPORTED_VERIFIED_BOUNDED_FRAGMENT",
                    "original_parent_code":original_parent,
                },{
                    "unwind_rva":0x2200,
                    "zip_member":"unwind/rva_00002200.bin",
                    "length_bytes":4,"sha256":digest(plain),
                    "version":1,"flags":0,"code_slots":0,
                }],
                "unwind_status":"COMPLETE_UNWIND_CHAIN_READ",
                "inter_region_gaps":[gap],
                "inter_region_gap_status":
                    "RECORDED_BOUNDED_ORIGINAL_PE_SOURCE_INTERVALS",
            }],
        }
        if change:change(meta,members)
        path=self.root/"original_source_gap_v14.zip"
        with ZipFile(path,"w") as z:
            for name,raw in members.items():
                z.writestr(name,raw)
            z.writestr("manifest.json",json.dumps(meta))
        return path

    def test_actual_source_gap_sha_complete_and_reachable_root(self):
        zip_path=self.archive()
        audit=analyze(zip_path)
        self.assertEqual(audit["sha256_verified_unique_executable_gap_fragments"],1)
        self.assertEqual(audit["sha256_verified_unique_executable_gap_bytes"],2)
        report=owner_source_parent_child_cfg(zip_path)
        self.assertEqual(report["source_group_stats"]["verified_raw_executable_gap_regions"],1)
        view=report["ranked_original_source_candidate_structures"][0][
            "actual_root_entry_reachable_cfg"]
        self.assertEqual(view["unmapped_fallthrough_edges"],0)
        self.assertEqual(view["reachable_ret_instructions"],1)
        self.assertEqual(view["unreachable_code_bytes"],0)
        self.assertFalse(report["original_carx_android_arm64_execution"])

    def test_source_gap_sha_tampering_must_fail_closed(self):
        def corrupt(meta,members):
            meta["functions"][0]["inter_region_gaps"][0]["sha256"]="0"*64
        with self.assertRaises(ValueError):
            analyze(self.archive(corrupt))

    def test_malformed_source_gap_bounds_must_fail(self):
        def corrupt(meta,members):
            meta["functions"][0]["inter_region_gaps"][0]["end_rva"]=0x1204
        with self.assertRaises(ValueError):
            analyze(self.archive(corrupt))

    def test_missing_source_gap_code_member_must_fail(self):
        def missing(meta,members):
            del members["gaps/rva_00001201.bin"]
        with self.assertRaises((KeyError,ValueError)):
            analyze(self.archive(missing))

    def test_missing_gap_changes_reachable_control_flow(self):
        def missing(meta,members):
            del members["gaps/rva_00001201.bin"]
            meta["functions"][0]["inter_region_gaps"][0]={
                "begin_rva":0x1201,"end_rva":0x1203,
                "gap_source_status":"ORIGINAL_PE_GAP_NOT_FILE_BACKED_OR_TOO_LARGE",
            }
            meta["unique_executable_inter_region_gap_fragments"]=0
            meta["original_executable_gap_code_bytes_exported"]=0
            meta["executable_gap_extraction_issues"]=1
        path=self.archive(missing)
        report=owner_source_parent_child_cfg(path)
        view=report["ranked_original_source_candidate_structures"][0][
            "actual_root_entry_reachable_cfg"]
        self.assertEqual(view["unmapped_fallthrough_edges"],1)
        self.assertEqual(view["reachable_ret_instructions"],0)
        self.assertEqual(
            report["source_group_stats"]["source_groups_with_missing_executable_gap_bytes"],1)

    def test_forged_total_source_gap_bytes_rejected(self):
        def forge(meta,members):
            meta["original_executable_gap_code_bytes_exported"]=100
        with self.assertRaises(ValueError):
            analyze(self.archive(forge))

    def test_v14_codegen_does_not_treat_parent_chain_as_whole_method(self):
        candidate=screen(self.archive())
        self.assertEqual(candidate["verified_original_executable_gap_fragments"],1)
        self.assertEqual(candidate["aot_supported_source_functions"],0)
        self.assertTrue(candidate["xdata_admission_enforced_before_cpp_codegen"])

if __name__=="__main__":
    unittest.main(verbosity=2)
