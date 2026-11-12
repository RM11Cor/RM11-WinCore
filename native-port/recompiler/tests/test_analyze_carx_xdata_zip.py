#!/usr/bin/env python3
"""All-original synthetic Win64 .pdata + .xdata ZIP integrity/chain controls."""
from __future__ import annotations
import hashlib
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import analyze_carx_win64_xdata_zip as analyzer
import screen_carx_pdata_zip as screener

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

class ActualSourceUnwindPackageTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)

    def make_package(self,corrupt=False,wrong_chain=False,missing=False):
        # Windows-x64 RCX argument => RAX, add RDX, return.
        code=bytes.fromhex("48 89 c8 48 01 d0 c3")
        # A chained range pointing to a parent xdata RUNTIME_FUNCTION.
        parent=bytes([1,6,2,0,6,0x42,1,0x30])
        chain=bytes([0x21,0,0,0])+struct.pack("<III",
                                               0x1200,0x1270,0x2200)
        members={
            "code/rva_00001100.bin":code,
            "unwind/rva_00002100.bin":chain,
            "unwind/rva_00002200.bin":parent
        }
        refs=[]
        for rva,raw in ((0x2100,chain),(0x2200,parent)):
            item={
                "unwind_rva":rva,
                "zip_member":"unwind/rva_%08x.bin"%rva,
                "length_bytes":len(raw),
                "sha256":sha(raw),
                "version":1,
                "flags":4 if rva==0x2100 else 0,
                "code_slots":0 if rva==0x2100 else 2,
            }
            if rva==0x2100:
                item["has_chained_runtime_function"]=True
                item["chained_runtime_function"]={
                    "begin_rva":0x1200,
                    "end_rva":0x1270,
                    "unwind_rva":0x2300 if wrong_chain else 0x2200,
                }
            refs.append(item)
        manifest={
            "schema":analyzer.ZIP_SCHEMA,
            "functions":[{
                "relative_rva":0x1100,
                "length_bytes":len(code),
                "win64_unwind_info_rva":0x2100,
                "zip_member":"code/rva_00001100.bin",
                "sha256":sha(code),
                "unwind_records":refs,
                "unwind_status":"COMPLETE_UNWIND_CHAIN_READ",
            }],
            "unwind_records_exported_unique":2,
        }
        if corrupt:
            manifest["functions"][0]["unwind_records"][1]["sha256"]="0"*64
        if missing:
            del members["unwind/rva_00002200.bin"]
        source=self.root/"source.zip"
        with ZipFile(source,"w") as z:
            for name,raw in members.items():z.writestr(name,raw)
            z.writestr("manifest.json",json.dumps(manifest))
        return source

    def test_original_source_v11_chain_recovery_and_screener(self):
        src=self.make_package()
        r=analyzer.analyze(src)
        self.assertEqual(r["sha256_verified_code_regions"],1)
        self.assertEqual(r["sha256_verified_unique_unwind_records"],2)
        self.assertEqual(r["independently_decoded_win64_unwind_records"],2)
        self.assertEqual(r["reported_complete_unwind_chains"],1)
        self.assertEqual(r["source_chain_observations"]["chained_unwind_record"],1)
        self.assertFalse(r["real_il2cpp_gameplay_method_identified"])
        self.assertFalse(r["original_carx_machine_code_executed_on_android"])
        screening=screener.screen(src)
        self.assertEqual(screening["original_function_samples_examined"],1)
        self.assertEqual(screening["aot_supported_source_functions"],0)
        self.assertEqual(screening["aot_rejected_source_functions"],1)
        self.assertTrue(screening["xdata_admission_enforced_before_cpp_codegen"])
        self.assertEqual(
            screening["rejection_categories"][
                "original_unwind_parent_or_boundary_dependencies_unresolved"],1)
        self.assertEqual(screening["original_unwind_records_sha_verified"],2)
        self.assertIn(
            "chained_parent_source_function_body_not_exported",
            r["source_function_unwind_details"][0]["callable_source_admission"]["blockers"])

    def test_complete_nonchained_xdata_still_allows_cpp_candidate_not_game_proof(self):
        src=self.make_package()
        with ZipFile(src) as z:
            code=z.read("code/rva_00001100.bin")
        plain=b"\x01\x00\x00\x00"
        manifest={
            "schema":analyzer.ZIP_SCHEMA,
            "functions":[{
                "relative_rva":0x1100,
                "length_bytes":len(code),
                "win64_unwind_info_rva":0x2100,
                "zip_member":"code/rva_00001100.bin",
                "sha256":sha(code),
                "unwind_records":[{
                    "unwind_rva":0x2100,
                    "zip_member":"unwind/rva_00002100.bin",
                    "length_bytes":len(plain),
                    "sha256":sha(plain),
                    "version":1,"flags":0,"code_slots":0,
                }],
                "unwind_status":"COMPLETE_UNWIND_CHAIN_READ",
            }],
            "unwind_records_exported_unique":1,
        }
        path=self.root/"unchained.zip"
        with ZipFile(path,"w") as z:
            z.writestr("code/rva_00001100.bin",code)
            z.writestr("unwind/rva_00002100.bin",plain)
            z.writestr("manifest.json",json.dumps(manifest))
        report=analyzer.analyze(path)
        admission=report["source_function_unwind_details"][0]["callable_source_admission"]
        self.assertEqual(admission["status"],
                         "STRUCTURALLY_LOCAL_CANDIDATE_NEEDS_REFERENCE_EXECUTION")
        screening=screener.screen(path)
        self.assertEqual(screening["aot_supported_source_functions"],1)
        self.assertFalse(report["original_carx_machine_code_executed_on_android"])

    def with_diversity_manifest(self,source,modify=None):
        with ZipFile(source) as z:
            members={name:z.read(name) for name in z.namelist()}
        manifest=json.loads(members["manifest.json"])
        manifest["version"]="1.2-source-diverse"
        manifest["sampler_policy"]="one_source_function_per_distinct_unwind_rva"
        manifest["sampled_distinct_unwind_rva_count"]=len({
            item["win64_unwind_info_rva"] for item in manifest["functions"]
        })
        if modify:
            modify(manifest,members)
        members["manifest.json"]=json.dumps(manifest).encode()
        dest=self.root/"diverse.zip"
        with ZipFile(dest,"w") as out:
            for name,raw in members.items():
                out.writestr(name,raw)
        return dest

    def test_v12_source_unique_unwind_metadata_verified(self):
        source=self.with_diversity_manifest(self.make_package())
        report=analyzer.analyze(source)
        self.assertEqual(report["observed_distinct_source_unwind_rvas"],1)
        self.assertTrue(report["v12_source_sampling_diversity_verified"])
        screening=screener.screen(source)
        self.assertTrue(screening["xdata_admission_enforced_before_cpp_codegen"])

    def test_v12_reject_duplicate_primary_unwind_source_rvas(self):
        def duplicate(manifest,members):
            first=manifest["functions"][0]
            other=dict(first)
            other["relative_rva"]=0x1300
            other["zip_member"]="code/rva_00001300.bin"
            members[other["zip_member"]]=members[first["zip_member"]]
            manifest["functions"].append(other)
            manifest["sampled_distinct_unwind_rva_count"]=1
        source=self.with_diversity_manifest(self.make_package(),duplicate)
        with self.assertRaises(ValueError):
            analyzer.analyze(source)

    def test_v12_reject_false_distinct_unwind_claim(self):
        source=self.with_diversity_manifest(
            self.make_package(),
            lambda manifest,members:
                manifest.update({"sampled_distinct_unwind_rva_count":256}))
        with self.assertRaises(ValueError):
            analyzer.analyze(source)

    def with_original_parent_code(self,source,modify=None):
        with ZipFile(source) as z:
            members={name:z.read(name) for name in z.namelist()}
        manifest=json.loads(members["manifest.json"])
        manifest.update({
            "schema":analyzer.ZIP_SCHEMA_V3,
            "version":"1.3-parent-code-bounded",
            "sampler_policy":"one_source_function_per_distinct_unwind_rva",
            "sampled_distinct_unwind_rva_count":1,
            "max_parent_code_fragment_bytes":4096,
            "max_parent_code_total_bytes":2*1024*1024,
        })
        # Original synthetic parent PE code fragment [0x1200,0x1270).
        parent=b"\x90"*111+b"\xc3"
        name="parents/rva_00001200.bin"
        members[name]=parent
        chained=manifest["functions"][0]["unwind_records"][0]
        chained["parent_code_status"]="EXPORTED_VERIFIED_BOUNDED_FRAGMENT"
        chained["original_parent_code"]={
            "begin_rva":0x1200,"end_rva":0x1270,
            "unwind_rva":0x2200,"zip_member":name,
            "length_bytes":112,"sha256":sha(parent),
        }
        manifest["unique_parent_source_code_fragments"]=1
        manifest["original_parent_code_bytes_exported"]=112
        manifest["parent_code_reference_extraction_issues"]=0
        if modify:
            modify(manifest,members)
        members["manifest.json"]=json.dumps(manifest).encode()
        target=self.root/"original_parent.zip"
        with ZipFile(target,"w") as z:
            for name,raw in members.items():
                z.writestr(name,raw)
        return target

    def test_v13_real_parent_code_sha_and_source_gate(self):
        source=self.with_original_parent_code(self.make_package())
        r=analyzer.analyze(source)
        self.assertTrue(r["original_parent_code_archive_schema_v3"])
        self.assertEqual(r["sha256_verified_unique_parent_code_fragments"],1)
        self.assertEqual(r["sha256_verified_parent_code_references"],1)
        self.assertEqual(r["sha256_verified_unique_parent_code_bytes"],112)
        blockers=r["source_function_unwind_details"][0][
            "callable_source_admission"]["blockers"]
        self.assertIn("chained_parent_code_fragments_require_merged_cfg",blockers)
        self.assertNotIn("chained_parent_source_function_body_not_exported",blockers)
        s=screener.screen(source)
        self.assertEqual(s["verified_original_chained_parent_code_fragments"],1)
        self.assertEqual(s["aot_supported_source_functions"],0)

    def test_v13_sha_bad_parent_never_accepted(self):
        def corrupt(manifest,members):
            manifest["functions"][0]["unwind_records"][0][
                "original_parent_code"]["sha256"]="0"*64
        with self.assertRaises(ValueError):
            analyzer.analyze(self.with_original_parent_code(
                self.make_package(),corrupt))

    def test_v13_chained_parent_code_wrong_source_begin_rejected(self):
        def mismatch(manifest,members):
            manifest["functions"][0]["unwind_records"][0][
                "original_parent_code"]["begin_rva"]=0x1201
        with self.assertRaises(ValueError):
            analyzer.analyze(self.with_original_parent_code(
                self.make_package(),mismatch))

    def test_v13_parent_code_declared_but_missing_fails_closed(self):
        def missing(manifest,members):
            del members["parents/rva_00001200.bin"]
        with self.assertRaises(ValueError):
            analyzer.analyze(self.with_original_parent_code(
                self.make_package(),missing))

    def test_v13_parent_code_bytes_counter_forgery_rejected(self):
        def bad_count(manifest,members):
            manifest["original_parent_code_bytes_exported"]=123
        with self.assertRaises(ValueError):
            analyzer.analyze(self.with_original_parent_code(
                self.make_package(),bad_count))

    def test_v13_parent_code_not_full_unity_method(self):
        source=self.with_original_parent_code(self.make_package())
        report=analyzer.analyze(source)
        self.assertFalse(report["real_il2cpp_gameplay_method_identified"])
        self.assertFalse(report["original_carx_machine_code_executed_on_android"])
        self.assertFalse(report["original_carx_game_first_frame_rendered"])

    def test_unwind_sha_mismatch_never_accepted(self):
        with self.assertRaises(ValueError):
            analyzer.analyze(self.make_package(corrupt=True))

    def test_chained_parent_mismatch_never_accepted(self):
        with self.assertRaises(ValueError):
            analyzer.analyze(self.make_package(wrong_chain=True))

    def test_missing_actual_parent_unwind_record_fails_closed(self):
        with self.assertRaises(ValueError):
            analyzer.analyze(self.make_package(missing=True))

    def test_source_xdata_is_not_executed_as_game_code(self):
        src=self.make_package()
        report=analyzer.analyze(src)
        self.assertFalse(report["original_carx_game_first_frame_rendered"])
        self.assertTrue(report["no_original_machine_code_in_report"])
        self.assertNotIn("48 89 c8",json.dumps(report))

if __name__=="__main__":
    unittest.main(verbosity=2)
