#!/usr/bin/env python3
"""Screen local user-owned GameAssembly RUNTIME_FUNCTION sample ZIP for AOT.

Run locally after user explicitly exports bounded samples with v1.0 app:
  python screen_carx_pdata_zip.py CarX_GameAssembly_AOT_SourceFunctions_v1.0.zip \
      --out aot_candidates.json --cpp-out-dir ./aot_cxx

Only writes generated C++ for functions fully understood by the first
recompiler subset. Never distributes/commits original game machine code;
manifest + hashes are reports, not genuine game method names.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import importlib.util
import json
import re
import sys
import zipfile
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parent))
from x64_function_aot import UnsupportedGuestCode, lift_function
from x64_control_flow_gate import inspect_cfg

MAX_ORIGINAL_BYTES=256*320
MAX_ARCHIVE_BYTES=8*1024*1024
SOURCE_SCHEMA_V2="rm11carx.original-win64-gameassembly-bounded-function-samples.v2"
SOURCE_SCHEMA_V3="rm11carx.original-win64-gameassembly-bounded-function-samples.v3"
SOURCE_SCHEMA_V4="rm11carx.original-win64-gameassembly-bounded-function-samples.v4"
SAFE_MEMBER=re.compile(r"^code/rva_([0-9a-f]{8})\.bin$")

def screen(archive:Path,cpp_dir:Path|None=None)->dict:
    result={
        "schema":"rm11carx.real-gameassembly-aot-g0-candidate-screen.v1",
        "original_carx_source_machine_code_sampled":True,
        "source_method_names_recognized":False,
        "actual_original_gameplay_semantics_proven":False,
        "android_aarch64_carx_gameplay_executed":False,
        "original_game_first_frame_rendered":False,
        "file_contents_distributed_to_github":False,
    }
    records=[]
    if archive.stat().st_size>MAX_ARCHIVE_BYTES:
        raise ValueError("archive outside bounded local sample size")
    with zipfile.ZipFile(archive,"r") as z:
        names=z.namelist()
        if len(names)>1+256+1024+1024+1024 or len(names)!=len(set(names)):
            raise ValueError("invalid/duplicate bounded sample ZIP")
        if "manifest.json" not in names:
            raise ValueError("missing authentic bridge manifest JSON")
        manifest=json.loads(z.read("manifest.json"))
        source_schema=manifest.get("schema")
        if source_schema not in (
            "rm11carx.original-win64-gameassembly-bounded-function-samples.v1",
            SOURCE_SCHEMA_V2,
            SOURCE_SCHEMA_V3,
            SOURCE_SCHEMA_V4):
            raise ValueError("wrong original source manifest schema")
        items=manifest.get("functions")
        if not isinstance(items,list) or len(items)>256 or not items:
            raise ValueError("invalid bounded function list")
        expected={"manifest.json"}|{item["zip_member"] for item in items}
        source_admission_by_rva={}
        if source_schema in (SOURCE_SCHEMA_V2,SOURCE_SCHEMA_V3,SOURCE_SCHEMA_V4):
            from analyze_carx_win64_xdata_zip import analyze
            unwind_report=analyze(archive)
            source_admission_by_rva={
                int(item["function_rva_hex"],16):
                    item["callable_source_admission"]
                for item in unwind_report["source_function_unwind_details"]
            }
            result["original_unwind_records_sha_verified"]=(
                unwind_report["sha256_verified_unique_unwind_records"])
            result["independent_win64_unwind_records_decoded"]=(
                unwind_report["independently_decoded_win64_unwind_records"])
            if source_schema in (SOURCE_SCHEMA_V3,SOURCE_SCHEMA_V4):
                result["verified_original_chained_parent_code_fragments"]=(
                    unwind_report["sha256_verified_unique_parent_code_fragments"])
                result["verified_original_parent_code_bytes"]=(
                    unwind_report["sha256_verified_unique_parent_code_bytes"])
                expected.update(
                    u["original_parent_code"]["zip_member"]
                    for item in items for u in item.get("unwind_records",[])
                    if u.get("parent_code_status")==
                        "EXPORTED_VERIFIED_BOUNDED_FRAGMENT")
            if source_schema==SOURCE_SCHEMA_V4:
                result["verified_original_executable_gap_fragments"]=(
                    unwind_report["sha256_verified_unique_executable_gap_fragments"])
                result["verified_original_executable_gap_bytes"]=(
                    unwind_report["sha256_verified_unique_executable_gap_bytes"])
                expected.update(
                    g["zip_member"] for item in items
                    for g in item.get("inter_region_gaps",[])
                    if g.get("gap_source_status")==
                        "EXPORTED_RAW_PE_EXECUTABLE_INTERVAL")
            expected.update(
                u["zip_member"] for item in items
                for u in item.get("unwind_records",[]))
        if set(names)!=expected:
            raise ValueError("ZIP contents and manifest mismatch")
        total=0
        rejected=collections.Counter()
        for i,item in enumerate(items):
            name=item["zip_member"]
            match=SAFE_MEMBER.fullmatch(name)
            if not match or int(match.group(1),16)!=item["relative_rva"]:
                raise ValueError("source method/member RVA mismatch")
            count=item.get("length_bytes")
            if not isinstance(count,int) or not (4<=count<=320):
                raise ValueError("invalid original code function bound")
            code=z.read(name)
            total+=len(code)
            if total>MAX_ORIGINAL_BYTES or len(code)!=count:
                raise ValueError("source code bytes exceed allowed manifest bounds")
            sha=hashlib.sha256(code).hexdigest()
            if sha!=item["sha256"]:
                raise ValueError("source original code SHA mismatch")
            cfg=inspect_cfg(code,base=item["relative_rva"])
            record={"rva_hex":hex(item["relative_rva"]),"bytes":len(code),
                    "sha256":sha,"statical_aot_translatable":False,
                    "reachable_original_x86_cfg":cfg.safe_report(),
                    "complete_unwind_info_verified":
                        source_schema in (SOURCE_SCHEMA_V2,SOURCE_SCHEMA_V3,SOURCE_SCHEMA_V4)}
            if source_schema in (SOURCE_SCHEMA_V2,SOURCE_SCHEMA_V3,SOURCE_SCHEMA_V4):
                admission=source_admission_by_rva.get(item["relative_rva"])
                if admission is None:
                    raise ValueError("source xdata admission missing for original RVA")
                record["callable_source_admission"]=admission
                if admission["status"]!=(
                        "STRUCTURALLY_LOCAL_CANDIDATE_NEEDS_REFERENCE_EXECUTION"):
                    reason="original_unwind_parent_or_boundary_dependencies_unresolved"
                    record["blocker_category"]=reason
                    rejected[reason]+=1
                    records.append(record)
                    continue
            if not cfg.structurally_self_contained_candidate:
                if cfg.external_direct_calls or cfg.indirect_calls:
                    reason="original_call_dependencies_unresolved"
                elif cfg.external_branches or cfg.indirect_branches:
                    reason="original_branch_dependencies_unresolved"
                elif cfg.rip_relative_memory_instructions:
                    reason="original_rip_relative_PE_data_mapping_required"
                elif cfg.overlapping_decode_attempts or cfg.decode_failures:
                    reason="unsafe_original_instruction_boundaries"
                elif cfg.unreachable_bytes:
                    reason="unreachable_padding_or_partial_function_fragment"
                elif not cfg.return_instructions:
                    reason="not_a_complete_returning_callable_region"
                else:
                    reason="unsafe_original_source_cfg"
                record["blocker_category"]=reason
                rejected[reason]+=1
                records.append(record)
                continue
            try:
                lifted=lift_function(code,base=item["relative_rva"])
            except UnsupportedGuestCode as failure:
                # Return only conservative structural classification; avoid
                # copying raw x86 hex, proprietary code or operands to report.
                explanation=str(failure)
                if "target outside" in explanation:
                    reason="unresolved_external_branch_or_call"
                elif "incomplete" in explanation:
                    reason="incomplete_x64_decode"
                elif "64-bit" in explanation or "register" in explanation:
                    reason="unsupported_register_width_or_memory"
                elif "no return" in explanation:
                    reason="function_without_ret_in_sample"
                elif "opcode" in explanation:
                    reason="unsupported_opcode"
                else:
                    reason="unsupported_function_structure"
                record["blocker_category"]=reason
                rejected[reason]+=1
            else:
                record["statical_aot_translatable"]=True
                record["decoded_instruction_count"]=lifted.insn_count
                if cpp_dir is not None:
                    cpp_dir.mkdir(parents=True,exist_ok=True)
                    source=cpp_dir/("generated_%08x.cpp"%item["relative_rva"])
                    if source.exists() or source.is_symlink():
                        raise ValueError("refuse overwriting existing generated C++")
                    source.write_text(lifted.code,encoding="utf-8")
                    record["generated_cpp_filename"]=source.name
            records.append(record)
        result["original_function_samples_examined"]=len(records)
        result["sample_code_total_bytes"]=total
        result["aot_supported_source_functions"]=sum(1 for x in records
                                                      if x["statical_aot_translatable"])
        result["aot_rejected_source_functions"]=len(records)-result["aot_supported_source_functions"]
        result["rejection_categories"]=dict(sorted(rejected.items()))
        result["per_function_results"]=records
        result["aot_cpp_generated"]=cpp_dir is not None and result["aot_supported_source_functions"]>0
        result["source_CFG_checked_before_AOT"]=True
        result["xdata_admission_enforced_before_cpp_codegen"]=source_schema in (SOURCE_SCHEMA_V2,SOURCE_SCHEMA_V3,SOURCE_SCHEMA_V4)
        result["legacy_v1_without_xdata_cannot_prove_callable_game_methods"]=source_schema not in (SOURCE_SCHEMA_V2,SOURCE_SCHEMA_V3,SOURCE_SCHEMA_V4)
        result["unresolved_source_function_fragments_not_emitted_as_CXX"]=True
        result["code_is_original_win64_unwind_function_not_confirmed_gameplay_method"]=True
    return result

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("input",type=Path)
    p.add_argument("--out",type=Path)
    p.add_argument("--cpp-out-dir",type=Path)
    args=p.parse_args()
    result=screen(args.input,args.cpp_out_dir)
    payload=json.dumps(result,indent=2,ensure_ascii=False)+"\n"
    if args.out:
        args.out.write_text(payload,encoding="utf-8")
    else:
        print(payload)
    return 0

if __name__=="__main__":
    raise SystemExit(main())
