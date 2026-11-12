#!/usr/bin/env python3
"""Offline integrity and Win64 UNWIND_INFO analysis of owner's v1.1 CarX ZIP.

Never executes source PE machine code, never outputs game bytes, and
does not call a pdata unwind region a Unity gameplay method.
The encrypted/signature provenance of the original game is NOT assessed.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import zipfile

from win64_unwind_boundary import UnsupportedWin64Unwind, decode_unwind_info
from x64_control_flow_gate import inspect_cfg
from win64_callable_source_gate import evaluate_win64_source_function

ZIP_SCHEMA="rm11carx.original-win64-gameassembly-bounded-function-samples.v2"
ZIP_SCHEMA_V3="rm11carx.original-win64-gameassembly-bounded-function-samples.v3"
ZIP_SCHEMA_V4="rm11carx.original-win64-gameassembly-bounded-function-samples.v4"
MAX_SIZE=8*1024*1024
MAX_CODE_BYTES=256*320
MAX_UNWIND_FILES=1024
MAX_PARENT_FILES=1024
MAX_GAP_FILES=1024
MAX_GAP_SOURCE_BYTES=2*1024*1024
MAX_PARENT_SOURCE_BYTES=2*1024*1024
CODE=re.compile(r"code/rva_([0-9a-f]{8})\.bin$")
UNWIND=re.compile(r"unwind/rva_([0-9a-f]{8})\.bin$")
PARENT=re.compile(r"parents/rva_([0-9a-f]{8})\.bin$")
GAP=re.compile(r"gaps/rva_([0-9a-f]{8})\.bin$")

def require(valid,reason):
    if not valid:raise ValueError(reason)

def verify_member(z:zipfile.ZipFile, info:dict,pattern:re.Pattern,expected_rva:int):
    member=info.get("zip_member")
    match=pattern.fullmatch(member or "")
    require(match is not None and int(match.group(1),16)==expected_rva,
            "ZIP member not tied to correct source RVA")
    require(member in z.NameToInfo,"original data member missing")
    declared=info.get("length_bytes")
    require(isinstance(declared,int) and 4<=declared<=528,
            "source record declared size invalid")
    require(z.getinfo(member).file_size==declared,
            "source record length mismatch")
    raw=z.read(member)
    require(len(raw)==declared,"source original data unexpected read size")
    require(hashlib.sha256(raw).hexdigest()==info.get("sha256"),
            "source original record SHA256 mismatch")
    return raw

def verify_parent_member(z:zipfile.ZipFile, parent:dict,
                         expected_begin:int,expected_end:int,
                         expected_unwind:int)->bytes:
    require(isinstance(parent,dict),"missing user-exported Win64 parent code metadata")
    begin=parent.get("begin_rva")
    end=parent.get("end_rva")
    require(begin==expected_begin and end==expected_end and
            parent.get("unwind_rva")==expected_unwind,
            "parent code declaration does not match actual original CHAININFO")
    size=end-begin
    require(1<=size<=4096 and parent.get("length_bytes")==size,
            "original parent machine-code range exceeds 4KiB bounded size")
    member=parent.get("zip_member")
    match=PARENT.fullmatch(member or "")
    require(match is not None and int(match.group(1),16)==begin,
            "parent code member does not match original BeginAddress")
    require(member in z.NameToInfo and z.getinfo(member).file_size==size,
            "original parent code member is missing or has wrong size")
    raw=z.read(member)
    require(len(raw)==size and
            hashlib.sha256(raw).hexdigest()==parent.get("sha256"),
            "original parent code bytes do not match manifest SHA256")
    return raw

def verify_gap_member(z:zipfile.ZipFile,info:dict,
                      expected_begin:int,expected_end:int)->bytes:
    member=info.get("zip_member")
    match=GAP.fullmatch(member or "")
    require(match is not None and int(match.group(1),16)==expected_begin,
            "original gap file doesn't match PE source BeginAddress")
    size=expected_end-expected_begin
    require(1<=size<=4096 and info.get("length_bytes")==size,
            "original gap size doesn't match original PE executable RVA interval")
    require(member in z.NameToInfo and z.getinfo(member).file_size==size,
            "original gap source file missing or different size")
    raw=z.read(member)
    require(len(raw)==size and
            hashlib.sha256(raw).hexdigest()==info.get("sha256"),
            "original executable gap source SHA256 verification failed")
    return raw

def analyze(source:Path)->dict:
    require(source.is_file() and not source.is_symlink() and
            0<source.stat().st_size<=MAX_SIZE,"source ZIP is unavailable or excessive")
    with zipfile.ZipFile(source) as z:
        records=z.infolist()
        names=[r.filename for r in records]
        require(len(records)<=1+256+MAX_UNWIND_FILES+MAX_PARENT_FILES+MAX_GAP_FILES,
                "archive entry bound exceeded")
        require(len(names)==len(set(names)),"duplicate original ZIP member")
        require("manifest.json" in names,"source manifest missing")
        require(all(name=="manifest.json" or CODE.fullmatch(name) or
                    UNWIND.fullmatch(name) or PARENT.fullmatch(name) or
                    GAP.fullmatch(name) for name in names),
                "unknown source ZIP members or unsafe archive paths")
        require(sum(x.file_size for x in records)<6*1024*1024,
                "uncompressed archive outside original sampling limit")
        require(z.getinfo("manifest.json").file_size<256*1024,
                "source manifest too large")
        manifest=json.loads(z.read("manifest.json"))
        source_schema=manifest.get("schema")
        require(source_schema in (ZIP_SCHEMA,ZIP_SCHEMA_V3,ZIP_SCHEMA_V4),
                "owner archive is not actual v1.1-v1.3 Win64 unwind source package")
        v3=(source_schema in (ZIP_SCHEMA_V3,ZIP_SCHEMA_V4))
        v4=(source_schema==ZIP_SCHEMA_V4)
        if v3:
            require(manifest.get("version") in (
                    "1.3-parent-code-bounded",
                    "1.4-inter-region-executable-source-gaps") and
                    manifest.get("max_parent_code_fragment_bytes")==4096 and
                    manifest.get("max_parent_code_total_bytes")==MAX_PARENT_SOURCE_BYTES,
                    "v1.3/v1.4 original parent-code export limits not documented")
        if v4:
            require(manifest.get("version")=="1.4-inter-region-executable-source-gaps" and
                    manifest.get("max_executable_inter_region_gap_bytes")==4096 and
                    manifest.get("max_executable_inter_region_gap_total_bytes")==MAX_GAP_SOURCE_BYTES,
                    "v1.4 original source gap export limits not documented")
        functions=manifest.get("functions")
        require(isinstance(functions,list) and 1<=len(functions)<=256,
                "source manifest function list absent or over bound")
        distinct_unwind_rvas={
            x.get("win64_unwind_info_rva") for x in functions
        }
        if manifest.get("version") in ("1.2-source-diverse",
                                       "1.3-parent-code-bounded",
                                       "1.4-inter-region-executable-source-gaps"):
            require(
                manifest.get("sampler_policy")==
                    "one_source_function_per_distinct_unwind_rva",
                "v1.2 sampled source strategy not declared")
            require(
                len(distinct_unwind_rvas)==len(functions) and
                all(isinstance(v,int) and 0<v<2**32
                    for v in distinct_unwind_rvas),
                "v1.2 included duplicate original unwind metadata RVA")
            require(
                manifest.get("sampled_distinct_unwind_rva_count")==
                    len(distinct_unwind_rvas),
                "v1.2 actual source and stated unique unwind count disagree")

        used={"manifest.json"}
        unique_unwind=set()
        unique_parent_code={}
        unique_gap_code={}
        original_gap_references_verified=0
        gap_source_references_missing=0
        parent_code_references_verified=0
        parent_code_references_missing=0
        code_bytes=0
        decoded=0
        unsupported=Counter()
        chain_types=Counter()
        cfg_totals=Counter()
        source_gate_totals=Counter()
        per_function=[]
        for function in functions:
            rva=function.get("relative_rva")
            require(isinstance(rva,int) and 0<rva<2**32,
                    "original PE function RVA malformed")
            sample=verify_member(z,function,CODE,rva)
            require(4<=len(sample)<=320,"original PE code region bound exceeded")
            cfg=inspect_cfg(sample,base=rva)
            cfg_totals["source_function_samples"]+=1
            cfg_totals["with_external_direct_calls"]+=cfg.external_direct_calls>0
            cfg_totals["with_indirect_calls"]+=cfg.indirect_calls>0
            cfg_totals["with_rip_relative_original_pe_references"]+=cfg.rip_relative_memory_instructions>0
            cfg_totals["with_unreachable_or_padding_bytes"]+=cfg.unreachable_bytes>0
            cfg_totals["with_overlapping_instruction_reachability"]+=cfg.overlapping_decode_attempts>0
            cfg_totals["with_unresolved_external_branches"]+=cfg.external_branches>0
            cfg_totals["with_reachable_ret"]+=cfg.return_instructions>0
            cfg_totals["local_control_flow_candidates_NOT_proven_methods"]+=cfg.structurally_self_contained_candidate
            require(function["zip_member"] not in used,
                    "duplicate code sample RVA")
            used.add(function["zip_member"])
            code_bytes+=len(sample)
            require(code_bytes<=MAX_CODE_BYTES,"original game source code budget exceeded")
            raw_chain=function.get("unwind_records")
            require(isinstance(raw_chain,list) and len(raw_chain)<=4,
                    "invalid bounded unwind chain list")
            decoded_for_function=0
            original_executable_intervals=[(rva,rva+len(sample))]
            independently_decoded_chain=[]
            status=function.get("unwind_status")
            chain_record=[]
            parent_code_complete=v3
            if raw_chain:
                require(raw_chain[0].get("unwind_rva")==
                        function.get("win64_unwind_info_rva"),
                        "unwind RVA is not original source-function unwind RVA")
            for index,item in enumerate(raw_chain):
                unwind_rva=item.get("unwind_rva")
                require(isinstance(unwind_rva,int) and 0<unwind_rva<2**32,
                        "bad xdata unwind RVA")
                unwind_raw=verify_member(z,item,UNWIND,unwind_rva)
                used.add(item["zip_member"])
                unique_unwind.add(item["zip_member"])
                try:
                    parsed=decode_unwind_info(unwind_raw)
                except UnsupportedWin64Unwind:
                    unsupported["unsupported_xdata_opcode_or_layout"]+=1
                    chain_record.append({"rva_hex":hex(unwind_rva),
                                         "status":"unsupported_xdata_opcode_or_layout"})
                    continue
                require(item.get("flags")==parsed.flags and
                        item.get("code_slots")==parsed.raw_code_slots and
                        item.get("version")==parsed.version,
                        "Android xdata source header and independent decoder disagree")
                declared_chain=item.get("chained_runtime_function")
                if parsed.chained_runtime_function:
                    chain_types["chained_unwind_record"]+=1
                    require(isinstance(declared_chain,dict),
                            "chained metadata record not declared by Android source")
                    expected=(declared_chain.get("begin_rva"),
                              declared_chain.get("end_rva"),
                              declared_chain.get("unwind_rva"))
                    require(tuple(expected)==parsed.chained_runtime_function,
                            "chained source RUNTIME_FUNCTION does not match original bytes")
                    if index+1<len(raw_chain):
                        require(raw_chain[index+1]["unwind_rva"]==expected[2],
                                "next Win64 xdata chain link missing/misordered")
                    if v3:
                        parent_status=item.get("parent_code_status")
                        if parent_status=="EXPORTED_VERIFIED_BOUNDED_FRAGMENT":
                            parent=item.get("original_parent_code")
                            parent_raw=verify_parent_member(
                                z,parent,*parsed.chained_runtime_function)
                            member=parent["zip_member"]
                            existing=unique_parent_code.get(member)
                            fingerprint=(len(parent_raw),parent["sha256"])
                            require(existing is None or existing==fingerprint,
                                    "original parent source reused with conflicting code bytes")
                            unique_parent_code[member]=fingerprint
                            used.add(member)
                            original_executable_intervals.append(
                                (expected[0],expected[1]))
                            parent_code_references_verified+=1
                        else:
                            require(
                                parent_status in (
                                    "ORIGINAL_PARENT_CODE_RANGE_REJECTED",
                                    "ORIGINAL_PARENT_RVA_LENGTH_CONFLICT",
                                    "PARENT_SOURCE_EXTRACTION_BUDGET",
                                    "ORIGINAL_PARENT_EXECUTABLE_RVA_UNAVAILABLE"),
                                "unrecognized original parent source code status")
                            require(not item.get("original_parent_code"),
                                    "parent source marked missing but file claimed")
                            parent_code_references_missing+=1
                            parent_code_complete=False
                else:
                    require(not declared_chain,
                            "Android reported false chain in independent decoder")
                    if v3:
                        require(not item.get("parent_code_status") and
                                not item.get("original_parent_code"),
                                "nonchained xdata must not declare parent executable")
                if parsed.handler_rva is not None:
                    chain_types["handler_record"]+=1
                decoded+=1
                decoded_for_function+=1
                independently_decoded_chain.append(parsed)
                chain_record.append({
                    "rva_hex":hex(unwind_rva),
                    "status":"independently_decoded",
                    "prologue_bytes":parsed.prologue_bytes,
                    "static_unwind_stack_bytes":parsed.stack_bytes_deallocated_by_unwind,
                    "handler_present":parsed.handler_rva is not None,
                    "chained":parsed.chained_runtime_function is not None,
                    "operations":[x.opcode for x in parsed.unwind_operations],
                })
            if status=="COMPLETE_UNWIND_CHAIN_READ":
                require(raw_chain and decoded_for_function==len(raw_chain) and
                        not chain_record[-1]["chained"],
                        "Android completion claim unsupported by source chain")
            # Verify executable PE gaps *between* original disjoint
            # source ranges. A gap may include unrelated original code or
            # padding and is never promoted to callable method identity.
            if v4:
                supplied=function.get("inter_region_gaps")
                require(isinstance(supplied,list) and len(supplied)<=4,
                        "v1.4 bounded inter-region gap list malformed")
                ordered=sorted(original_executable_intervals)
                if not all(ordered[i][1]<=ordered[i+1][0]
                           for i in range(len(ordered)-1)):
                    require(
                        function.get("inter_region_gap_status")==
                            "ORIGINAL_SOURCE_REGIONS_OVERLAP_CANNOT_INFER_GAP"
                        and not supplied,
                        "v1.4 ambiguous source intervals cannot claim valid gap")
                elif function.get("inter_region_gap_status")==(
                        "RECORDED_BOUNDED_ORIGINAL_PE_SOURCE_INTERVALS"):
                    expected_gaps=[
                        (ordered[i][1],ordered[i+1][0])
                        for i in range(len(ordered)-1)
                        if ordered[i+1][0]>ordered[i][1]
                    ]
                    require(len(supplied)==len(expected_gaps),
                            "original PE inter-region source gaps omitted/fabricated")
                    for g,(begin,end) in zip(supplied,expected_gaps):
                        require(g.get("begin_rva")==begin and
                                g.get("end_rva")==end,
                                "source gap RVA doesn't match actual parent/child ranges")
                        gstatus=g.get("gap_source_status")
                        if gstatus=="EXPORTED_RAW_PE_EXECUTABLE_INTERVAL":
                            source_info={
                                "zip_member":g.get("zip_member"),
                                "length_bytes":g.get("length_bytes"),
                                "sha256":g.get("sha256"),
                            }
                            raw=verify_gap_member(z,source_info,begin,end)
                            member=source_info["zip_member"]
                            fingerprint=(len(raw),source_info["sha256"])
                            old=unique_gap_code.get(member)
                            require(old is None or old==fingerprint,
                                    "source gap duplicate path conflicting content")
                            unique_gap_code[member]=fingerprint
                            used.add(member)
                            original_gap_references_verified+=1
                        else:
                            require(gstatus in (
                                "ORIGINAL_SOURCE_GAP_CONFLICTING_LENGTH",
                                "ORIGINAL_SOURCE_GAP_EXTRACTION_BUDGET",
                                "ORIGINAL_PE_GAP_NOT_FILE_BACKED_OR_TOO_LARGE"),
                                "unexpected original source gap extraction status")
                            require(not g.get("zip_member"),
                                    "declared missing gap must not claim original bytes")
                            gap_source_references_missing+=1
                else:
                    require(function.get("inter_region_gap_status") in (
                        "NO_PARENT_OR_INCOMPLETE_UNWIND_SOURCE",
                        "ORIGINAL_SOURCE_REGIONS_OVERLAP_CANNOT_INFER_GAP")
                        and not supplied,
                        "v1.4 gaps declared without validated source intervals")
            # Attach actual decoded xdata and source CFG to one stringent
            # admission result; a small pdata range is not necessarily a
            # standalone or identifiable Unity game method.
            source_gate=evaluate_win64_source_function(
                rva,len(sample),cfg,independently_decoded_chain,
                status if isinstance(status,str) else "UNWIND_NOT_READ",
                parent_code_segments_verified=(
                    v3 and parent_code_complete and
                    any(x.chained_runtime_function is not None
                        for x in independently_decoded_chain)))
            source_gate_totals[source_gate.status]+=1
            for blocker in source_gate.blockers:
                source_gate_totals["blocked_by_"+blocker]+=1
            per_function.append({
                "function_rva_hex":hex(rva),
                "callable_source_admission":source_gate.safe_report(),
                "original_function_code_bytes":len(sample),
                "unwind_metadata_status":status,
                "independently_decoded_unwind_count":decoded_for_function,
                "original_chain_parent_code_all_verified":
                    v3 and parent_code_complete,
                "reachable_original_x64_cfg":cfg.safe_report(),
                "chain":chain_record,
                "complete_callable_il2cpp_method_proven":False,
            })
        require(used==set(names),"archive contains undeclared original data")
        require(len(unique_unwind)==manifest.get("unwind_records_exported_unique"),
                "unique source unwind record count mismatch")
        if v3:
            require(
                len(unique_parent_code)==
                    manifest.get("unique_parent_source_code_fragments") and
                sum(v[0] for v in unique_parent_code.values())==
                    manifest.get("original_parent_code_bytes_exported") and
                parent_code_references_missing==
                    manifest.get("parent_code_reference_extraction_issues"),
                "v1.3 original parent code counters differ from SHA-verified ZIP")
            require(sum(v[0] for v in unique_parent_code.values())<=
                        MAX_PARENT_SOURCE_BYTES,
                    "v1.3 original parent source export over total budget")
        if v4:
            require(
                len(unique_gap_code)==
                    manifest.get("unique_executable_inter_region_gap_fragments") and
                sum(v[0] for v in unique_gap_code.values())==
                    manifest.get("original_executable_gap_code_bytes_exported") and
                gap_source_references_missing==
                    manifest.get("executable_gap_extraction_issues"),
                "v1.4 original gap source ZIP and declared counters mismatch")
            require(sum(v[0] for v in unique_gap_code.values())<=
                        MAX_GAP_SOURCE_BYTES,
                    "v1.4 original gap source export over total budget")
        return {
            "schema":"rm11carx.owner-real-gameassembly-win64-unwind-analyzed.v1",
            "original_source_archive_type":"owner Android PortLab v1.1 Windows PE x64 .pdata/.xdata",
            "sha256_verified_code_regions":len(functions),
            "observed_distinct_source_unwind_rvas":len(distinct_unwind_rvas),
            "v12_source_sampling_diversity_verified":
                manifest.get("version")=="1.2-source-diverse",
            "original_source_code_bytes_verified":code_bytes,
            "sha256_verified_unique_unwind_records":len(unique_unwind),
            "original_parent_code_archive_schema_v3":v3,
            "original_executable_gap_archive_schema_v4":v4,
            "sha256_verified_unique_executable_gap_fragments":len(unique_gap_code),
            "sha256_verified_unique_executable_gap_bytes":
                sum(v[0] for v in unique_gap_code.values()),
            "sha256_verified_gap_source_references":original_gap_references_verified,
            "unavailable_original_inter_region_gap_references":
                gap_source_references_missing,
            "sha256_verified_unique_parent_code_fragments":len(unique_parent_code),
            "sha256_verified_parent_code_references":parent_code_references_verified,
            "missing_bounded_parent_code_references":parent_code_references_missing,
            "sha256_verified_unique_parent_code_bytes":
                sum(v[0] for v in unique_parent_code.values()),
            "independently_decoded_win64_unwind_records":decoded,
            "unsupported_unwind_records":dict(sorted(unsupported.items())),
            "source_chain_observations":dict(sorted(chain_types.items())),
            "source_reachable_x64_cfg_categories":dict(sorted(cfg_totals.items())),
            "merged_unwind_plus_cfg_admission":dict(sorted(source_gate_totals.items())),
            "merged_admission_never_proves_original_gameplay_identity":True,
            "reachable_cfg_does_not_prove_whole_original_function":True,
            "reported_complete_unwind_chains":sum(x["unwind_metadata_status"]==
                                                   "COMPLETE_UNWIND_CHAIN_READ"
                                                   for x in per_function),
            "source_function_unwind_details":per_function,
            "real_il2cpp_gameplay_method_identified":False,
            "original_carx_machine_code_executed_on_android":False,
            "original_carx_game_first_frame_rendered":False,
            "no_original_machine_code_in_report":True,
            "next_gate":"merge source Win64 parent code into bounded multi-segment CFG, resolve original call/global dependencies and prove real reference behavior",
        }

def main():
    import argparse
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("source_zip",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    result=analyze(args.source_zip)
    payload=json.dumps(result,ensure_ascii=False,indent=2)+"\n"
    if args.out:
        args.out.write_text(payload,encoding="utf-8")
    else:print(payload)

if __name__=="__main__":
    main()
