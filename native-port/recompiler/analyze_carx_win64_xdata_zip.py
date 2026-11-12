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

ZIP_SCHEMA="rm11carx.original-win64-gameassembly-bounded-function-samples.v2"
MAX_SIZE=8*1024*1024
MAX_CODE_BYTES=256*320
MAX_UNWIND_FILES=1024
CODE=re.compile(r"code/rva_([0-9a-f]{8})\.bin$")
UNWIND=re.compile(r"unwind/rva_([0-9a-f]{8})\.bin$")

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

def analyze(source:Path)->dict:
    require(source.is_file() and not source.is_symlink() and
            0<source.stat().st_size<=MAX_SIZE,"source ZIP is unavailable or excessive")
    with zipfile.ZipFile(source) as z:
        records=z.infolist()
        names=[r.filename for r in records]
        require(len(records)<=1+256+MAX_UNWIND_FILES,
                "archive entry bound exceeded")
        require(len(names)==len(set(names)),"duplicate original ZIP member")
        require("manifest.json" in names,"source manifest missing")
        require(all(name=="manifest.json" or CODE.fullmatch(name) or
                    UNWIND.fullmatch(name) for name in names),
                "unknown source ZIP members or unsafe archive paths")
        require(sum(x.file_size for x in records)<2*1024*1024,
                "uncompressed archive outside original sampling limit")
        require(z.getinfo("manifest.json").file_size<256*1024,
                "source manifest too large")
        manifest=json.loads(z.read("manifest.json"))
        require(manifest.get("schema")==ZIP_SCHEMA,
                "owner archive is not actual v1.1 UNWIND_INFO source package")
        functions=manifest.get("functions")
        require(isinstance(functions,list) and 1<=len(functions)<=256,
                "source manifest function list absent or over bound")

        used={"manifest.json"}
        unique_unwind=set()
        code_bytes=0
        decoded=0
        unsupported=Counter()
        chain_types=Counter()
        per_function=[]
        for function in functions:
            rva=function.get("relative_rva")
            require(isinstance(rva,int) and 0<rva<2**32,
                    "original PE function RVA malformed")
            sample=verify_member(z,function,CODE,rva)
            require(4<=len(sample)<=320,"original PE code region bound exceeded")
            require(function["zip_member"] not in used,
                    "duplicate code sample RVA")
            used.add(function["zip_member"])
            code_bytes+=len(sample)
            require(code_bytes<=MAX_CODE_BYTES,"original game source code budget exceeded")
            raw_chain=function.get("unwind_records")
            require(isinstance(raw_chain,list) and len(raw_chain)<=4,
                    "invalid bounded unwind chain list")
            decoded_for_function=0
            status=function.get("unwind_status")
            chain_record=[]
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
                else:
                    require(not declared_chain,
                            "Android reported false chain in independent decoder")
                if parsed.handler_rva is not None:
                    chain_types["handler_record"]+=1
                decoded+=1
                decoded_for_function+=1
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
            per_function.append({
                "function_rva_hex":hex(rva),
                "original_function_code_bytes":len(sample),
                "unwind_metadata_status":status,
                "independently_decoded_unwind_count":decoded_for_function,
                "chain":chain_record,
                "complete_callable_il2cpp_method_proven":False,
            })
        require(used==set(names),"archive contains undeclared original data")
        require(len(unique_unwind)==manifest.get("unwind_records_exported_unique"),
                "unique source unwind record count mismatch")
        return {
            "schema":"rm11carx.owner-real-gameassembly-win64-unwind-analyzed.v1",
            "original_source_archive_type":"owner Android PortLab v1.1 Windows PE x64 .pdata/.xdata",
            "sha256_verified_code_regions":len(functions),
            "original_source_code_bytes_verified":code_bytes,
            "sha256_verified_unique_unwind_records":len(unique_unwind),
            "independently_decoded_win64_unwind_records":decoded,
            "unsupported_unwind_records":dict(sorted(unsupported.items())),
            "source_chain_observations":dict(sorted(chain_types.items())),
            "reported_complete_unwind_chains":sum(x["unwind_metadata_status"]==
                                                   "COMPLETE_UNWIND_CHAIN_READ"
                                                   for x in per_function),
            "source_function_unwind_details":per_function,
            "real_il2cpp_gameplay_method_identified":False,
            "original_carx_machine_code_executed_on_android":False,
            "original_carx_game_first_frame_rendered":False,
            "no_original_machine_code_in_report":True,
            "next_gate":"match decoded unwind ranges to real x86 CFG + source RIP globals; only then test actual GameAssembly method",
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
