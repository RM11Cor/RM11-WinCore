#!/usr/bin/env python3
"""Read-only local triage of x86-64 PE .pdata function sample archives.

Requires binutils objdump and a user-owned ZIP from the Android AOT code bridge.
It never runs original game binaries and never exports raw proprietary code.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

SCHEMA="rm11carx.real-pe-code-structural-triage.v1"
SOURCE_SCHEMA="rm11carx.original-win64-gameassembly-bounded-function-samples.v1"
LINE=re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*([A-Za-z][A-Za-z0-9.]*)\s*(.*?)\s*$")
MEMBER=re.compile(r"^code/rva_([0-9a-f]{8})\.bin$")
SIMD={"movups","movaps","movss","movsd","movd","movq","movapd","movupd",
      "xorps","addps","subps","mulps","divps","xorps","addss","subss",
      "mulss","divss","addsd","subsd","mulsd","divsd","pxor","paddd",
      "ucomiss","ucomisd","comiss","comisd","cvtsi2ss","cvttss2si"}

def ensure(value,reason):
    if not value:
        raise ValueError(reason)

def disassemble(code:bytes):
    with tempfile.NamedTemporaryFile(suffix=".bin") as file:
        file.write(code)
        file.flush()
        done=subprocess.run(
            ["objdump","-D","-b","binary","-m","i386:x86-64",
             "-M","intel",file.name],capture_output=True,text=True,timeout=10)
        ensure(done.returncode==0,"source disassembler failed")
    result=[]
    for line in done.stdout.splitlines():
        m=LINE.match(line)
        if m:
            result.append((int(m.group(1),16),
                           len(bytes.fromhex(m.group(2).strip().replace(" ",""))),
                           m.group(3).lower(),m.group(4).split("#",1)[0].strip()))
    ensure(bool(result),"no source instructions decoded")
    return result

def classify(length:int,insns:list):
    ops=[op for _,_,op,_ in insns]
    tags=set()
    if any(x.startswith("ret") for x in ops):tags.add("contains_ret")
    else:tags.add("no_ret")
    if any(x=="int3" for x in ops):tags.add("contains_int3")
    if any("rip" in s for _,_,_,s in insns):tags.add("rip_relative_memory")
    if any(op.startswith("v") and op not in ("verr","verw") or
           op in SIMD for op in ops):tags.add("simd_or_vector")
    if ops[0]=="pop" or (ops[0]=="add" and "rsp" in insns[0][3]):
        tags.add("possible_epilogue_or_chained_pdata_region")
    if insns[-1][0]+insns[-1][1]!=length:
        tags.add("disassembly_does_not_cover_source")
    for address,size,op,operands in insns:
        if op not in ("call","jmp"):continue
        m=re.match(r"0x([0-9a-f]+)",operands)
        inside=bool(m and int(m.group(1),16)<length)
        if not inside:
            tags.add("external_"+op+"_target")
    if "contains_ret" in tags and not(tags & {
        "external_call_target","external_jmp_target","rip_relative_memory",
        "simd_or_vector","contains_int3"}):
        tags.add("structurally_local_ret_candidate_not_proven_game_function")
    return tags

def triage(archive:Path):
    ensure(archive.is_file() and not archive.is_symlink() and
           archive.stat().st_size<=4*1024*1024,"invalid source archive")
    totals=Counter()
    opcodes=Counter()
    candidates=[]
    with zipfile.ZipFile(archive) as z:
        names=z.namelist()
        ensure(len(names)<=257 and len(names)==len(set(names)),"source ZIP member limit or duplicates")
        ensure("manifest.json" in names,"missing original source manifest")
        meta=json.loads(z.read("manifest.json"))
        ensure(meta.get("schema")==SOURCE_SCHEMA,"unknown source ZIP schema")
        functions=meta.get("functions")
        ensure(isinstance(functions,list) and 1<=len(functions)<=256,"bad source sample count")
        ensure(set(names)=={"manifest.json"}|{f["zip_member"] for f in functions},
               "ZIP member names differ from original function manifest")
        total_bytes=0
        for info in functions:
            name=info["zip_member"]
            member=MEMBER.fullmatch(name)
            ensure(member is not None and int(member.group(1),16)==info["relative_rva"],
                   "source ZIP member mismatch")
            code=z.read(name)
            total_bytes+=len(code)
            ensure(4<=len(code)<=320 and len(code)==info["length_bytes"] and
                   total_bytes<=256*320,"original sample bounds exceeded")
            ensure(hashlib.sha256(code).hexdigest()==info["sha256"],
                   "original game code SHA mismatch")
            insns=disassemble(code)
            tags=classify(len(code),insns)
            totals.update(tags)
            opcodes.update({op for _,_,op,_ in insns})
            if "structurally_local_ret_candidate_not_proven_game_function" in tags:
                candidates.append({
                    "rva_hex":"0x%08x"%info["relative_rva"],
                    "length_bytes":len(code),
                    "possible_epilogue_region":
                        "possible_epilogue_or_chained_pdata_region" in tags})
    return {
        "schema":SCHEMA,
        "source_gameassembly_bytes":meta.get("source_file_size_bytes"),
        "source_pdata_entries":meta.get("total_exception_table_entries"),
        "samples_examined_and_hashes_verified":len(functions),
        "code_bytes_examined":total_bytes,
        "categories":dict(sorted(totals.items())),
        "common_opcode_families":opcodes.most_common(32),
        "structurally_local_candidates":candidates,
        "method_names_recovered":False,
        "actual_carx_gameplay_execution_proven":False,
        "original_game_arm64_port_proven":False,
        "warning":"PE RUNTIME_FUNCTION boundaries can be partial/chained regions; "
                  "a RET or a local branch is not proof of an independent game method.",
    }

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("source_zip",type=Path)
    ap.add_argument("--out",type=Path)
    args=ap.parse_args()
    text=json.dumps(triage(args.source_zip),indent=2)+"\n"
    if args.out:args.out.write_text(text,encoding="utf8")
    else:print(text)

if __name__=="__main__":
    main()
