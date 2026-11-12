#!/usr/bin/env python3
"""Independent original GNU IFUNC85 zero-to-zero hardware store after 80..84.

Do NOT claim resolver CALL/RET execution from a store, nor 40/40 C closure.
This enforces SHA-pinned GNU sources and a genuine GDB original FEX hardware
AWATCH callback containing the actual guest-JIT-mapped ARM64 STLR STORE.
A read-only zero qword observation is specifically insufficient.
"""
from __future__ import annotations
import hashlib,json,re,sys
from pathlib import Path
from kernix_g0_l40_c_irelative85_after_five_same_fex_awatch_plan import (
    plan as make_source, SCHEMA as SOURCE_SCHEMA, GDB as GDB_SCRIPT,
    TARGET, RESOLVER, STORE_GUEST, SOURCE_OPCODE,
)
from kernix_g0_l40_c_fifth_original_writer_independent_gate import (
    verify as first_five_verify,
    negative_controls as first_five_negative,
)

SCHEMA="kernix.g0.l40c.six-original-gnu-five-globdat-ifunc85-native-store-one-fex-pid-independent.v1"
OUT="KERNIX-G0-C-Original-80-85-Six-Native-STLR-Stores-One-FEX-PID-IFUNC85-RET-OPEN.json"
LOG="original-gnu-C-first-five-then-ifunc85-one-FEX-pid.gdb.log"
ARM="IFUNC85_AWATCH_ARMED_AFTER_FIVE_IN_SAME_PID"
WRITE="IFUNC85_TRUE_NATIVE_ZERO_TO_ZERO_STORE"
FINAL="FIRST_SIX_ORIGINAL_GNU_SOURCE_NATIVE_STORES_ONE_FEX_PID"
BAD="IFUNC85_UNCLASSIFIED_AWATCH_ACCESS"
PREFIX="KERNIX_G0_L40_C_"
PAT=re.compile(r"^KERNIX_G0_L40_C_([A-Z0-9_]+) (\{[^\r\n]*\})$",re.M)

def need(ok,msg):
    if not ok:raise AssertionError("KERNIX_C_IFUNC85_SAME_PID_INDEPENDENT_FAIL_CLOSED: "+msg)
def read(path:Path,limit:int=3000000)->bytes:
    need(path.is_file() and not path.is_symlink(),"actual regular original source/native evidence "+str(path))
    data=path.read_bytes()
    need(0<len(data)<=limit,"bounded original trace or source "+str(path))
    return data

def events(log:str):
    records={}
    for m in PAT.finditer(log):
        records.setdefault(m[1],[]).append((m.start(),json.loads(m[2])))
    for k,n in ((ARM,1),(WRITE,1),(FINAL,1)):
        need(len(records.get(k,[]))==n,"one true original GNU #85 event "+k)
    need("IFUNC85_REJECT_EXCEPTION" not in records,
         "native AWATCH callback exception cannot be a valid GNU store")
    need(len(records.get(BAD,[]))<=47,
         "hardware AWATCH bound and genuine nonstore events")
    return records

def verify(log:str,source:dict):
    need(source["schema"]==SOURCE_SCHEMA
         and source["previous_five_source_indices"]==[80,81,82,83,84]
         and source["original_IRELATIVE_source_index"]==85
         and source["original_IRELATIVE_target"]==TARGET
         and source["original_IRELATIVE_old_qword"]=="0x0"
         and source["candidate_source_resolver_guest_entry"]==RESOLVER
         and source["original_GNU_ldso_x86_store_guest_RIP"]==STORE_GUEST
         and source["original_GNU_ldso_x86_store_opcode"]==SOURCE_OPCODE,
         "immutable first five and original GNU IFUNC85 SHA source only")
    ev=events(log)
    armed_position,armed=ev[ARM][0]
    hit_position,hit=ev[WRITE][0]
    final_position,final=ev[FINAL][0]
    need(armed_position<hit_position<final_position,
         "original FEX real same-PID native AWATCH after first five")
    origfive=first_five_verify(log[:armed_position],source["first_five_source_plan"])
    pid=origfive["pid"]
    need(type(pid) is int and pid>0 and armed=={
        "pid":pid,"index":85,"target":TARGET,"prewrite":"0x0",
        "expected_guest_store":STORE_GUEST,"source_resolver":RESOLVER,
        "five_indices":[80,81,82,83,84],"native_writer_proven_yet":False,
    },"same real FEX native process original IFUNC85 watch armed after five")
    for pos,x in ev.get(BAD,[]):
        need(armed_position<pos<hit_position
             and x["pid"]==pid and x["index"]==85
             and x["access_ordinal"]<hit["access_ordinal"],
             "unclassified AWATCH read must precede true native store")
    fields={"index","pid","access_ordinal","target","value","pc","x4","x19",
            "x28","instruction","FEX_guest_entry","FEX_guest_size",
            "FEX_native_ops","source_x86_3bytes"}
    need(set(hit)==fields
         and type(hit["index"]) is int and hit["index"]==85
         and type(hit["pid"]) is int and hit["pid"]==pid
         and type(hit["access_ordinal"]) is int and 1<=hit["access_ordinal"]<=48
         and hit["access_ordinal"]==len(ev.get(BAD,[]))+1
         and hit["target"]==TARGET and hit["value"]=="0x0"
         and hit["x4"]=="0x0" and hit["x19"]==TARGET
         and type(hit["FEX_guest_size"]) is int and hit["FEX_guest_size"]==3
         and type(hit["FEX_native_ops"]) is int and 1<=hit["FEX_native_ops"]<=64
         and hit["FEX_guest_entry"]==STORE_GUEST
         and hit["source_x86_3bytes"]==SOURCE_OPCODE
         and int(hit["pc"],16)>=0xffff00000000
         and int(hit["x28"],16)>=0xffff00000000
         and re.search(r"\bstlr\s+x4,\s*\[x19\]",hit["instruction"]) is not None,
         "EXACT original IFUNC85 zero store: native STLR x4 zero x19 target, original GNU FEX guest JIT source")
    need(final=={
        "pid":pid,"indices":[80,81,82,83,84,85],
        "source85_zero_to_zero_real_native_store":True,
        "original_IFUNC85_resolver_ENTRY_and_RET_chain_proven":False,
        "stage_C_all_40_original_writers_proven":False,
        "all_147_one_guest_loader_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    },"six authentic GLOB_DAT/IRELATIVE same pid only; no false loader claims")
    return pid,hit,ev

def corrupt(log:str,kind:str,index:int,field:str,value):
    candidates=[x for x in PAT.finditer(log) if x[1]==kind]
    need(index<len(candidates),"expected real native event for mutation")
    match=candidates[index]
    doc=json.loads(match[2])
    need(field in doc and doc[field]!=value,"mutation must change source evidence")
    doc[field]=value
    return log[:match.start()]+PREFIX+kind+" "+json.dumps(doc,sort_keys=True)+log[match.end():]

def negative_controls(log:str,src:dict):
    variants=[
        ("armed_pid",ARM,0,"pid",999999),
        ("armed_target",ARM,0,"target","0x1"),
        ("armed_zero_forged",ARM,0,"prewrite","0x1"),
        ("armed_resolver_forged",ARM,0,"source_resolver","0x1"),
        ("armed_writer_forged",ARM,0,"expected_guest_store","0x1"),
        ("armed_first_five_forged",ARM,0,"five_indices",[80,81,82]),
        ("native_index",WRITE,0,"index",86),
        ("native_pid",WRITE,0,"pid",999999),
        ("native_x19_target",WRITE,0,"x19","0x1"),
        ("native_x4_zero",WRITE,0,"x4","0x1"),
        ("native_source_x86_opcode",WRITE,0,"source_x86_3bytes","909090"),
        ("native_jit_entry",WRITE,0,"FEX_guest_entry","0x1"),
        ("native_pc",WRITE,0,"pc","0x2"),
        ("native_target",WRITE,0,"target","0x1"),
        ("native_value",WRITE,0,"value","0x1"),
        ("native_native_ops",WRITE,0,"FEX_native_ops",999),
        ("native_guest_size",WRITE,0,"FEX_guest_size",4),
        ("forged_final_pid",FINAL,0,"pid",999999),
        ("forged_final_85_resolver",FINAL,0,"original_IFUNC85_resolver_ENTRY_and_RET_chain_proven",True),
        ("forged_final_C40",FINAL,0,"stage_C_all_40_original_writers_proven",True),
    ]
    need(len(variants)==20,"20 false zero-to-zero native ARM64 hardware writer logs")
    denied=[]
    for name,kind,n,field,val in variants:
        try:verify(corrupt(log,kind,n,field,val),src)
        except (AssertionError,KeyError,ValueError,TypeError):denied.append(name)
        else:raise AssertionError("FORGED_GNU_IFUNC85_ZERO_NATIVE_STORE_ACCEPTED "+name)
    need(len(denied)==20 and len(set(denied))==20,"every falsified native read/store/resolver scope denied")
    return denied

def run(triad:Path,ledger:Path,repo:Path,raw_dir:Path,out:Path):
    src=make_source(triad,ledger,repo,out/"source-rebuild")
    script=read(out/"source-rebuild"/GDB_SCRIPT,150000)
    need(hashlib.sha256(script).hexdigest()==src["native_fex_gdb_script_sha256"],
         "regenerated pinned original GNU/FEX GDB exact script")
    log=read(raw_dir/LOG,250000).decode(errors="replace")
    rc=int(read(raw_dir/"gdb.exit",60).decode().strip())
    need(rc==0,"actual ARM64 FEX process and original GNU hardware AWATCH must exit zero")
    source=dict(src)
    source["first_five_source_plan"]=json.loads(
        read(out/"source-rebuild"/"five-source"/
             "KERNIX-G0-C-Original-GLOB_DAT80-84-Five-Rolling-One-FEX-PID-SOURCE-ONLY.json"))
    pid,hit,_=verify(log,source)
    controls=negative_controls(log,source)
    # Previously accepted 44 first-five forged controls must ALSO pass for
    # this very same original FEX inferior, not earlier separate process.
    five_prefix=log[:events(log)[ARM][0][0]]
    firstfive_denied=first_five_negative(five_prefix,source["first_five_source_plan"])
    need(len(firstfive_denied)==16 and len(controls)==20,
         "16 fifth-native and 20 #85 independent forged original GNU traces")
    report={
        "schema":SCHEMA,
        "source_indices_same_real_FEX_native_writer_PID":[80,81,82,83,84,85],
        "actual_linux_ARM64_FEX_PID":pid,
        "original_source85_zero_to_zero_native_hardware_store":True,
        "original_source85_native_ARM64_STLR":hit["instruction"],
        "original_source85_native_store_guest_RIP":hit["FEX_guest_entry"],
        "original_source85_native_store_target":TARGET,
        "original_source85_value_stored":"0x0",
        "fifth_writer_negative_controls_rejected":firstfive_denied,
        "twenty_source85_false_native_writer_claims_rejected":controls,
        "genuine_original_native_gdb_log_sha256":hashlib.sha256(log.encode()).hexdigest(),
        "original_source85_resolver_entry_and_RET_execution_proven":False,
        "stage_C_40_native_GNU_writers_proven":False,
        "all_147_one_process_loader_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/OUT).write_text(json.dumps(report,indent=2)+"\n")
    print("KERNIX_G0_C_FIRST_SIX_GNU_NATIVE_STORES_SAME_ONE_FEX_PID_IFUNC85_ZERO_STORE_PROVEN",
          pid,"20_NEW_FORGERIES_REJECTED_RESOLVER_ENTRY_RET_STILL_OPEN")
    return report

if __name__=="__main__":
    need(len(sys.argv)==6,"usage original_GNU_triad original147_repo_ledger repo_root raw_native_dir output")
    run(*map(Path,sys.argv[1:]))
