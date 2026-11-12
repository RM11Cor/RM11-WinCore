#!/usr/bin/env python3
"""Independent authentic IFUNC85 C3 RET JIT guest header and same-PID writer.

This does NOT attest a hardware read of the guest stack. It only proves
a genuine source-authenticated native FEX JIT dispatch header at C3 RIP,
with actual return qword, subsequent caller JIT, and native target writer.
"""
from __future__ import annotations
import hashlib,json,re,sys
from pathlib import Path
from kernix_g0_l40_c_ifunc85_c3_ret_jit_header_no_stack_watch_plan import (
    plan as source_plan, SCHEMA as SOURCE_SCHEMA, GDB as GDB_SOURCE,
    OUT as SOURCE_OUT, RET, RETVAL,
)
from kernix_g0_l40_c_ifunc85_resolver_entry_caller_independent_gate import (
    verify as prior_verify, negatives as prior_negative,
)
from kernix_g0_l40_c_ifunc85_resolver_entry_caller_after_five_source_plan import OUT as PRIOR_OUT
from kernix_g0_l40_c_irelative85_after_five_same_fex_awatch_plan import OUT as SIX_OUT

SCHEMA="kernix.g0.l40c.original-ifunc85-c3-ret-guest-jit-header-one-pid-no-stack-hardware-read-independent.v1"
OUT="KERNIX-G0-C-IFUNC85-Original-C3-RET-JIT-Header-Real-Native-FEX-No-Stack-HW-Read.json"
LOG="original-gnu-ifunc85-c3-ret-jit-header-without-stack-watch.gdb.log"
HEADER="IFUNC85_C3_RET_JIT_GUEST_HEADER_OBSERVED_NO_HW_STACK_READ"
FINAL="IFUNC85_C3_RET_JIT_HEADER_WITH_CALLER_AND_NATIVE_ZERO_STORE_ONLY"
ARM="IFUNC85_FEX_GUEST_JIT_STATE_WATCH_ARMED"
ENTRY="IFUNC85_RESOLVER_JIT_ENTRY_HW"
CALLER="IFUNC85_CALLER_JIT_RETURN_SITE_HW"
WRITE="IFUNC85_TRUE_NATIVE_ZERO_TO_ZERO_STORE"
PAT=re.compile(r"^KERNIX_G0_L40_C_([A-Z0-9_]+) (\{[^\r\n]*\})$",re.M)
PREFIX="KERNIX_G0_L40_C_"

def need(test,why):
    if not test:raise AssertionError("KERNIX_G0_C_IFUNC85_C3_RET_JIT_HEADER_INDEPENDENT_FAIL_CLOSED: "+why)
def read(p,limit=3_000_000):
    need(p.is_file() and not p.is_symlink(),"real source or native log regular file "+str(p))
    raw=p.read_bytes()
    need(0<len(raw)<=limit,"bounded original source/native log "+str(p))
    return raw

def events(log):
    records={}
    for m in PAT.finditer(log):
        records.setdefault(m[1],[]).append((m.start(),json.loads(m[2])))
    for name in (HEADER,FINAL,ARM,ENTRY,CALLER,WRITE):
        need(len(records.get(name,[]))==1,"genuine unique FEX original C3 JIT event "+name)
    for name in ("IFUNC85_JIT_SCAN_BOUNDED_REJECT","IFUNC85_JIT_REJECT_EXCEPTION"):
        need(name not in records,"no actual JIT debug failure "+name)
    return records

def verify(log,source):
    need(source["schema"]==SOURCE_SCHEMA
         and source["original_source85_C3_RET_guest_RIP"]==hex(RET)
         and source["original_source85_C3_RET_byte"]=="c3"
         and source["original_gnu_caller_return_guest_address"]==hex(RETVAL)
         and source["guest_stack_hardware_watch_armed_in_this_test"] is False,
         "exact original GNU IFUNC85 guest source C3 and no stack hardware watch")
    pid,entry,caller=prior_verify(log,source["prior_source"])
    ev=events(log)
    hpos,h=ev[HEADER][0]
    fpos,final=ev[FINAL][0]
    need(ev[ARM][0][0]<ev[ENTRY][0][0]<hpos<ev[CALLER][0][0]<ev[WRITE][0][0]<fpos,
         "genuine one PID source resolver, C3 header, caller, zero write order")
    need(set(h)=={"pid","scan","native_pc","guest_entry","guest_size",
                  "native_ops","guest_rsp","guest_return_qword","guest_rax","source_C3_byte"},
         "exact original GNU native C3 FEX guest header event fields")
    need(type(h["pid"]) is int and h["pid"]==pid
         and type(h["scan"]) is int and entry["scan"]<h["scan"]<caller["scan"]
         and h["guest_entry"]==hex(RET)
         and h["guest_size"]==1
         and type(h["native_ops"]) is int and 1<=h["native_ops"]<=128
         and h["guest_rsp"]==entry["guest_rsp"]
         and h["guest_return_qword"]==hex(RETVAL)
         and h["source_C3_byte"]=="c3"
         and int(h["native_pc"],16)>=0xffff00000000,
         "source x86 C3 guest RIP reached real native FEX JIT header with original stack qword")
    need(final=={
        "pid":pid,"original_guest_C3_RET_source_JIT_header_seen":True,
        "exact_guest_C3_RET_stack_hardware_read_proven":False,
        "stage_C_40_original_GNU_relocations_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    },"no false native stack READ or full loader claim")
    return pid,h

def fake(log,kind,field,value):
    ms=[m for m in PAT.finditer(log) if m[1]==kind]
    need(len(ms)==1,"one original native source C3 header for forged control")
    m=ms[0]
    v=json.loads(m[2])
    need(field in v and v[field]!=value,"actual mutation changes evidence")
    v[field]=value
    return log[:m.start()]+PREFIX+kind+" "+json.dumps(v,sort_keys=True)+log[m.end():]

def negatives(log,source):
    cases=[
        ("false_pid",HEADER,"pid",999999),
        ("false_scan",HEADER,"scan",999999),
        ("false_guest_ret",HEADER,"guest_entry","0x1"),
        ("false_guest_size",HEADER,"guest_size",2),
        ("false_guest_byte",HEADER,"source_C3_byte","90"),
        ("false_rsp",HEADER,"guest_rsp","0x1"),
        ("false_ret_qword",HEADER,"guest_return_qword","0x1"),
        ("false_native_pc",HEADER,"native_pc","0x1"),
        ("false_native_ops",HEADER,"native_ops",0),
        ("false_final_pid",FINAL,"pid",999999),
        ("false_final_header",FINAL,"original_guest_C3_RET_source_JIT_header_seen",False),
        ("false_final_hw_read",FINAL,"exact_guest_C3_RET_stack_hardware_read_proven",True),
    ]
    need(len(cases)==12,"twelve original source C3 JIT forged tests")
    denied=[]
    for name,kind,field,val in cases:
        try:verify(fake(log,kind,field,val),source)
        except (AssertionError,KeyError,TypeError,ValueError):denied.append(name)
        else:raise AssertionError("FORGED_ORIGINAL_IFUNC85_C3_RET_GUEST_JIT_HEADER_ACCEPTED "+name)
    need(len(denied)==12 and len(set(denied))==12,
         "twelve false original GNU C3 JIT header claims all rejected")
    return denied

def run(triad:Path,ledger:Path,repo:Path,native:Path,out:Path):
    src=source_plan(triad,ledger,repo,out/"regenerated")
    script=read(out/"regenerated"/GDB_SOURCE,180000)
    need(hashlib.sha256(script).hexdigest()==src["native_GDB_script_sha256"],
         "regenerated source FEX native header code exact SHA")
    log=read(native/LOG,250000).decode(errors="replace")
    rc=int(read(native/"gdb.exit",60).decode().strip())
    need(rc==0,"actual original FEX C3 JIT header test must complete")
    prev_folder=out/"regenerated"/"original"
    prev=json.loads(read(prev_folder/PRIOR_OUT))
    six_folder=prev_folder/"six-source"
    six=json.loads(read(six_folder/SIX_OUT))
    six["first_five_source_plan"]=json.loads(read(six_folder/"five-source"/
        "KERNIX-G0-C-Original-GLOB_DAT80-84-Five-Rolling-One-FEX-PID-SOURCE-ONLY.json"))
    prev["six_gate_source"]=six
    src["prior_source"]=prev
    pid,h=verify(log,src)
    denied=negatives(log,src)
    previous=prior_negative(log,prev)
    need(len(denied)==12 and len(previous)==18,
         "twelve source C3 JIT header and 18 old IFUNC resolver independent forgeries")
    result={
        "schema":SCHEMA,
        "real_linux_ARM64_FEX_one_PID":pid,
        "source_original_indices_native_writers_one_FEX_PID":[80,81,82,83,84,85],
        "original_GNU_IFUNC85_C3_guest_JIT_header_reached":True,
        "original_GNU_IFUNC85_C3_guest_source_byte":"c3",
        "original_GNU_IFUNC85_C3_guest_RIP":hex(RET),
        "original_GNU_guest_stack_return_qword_seen":h["guest_return_qword"],
        "source_original_IFUNC85_GNU_caller_and_native_zero_store_one_pid":True,
        "twelve_forged_C3_JIT_guest_header_events_rejected":denied,
        "prior_eighteen_resolver_JIT_forged_logs_rejected":previous,
        "raw_native_gdb_log_sha256":hashlib.sha256(log.encode()).hexdigest(),
        "actual_original_C3_RET_stack_hardware_read_proven":False,
        "full_original_dynamic_relocation_closure_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/OUT).write_text(json.dumps(result,indent=2)+"\n")
    print("KERNIX_G0_C_ORIGINAL_IFUNC85_C3_RET_REAL_FEX_JIT_GUEST_HEADER_NO_STACK_HW_READ_ONE_PID_PASS",pid)
    return result

if __name__=="__main__":
    need(len(sys.argv)==6,"usage original_SHA_GNU_triad canonical147 repo native_GDB_dir output")
    run(*map(Path,sys.argv[1:]))
