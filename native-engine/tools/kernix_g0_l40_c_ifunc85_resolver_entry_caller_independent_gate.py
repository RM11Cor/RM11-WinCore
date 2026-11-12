#!/usr/bin/env python3
"""Independent original GNU IFUNC85 resolver-JIT -> caller-JIT -> zero-store gate.

Same real FEX ARM64 process must have source-authenticated first five
GLOB_DAT stores, native IFUNC85 zero-STLR, and hardware-mapped resolver
entry + caller return site. Caller site is NOT proof of exact guest C3
RET opcode or actual return-address STACK READ: keep that gate OPEN.
"""
from __future__ import annotations
import hashlib,json,re,sys
from pathlib import Path
from kernix_g0_l40_c_ifunc85_resolver_entry_caller_after_five_source_plan import (
    plan as original_plan, SCHEMA as PLAN_SCHEMA, GDB as GDB_SOURCE,
    OUT as PLAN_OUTPUT, RET,
)
from kernix_g0_l40_c_irelative85_after_five_same_fex_independent_gate import (
    verify as six_verify, negative_controls as six_negative,
)
from kernix_g0_l40_c_irelative85_after_five_same_fex_awatch_plan import OUT as SIX_OUTPUT

SCHEMA="kernix.g0.l40c.original-gnu-ifunc85-resolver-caller-source-JIT-same-fex-pid-independent.v1"
OUT="KERNIX-G0-C-IFUNC85-Resolver-Caller-JIT-Real-FEX-One-PID-RET-READ-OPEN.json"
LOG="original-gnu-ifunc85-resolver-caller-JIT-after-five-one-FEX-pid.gdb.log"
PREFIX="KERNIX_G0_L40_C_"
ARM="IFUNC85_FEX_GUEST_JIT_STATE_WATCH_ARMED"
ENTRY="IFUNC85_RESOLVER_JIT_ENTRY_HW"
CALLER="IFUNC85_CALLER_JIT_RETURN_SITE_HW"
FINAL="IFUNC85_SAME_PID_RESOLVER_JIT_CALLER_AND_ZERO_WRITER_TRACE"
AWATCH="IFUNC85_AWATCH_ARMED_AFTER_FIVE_IN_SAME_PID"
WRITE="IFUNC85_TRUE_NATIVE_ZERO_TO_ZERO_STORE"
PAT=re.compile(r"^KERNIX_G0_L40_C_([A-Z0-9_]+) (\{[^\r\n]*\})$",re.M)

def need(ok,msg):
    if not ok:raise AssertionError("KERNIX_G0_C_IFUNC85_SOURCE_RESOLVER_JIT_INDEPENDENT_FAIL_CLOSED: "+msg)
def read(p:Path,limit=3_000_000):
    need(p.is_file() and not p.is_symlink(),"real source/native evidence "+str(p))
    raw=p.read_bytes()
    need(0<len(raw)<=limit,"bounded original evidence "+str(p))
    return raw
def events(log):
    e={}
    for m in PAT.finditer(log):
        e.setdefault(m[1],[]).append((m.start(),json.loads(m[2])))
    for k in (ARM,ENTRY,CALLER,FINAL,AWATCH,WRITE):
        need(len(e.get(k,[]))==1,"exact one original GNU/FEX hardware event "+k)
    for k in ("IFUNC85_JIT_SCAN_BOUNDED_REJECT","IFUNC85_JIT_REJECT_EXCEPTION"):
        need(k not in e,"real original GNU native FEX/JIT watch failed closed "+k)
    return e
def without_arm_header_marker(log):
    lines=[x for x in log.splitlines(keepends=True) if
           not x.startswith(PREFIX+ARM+" ")]
    need(len(lines)==len(log.splitlines(keepends=True))-1,
         "exact one JIT watch arming event for previous original six native writer audit")
    return "".join(lines)

def verify(log,source):
    need(source["schema"]==PLAN_SCHEMA
         and source["previous_five_indices"]==[80,81,82,83,84]
         and source["ifunc_original_source_index"]==85
         and source["source_guest_resolver"]=="0x8040c8570"
         and source["source_guest_caller_return_RIP"]=="0x80100fd5c"
         and source["source_guest_IFUNC_writer"]=="0x80100fd60"
         and source["source_guest_target"]=="0x8042014c8"
         and source["original_source_resolver_RET_guest_RIP"]==hex(RET),
         "exact SHA original GNU source IFUNC85 call/entry/caller/ret candidate")
    e=events(log)
    arm_pos,arm=e[ARM][0]
    entry_pos,entry=e[ENTRY][0]
    caller_pos,caller=e[CALLER][0]
    write_pos,writer=e[WRITE][0]
    final_pos,final=e[FINAL][0]
    need(arm_pos<e[AWATCH][0][0]<entry_pos<caller_pos<write_pos<final_pos,
         "one actual FEX PID original five, resolver, GNU caller and zero store chronology")
    clean=without_arm_header_marker(log)
    pid,native,_=six_verify(clean,source["six_gate_source"])
    need(type(pid) is int and pid>0
         and arm=={"pid":pid,
                   "source_resolver":"0x8040c8570",
                   "original_caller_site":"0x80100fd5c",
                   "source_guest_RET":"0x8040c860d",
                   "native_RET_stack_read_proven_yet":False},
         "same FEX host PID and source-authenticated original GNU JIT state watch")
    need(set(entry)=={"pid","scan","native_pc","guest_entry",
                       "guest_size","native_ops","guest_rsp",
                       "guest_stack_return","guest_rax","guest_r14"},
         "exact actual resolver hardware/JIT header data fields")
    need(type(entry["pid"]) is int and entry["pid"]==pid
         and entry["guest_entry"]=="0x8040c8570"
         and entry["guest_stack_return"]=="0x80100fd5c"
         and type(entry["scan"]) is int and 1<=entry["scan"]<=16384
         and type(entry["guest_size"]) is int and 1<=entry["guest_size"]<=4096
         and type(entry["native_ops"]) is int and 1<=entry["native_ops"]<=4096
         and int(entry["native_pc"],16)>=0xffff00000000,
         "genuine GNU IFUNC85 resolver guest entry and CALL return slot live in host FEX")
    need(set(caller)=={"pid","scan","native_pc","guest_entry",
                       "guest_size","native_ops","guest_rsp","guest_rax","guest_r14"},
         "exact original GNU caller JIT hardware header witness")
    need(type(caller["pid"]) is int and caller["pid"]==pid
         and caller["guest_entry"]=="0x80100fd5c"
         and type(caller["scan"]) is int
         and entry["scan"]<caller["scan"]<=16384
         and type(caller["guest_size"]) is int and 1<=caller["guest_size"]<=4096
         and type(caller["native_ops"]) is int and 1<=caller["native_ops"]<=4096
         and int(caller["guest_rsp"],16)==int(entry["guest_rsp"],16)+8
         and caller["guest_rax"]=="0x0"
         and caller["guest_r14"]=="0x8042014c8"
         and int(caller["native_pc"],16)>=0xffff00000000,
         "actual GNU caller return-site FEX JIT after source resolver with restored x86 RSP")
    need(writer["pid"]==pid and writer["value"]=="0x0"
         and writer["x19"]=="0x8042014c8" and writer["x4"]=="0x0",
         "subsequent source-authenticated zero-to-zero native writer same process")
    need(final=={
        "pid":pid,
        "source85_resolver_JIT_entry_seen":True,
        "source85_caller_JIT_return_site_seen":True,
        "source85_real_zero_store_seen":True,
        "exact_original_C3_RET_opcode_native_stack_read_proven":False,
        "stage_C_all_40_GNU_relocations_proven":False,
        "all_147_one_guest_loader_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    },"specific C3 return hardware-read and 40 source closure remain OPEN")
    return pid,entry,caller

def mutate(log,kind,index,field,bad):
    matches=[m for m in PAT.finditer(log) if m[1]==kind]
    need(index<len(matches),"original source marker present")
    match=matches[index]
    d=json.loads(match[2])
    need(field in d and d[field]!=bad,"actual hardware change in forged case")
    d[field]=bad
    return log[:match.start()]+PREFIX+kind+" "+json.dumps(d,sort_keys=True)+log[match.end():]

def negatives(log,source):
    cases=[
        ("arm_pid",ARM,0,"pid",999999),
        ("arm_resolver",ARM,0,"source_resolver","0x1"),
        ("entry_pid",ENTRY,0,"pid",999999),
        ("entry_rip",ENTRY,0,"guest_entry","0x1"),
        ("entry_stack_return",ENTRY,0,"guest_stack_return","0x1"),
        ("entry_pc",ENTRY,0,"native_pc","0x2"),
        ("entry_block_size",ENTRY,0,"guest_size",0),
        ("entry_scan",ENTRY,0,"scan",99999),
        ("caller_pid",CALLER,0,"pid",999999),
        ("caller_rip",CALLER,0,"guest_entry","0x1"),
        ("caller_rsp",CALLER,0,"guest_rsp","0x1"),
        ("caller_rax",CALLER,0,"guest_rax","0x1"),
        ("caller_r14",CALLER,0,"guest_r14","0x1"),
        ("caller_pc",CALLER,0,"native_pc","0x1"),
        ("final_resolver",FINAL,0,"source85_resolver_JIT_entry_seen",False),
        ("final_caller",FINAL,0,"source85_caller_JIT_return_site_seen",False),
        ("final_zero",FINAL,0,"source85_real_zero_store_seen",False),
        ("final_fake_ret",FINAL,0,"exact_original_C3_RET_opcode_native_stack_read_proven",True),
    ]
    need(len(cases)==18,"18 source and runtime fabricated resolver/JIT checks")
    denied=[]
    for name,kind,index,field,bad in cases:
        try:verify(mutate(log,kind,index,field,bad),source)
        except (AssertionError,ValueError,KeyError,TypeError):denied.append(name)
        else:raise AssertionError("FORGED_GNU_IFUNC85_RESOLVER_JIT_ACCEPTED "+name)
    need(len(denied)==18 and len(set(denied))==18,"all false source resolver/caller runtime JIT traces rejected")
    return denied

def run(triad:Path,ledger:Path,repo:Path,rawdir:Path,out:Path):
    source=original_plan(triad,ledger,repo,out/"regenerated")
    script=read(out/"regenerated"/GDB_SOURCE,160000)
    need(hashlib.sha256(script).hexdigest()==source["native_GDB_script_sha256"],
         "exact original SHA source one FEX PID native hardware JIT script")
    log=read(rawdir/LOG,300000).decode(errors="replace")
    rc=int(read(rawdir/"gdb.exit",60).decode().strip())
    need(rc==0,"real FEX source resolver and 0 writer GDB process exit zero")
    six_dir=out/"regenerated"/"six-source"
    six_source=json.loads(read(six_dir/SIX_OUTPUT))
    six_source["first_five_source_plan"]=json.loads(
        read(six_dir/"five-source"/
             "KERNIX-G0-C-Original-GLOB_DAT80-84-Five-Rolling-One-FEX-PID-SOURCE-ONLY.json"))
    source["six_gate_source"]=six_source
    pid,entry,caller=verify(log,source)
    rejected=negatives(log,source)
    six_denied=six_negative(without_arm_header_marker(log),six_source)
    need(len(rejected)==18 and len(six_denied)==20,
         "18 real guest JIT + 20 zero-store independent falsifications rejected")
    report={
        "schema":SCHEMA,
        "native_same_real_FEX_inferior_pid":pid,
        "original_source_indices_native_writer_observed_in_same_pid":[80,81,82,83,84,85],
        "original_source_IFUNC85_resolver_jit_entry_seen":True,
        "original_source_IFUNC85_actual_gnu_caller_jit_return_site_seen":True,
        "original_source_IFUNC85_caller_zero_rax":caller["guest_rax"],
        "original_source_IFUNC85_guest_stack_restored_plus_eight":True,
        "original_source_IFUNC85_zero_to_zero_hardware_write_confirmed":True,
        "eighteen_forged_resolver_jit_logs_denied":rejected,
        "twenty_forged_zero_hardware_store_logs_denied":six_denied,
        "real_native_gdb_log_sha256":hashlib.sha256(log.encode()).hexdigest(),
        "specific_guest_C3_RET_native_hardware_stack_read_proven":False,
        "full_original_IFUNC85_resolver_entire_body_proven":False,
        "stage_C_40_original_relocations_one_pid_proven":False,
        "full_GNU_loader_closure_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/OUT).write_text(json.dumps(report,indent=2)+"\n")
    print("KERNIX_G0_C_REAL_IFUNC85_RESOLVER_JIT_CALLER_SITE_ZERO_WRITE_ONE_FEX_PID_INDEPENDENT_PROOF_NO_EXPLICIT_C3_RET",pid)
    return report

if __name__=="__main__":
    need(len(sys.argv)==6,"usage original_GNU_triad canonical147 repo raw_gdb_dir report_out")
    run(*map(Path,sys.argv[1:]))
