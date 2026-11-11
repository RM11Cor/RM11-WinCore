#!/usr/bin/env python3
"""Independent strict original GNU 81+82 same-inferior native ARM64 FEX writer gate.

The original 147 individually proved source targets do not substitute for
two actual simultaneous original FEX hardware write traps in ONE host pid.
The raw runner cannot independently attest itself. 16 forged native trace
tests must fail closed. This is NOT full 147 closure or Android execution.
"""
from __future__ import annotations
import hashlib,json,re,sys
from pathlib import Path
from kernix_g0_l1_original_two_rela81_82_one_fex_process_plan import (
    OUT as SOURCE_OUT,GDB as SOURCE_GDB,plan as rebuild_plan,SCHEMA as SOURCE_SCHEMA,
)
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA

SCHEMA="kernix.g0.l1.original-gnu-source81-82-one-same-real-linux-arm64-fex-pid-independent-proof.v1"
OUT="KERNIX-G0-L1-Real-Original-GNU-RELA81-82-One-FEX-PID-Independent-Hardware-Writer-Only.json"
RAW="two-original-GNU-writers-one-FEX-process-RAW-ONLY.json"
LOG="real-arm64-fex-two-targets-one-process.gdb.log"
PATTERN=r"^KERNIX_G0_L1_([A-Z_]+) (\{[^\r\n]*\})$"
REQUIRED={
    "BEFORE":2,
    "TWO_HARDWARE_WRITERS_ARMED_ONE_PID":1,
    "LIVE_HARDWARE_WRITER":2,
    "TWO_REAL_ORIGINAL_RELOCATION_WRITERS_SAME_ARM64_FEX_PID":1,
}
def need(ok,msg):
    if not ok:raise AssertionError("KERNIX_G0_L1_SAME_PROCESS_INDEPENDENT_FAIL_CLOSED: "+msg)
def get(p:Path,size=2000000):
    need(p.is_file() and not p.is_symlink(),"regular original SHA evidence file "+str(p))
    b=p.read_bytes()
    need(0<len(b)<=size,"bounded original independent source "+str(p))
    return b
def markers(trace:str):
    out={}
    for match in re.finditer(PATTERN,trace,re.M):
        label=match[1]
        need(label in REQUIRED,"no unexpected, spoofed or rejected actual GDB live event")
        out.setdefault(label,[]).append((match.start(),json.loads(match[2])))
    need(set(out)==set(REQUIRED),"all four correct actual live witness event classes")
    for key,count in REQUIRED.items():
        need(len(out[key])==count,"real GDB event count "+key)
    return out
def original_events(trace:str,plan:dict):
    m=markers(trace)
    before=m["BEFORE"]
    armed=m["TWO_HARDWARE_WRITERS_ARMED_ONE_PID"][0]
    hits=m["LIVE_HARDWARE_WRITER"]
    final=m["TWO_REAL_ORIGINAL_RELOCATION_WRITERS_SAME_ARM64_FEX_PID"][0]
    need(before[0][0]<before[1][0]<armed[0]<hits[0][0]<hits[1][0]<final[0],
         "one actual GDB inferior source-arm -> two hardware traps -> final verifier chronology")
    pid=armed[1]["pid"]
    need(type(pid)==int and pid>0,"true original Linux ARM64 FEX inferior OS process id")
    source=plan["source_tuples"]
    for i,(at,v) in enumerate(before):
        need(v=={"index":source[i]["index"],"pid":pid,
                "target":source[i]["target"],"value":"0x0"},
             "original SHA source qword zero in real same pid before any store")
    need(armed[1]=={"pid":pid,"indices":[81,82]},
         "two simultaneous true GDB hardware write watchpoints at one inferior")
    actual=[]
    for i,(_,v) in enumerate(hits):
        row=source[i]
        target=row["target"]
        expected=row["candidate"]
        need(v["index"]==row["index"] and v["pid"]==pid
             and v["target"]==target
             and v["x4"]==target and v["x13"]==v["value"]
             and int(v["pc"],16)>=0xffff00000000
             and int(v["x28"],16)>=0xffff00000000
             and int(v["value"],16)>0
             and (expected is None or v["value"]==expected)
             and v["source_x86_3bytes"]=="4c8908"
             and v["FEX_guest_entry"]=="0x80100fb8b"
             and v["FEX_guest_size"]==3
             and v["FEX_native_ops"]==2
             and re.search(r"\bstlr\s+x13,\s*\[x4\]",v["instruction"]) is not None,
             "source "+str(row["index"])+" exact original ELF target, live register, authentic x86 JIT and native ARM64 store")
        need(re.search(r"0x[0-9a-f]+:\s+stlr\s+x13,\s*\[x4\]",v["instruction"]) is not None,
             "actual ARM64 native instruction disassembly, not merely a synthetic claim")
        actual.append(v)
    need(final[1]=={
        "pid":pid,"indices":[81,82],
        "targets":[v["target"] for v in hits_to_values(hits)],
        "values":[v["value"] for v in hits_to_values(hits)],
        "all_147_same_guest_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    },"GDB final same-pid self-check marker matches both authentic FEX hardware traps")
    return {"same_original_native_fex_inferior_pid":pid,
            "two_original_GNU_rela_indices":[81,82],
            "actual_source_native_stores":actual}
def hits_to_values(hits):
    return [v for _,v in hits]
def mutate_event(trace,label,which,field,val):
    entry="KERNIX_G0_L1_"+label+" "
    src=[m for m in re.finditer(r"^"+re.escape(entry)+r"(\{[^\r\n]*\})$",trace,re.M)]
    need(len(src)==REQUIRED[label] and which<len(src),"tamper exact selected original native event")
    hit=src[which]
    data=json.loads(hit[1])
    need(field in data and data[field]!=val,"independent mutation actually alters original witness")
    data[field]=val
    return trace[:hit.start()]+entry+json.dumps(data,sort_keys=True)+trace[hit.end():]
def negatives(trace,plan):
    e=markers(trace)
    pid=e["TWO_HARDWARE_WRITERS_ARMED_ONE_PID"][0][1]["pid"]
    changes=[
        ("mutate_before_81_pid","BEFORE",0,"pid",pid+1),
        ("mutate_before_82_pid","BEFORE",1,"pid",pid+1),
        ("mutate_initial_qword","BEFORE",1,"value","0x1"),
        ("mutate_source_index","BEFORE",0,"index",99),
        ("mutate_watches_inferior_pid","TWO_HARDWARE_WRITERS_ARMED_ONE_PID",0,"pid",pid+1),
        ("mutate_armed_index_list","TWO_HARDWARE_WRITERS_ARMED_ONE_PID",0,"indices",[81,83]),
        ("mutate_first_write_pid","LIVE_HARDWARE_WRITER",0,"pid",pid+1),
        ("mutate_second_write_pid","LIVE_HARDWARE_WRITER",1,"pid",pid+1),
        ("mutate_first_native_target","LIVE_HARDWARE_WRITER",0,"target","0x1"),
        ("mutate_second_native_value","LIVE_HARDWARE_WRITER",1,"value","0x0"),
        ("mutate_native_x4_target","LIVE_HARDWARE_WRITER",0,"x4","0x1"),
        ("mutate_native_x13_value","LIVE_HARDWARE_WRITER",1,"x13","0x1"),
        ("mutate_real_ARM64_opcode","LIVE_HARDWARE_WRITER",0,"instruction","0xffff00000104:\tldar x13, [x4]"),
        ("mutate_original_x86_guest_source","LIVE_HARDWARE_WRITER",1,"source_x86_3bytes","909090"),
        ("mutate_actual_FEX_guest_JIT","LIVE_HARDWARE_WRITER",0,"FEX_guest_entry","0x1"),
        ("mutate_final_proof_pid","TWO_REAL_ORIGINAL_RELOCATION_WRITERS_SAME_ARM64_FEX_PID",0,"pid",pid+1),
    ]
    need(len(changes)==16 and len({c[0] for c in changes})==16,"exact sixteen unique adversarial falsifications")
    denied=[]
    for name,label,which,field,value in changes:
        bad=mutate_event(trace,label,which,field,value)
        try:original_events(bad,plan)
        except (AssertionError,ValueError,KeyError,TypeError):
            denied.append(name)
        else:raise AssertionError("FORGED_SAME_PID_FEX_NATIVE_GNU_HARDWARE_WRITER_EVIDENCE_ACCEPTED: "+name)
    need(len(denied)==16,"all forged source process / register / JIT events must fail closed")
    return denied
def run(triad:Path,prior141:Path,source:Path,prior147:Path,raw:Path,repo:Path,dist:Path):
    rebuilt=dist/"source_rebuilt"
    plan=rebuild_plan(triad,prior141,source,prior147,repo,rebuilt)
    need(plan["schema"]==SOURCE_SCHEMA,"real original GNU signed SHA single-process source")
    for file in (SOURCE_OUT,SOURCE_GDB):
        need(get(source/file,600000)==get(rebuilt/file,600000),
             "source artifact equals independently re-generated SHA original GNU plan "+file)
    rawdoc=json.loads(get(raw/RAW))
    trace=get(raw/LOG,600000).decode(errors="replace")
    exitcode=int(get(raw/"gdb.exit",50).decode().strip())
    need(rawdoc["schema"]=="kernix.g0.l1.original-gnu-two-hardware-relocations-one-real-arm64-fex-process-raw.v1"
         and rawdoc["original_source_indices"]==[81,82]
         and rawdoc["native_raw_log_sha256"]==hashlib.sha256(trace.encode()).hexdigest()
         and rawdoc["native_gdb_exit_code"]==0 and exitcode==0
         and rawdoc["same_inferior_linux_arm64_fex_pid_for_two_native_hardware_stores_raw"] is True
         and rawdoc["independently_attested_same_guest_native_writers"] is False
         and rawdoc["all_147_same_guest_native_execution_proven"] is False
         and rawdoc["full_original_libc_147_process_relocation_closure_proven"] is False
         and rawdoc["Android_Bionic_Wine_Proton_games_proven"] is False,
         "real pinned raw FEX source process log hash, script and no premature certification")
    verified=original_events(trace,plan)
    need(rawdoc["one_guest_pid_observed"]==verified["same_original_native_fex_inferior_pid"]
         and rawdoc["original_guest_live_hardware_events"]==verified["actual_source_native_stores"],
         "raw report must faithfully reflect exact independent live GDB native original GNU events")
    rejected=negatives(trace,plan)
    output={
        "schema":SCHEMA,
        "original_source_libc_sha256":LIBC_SHA,
        "original_source_ldso_sha256":LDSO_SHA,
        "original_relocation_indices":[81,82],
        "one_native_linux_arm64_fex_original_guest_process_real_hardware_writes_independently_proven":True,
        "real_linux_arm64_host_inferior_pid":verified["same_original_native_fex_inferior_pid"],
        "both_source_targets_real_arm64_store_per_same_inferior_process":verified["actual_source_native_stores"],
        "original_live_hardware_gdb_trace_sha256":hashlib.sha256(trace.encode()).hexdigest(),
        "sixteen_forged_same_process_hardware_traces_rejected":rejected,
        "number_of_original_relocation_targets_live_same_process_proven":2,
        "all_147_same_guest_native_execution_proven":False,
        "full_original_libc_147_process_relocation_closure_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    dist.mkdir(parents=True,exist_ok=True)
    (dist/OUT).write_text(json.dumps(output,indent=2)+"\n")
    print("KERNIX_G0_L1_TWO_ORIGINAL_GNU_WRITERS_IN_ONE_NATIVE_FEX_ARM64_PROCESS_INDEPENDENTLY_ATTESTED",verified["same_original_native_fex_inferior_pid"],"FORGED_TRACES_REJECTED=16 NOT_ALL_147")
    return output
if __name__=="__main__":
    need(len(sys.argv)==8,"usage triad prior141 original81 source prior147 archived-live-raw repo output")
    run(*map(Path,sys.argv[1:]))
