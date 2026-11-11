#!/usr/bin/env python3
"""Independent G0-L3 original GNU source77..84 real Linux ARM64 FEX one-PID gate.

This gate never infers an eight-source live relocation proof from eight separate
raw trials. It requires a new single-inferior FEX GDB log containing eight
genuine original ELF source-native hardware stores in TWO sequential windows
of FOUR actual hardware watchpoints. It rejects 32 deliberately forged
phase, pid, source, ARM64 CPU, guest JIT and native write evidence variants.
Neither 147-in-one-process, Android, nor game launch is proved.
"""
from __future__ import annotations
import hashlib,json,re,sys
from pathlib import Path
from kernix_g0_l3_original_eight_rela77_84_one_fex_windowed_process_plan import (
    SCHEMA as SOURCE_SCHEMA,OUT as SOURCE_OUT,GDB as SOURCE_GDB,
    plan as rebuild_plan,
)
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA
SCHEMA="kernix.g0.l3.original-gnu-eight-real-native-writers-77-84-one-fex-pid-independent-two-four-watchpoint-windows.v1"
OUT="KERNIX-G0-L3-Original-GNU-RELA77-84-Eight-One-FEX-PID-Independent-32-Forgery-Hardware-Writers.json"
RAW="eight-original-GNU-writers-two-window-one-FEX-RAW-ONLY.json"
LOG="real-eight-writer-windowed-one-FEX-process.gdb.log"
NAMES=("BEFORE","FIRST_FOUR_HARDWARE_WRITERS_ARMED_ONE_PID",
       "LIVE_HARDWARE_WRITER","SECOND_FOUR_HARDWARE_WRITERS_ARMED_SAME_PID",
       "EIGHT_REAL_ORIGINAL_RELOCATION_WRITERS_SAME_ARM64_FEX_PID")
COUNTS=(8,1,8,1,1)
RELA=list(range(77,85))
MARK=r"^KERNIX_G0_L3_([A-Z0-9_]+) (\{[^\r\n]*\})$"

def need(ok,msg):
    if not ok:raise AssertionError("KERNIX_G0_L3_INDEPENDENT_EIGHT_SOURCE_FAIL_CLOSED: "+msg)
def read(p,limit=2500000):
    need(p.is_file() and not p.is_symlink(),"true regular SHA input "+str(p))
    data=p.read_bytes()
    need(0<len(data)<=limit,"bounded original input "+str(p))
    return data
def events(text:str):
    out={}
    for match in re.finditer(MARK,text,re.M):
        k=match[1]
        need(k in NAMES,"no unknown same-process FEX event accepted "+str(k))
        out.setdefault(k,[]).append((match.start(),json.loads(match[2])))
    need(set(out)==set(NAMES),"require all 5 genuinely recorded native FEX event categories")
    for k,n in zip(NAMES,COUNTS):
        need(len(out[k])==n,"exact original native FEX source writer event count "+k)
    return out
def attest(text:str,plan:dict)->dict:
    e=events(text)
    before=e["BEFORE"]
    first=e["FIRST_FOUR_HARDWARE_WRITERS_ARMED_ONE_PID"][0]
    hits=e["LIVE_HARDWARE_WRITER"]
    second=e["SECOND_FOUR_HARDWARE_WRITERS_ARMED_SAME_PID"][0]
    final=e["EIGHT_REAL_ORIGINAL_RELOCATION_WRITERS_SAME_ARM64_FEX_PID"][0]
    need(all(before[i][0]<before[i+1][0] for i in range(7))
         and before[-1][0]<first[0]<hits[0][0]
         and all(hits[i][0]<hits[i+1][0] for i in range(3))
         and hits[3][0]<second[0]<hits[4][0]
         and all(hits[i][0]<hits[i+1][0] for i in range(4,7))
         and hits[7][0]<final[0],
         "one GNU interpreter source order, first 4 writes, SAME PID re-arm, last 4 stores, end marker")
    rows=plan["source_tuples"]
    need(len(rows)==8 and [r["index"] for r in rows]==RELA,
         "original GNU SHA source tuples fully preserve relocation order")
    pid=first[1]["pid"]
    need(type(pid)==int and pid>0,"true Linux AArch64 inferior OS pid, not synthetic")
    need(first[1]=={"pid":pid,"indices":[77,78,79,80]},
         "initial four genuine native hardware GDB watcher registrations in single FEX inferior")
    need(second[1]=={"pid":pid,
                     "indices":[81,82,83,84],
                     "already_observed":[77,78,79,80]},
         "GDB re-armed next four hardware watchpoints while same FEX guest process STOPPED")
    for i,(_,row) in enumerate(before):
        r=rows[i]
        need(row=={"index":r["index"],"pid":pid,
                   "target":r["target"],"value":"0x0"},
             "all original guest qwords zero before any of eight original native stores")
    good=[]
    for i,(_,v) in enumerate(hits):
        r=rows[i]
        need(v["index"]==r["index"]
             and v["target"]==r["target"]
             and v["value"]==r["candidate"]
             and v["pid"]==pid
             and v["x4"]==r["target"]
             and v["x13"]==v["value"]
             and int(v["value"],16)>0
             and int(v["pc"],16)>=0xffff00000000
             and int(v["x28"],16)>=0xffff00000000
             and v["source_x86_3bytes"]=="4c8908"
             and v["FEX_guest_entry"]=="0x80100fb8b"
             and v["FEX_guest_size"]==3
             and v["FEX_native_ops"]==2
             and re.search(r"^\s*(0x[0-9a-f]+):\s+stlr\s+x13,\s*\[x4\]\s*$",
                           v["instruction"]) is not None,
             "source "+str(r["index"])+" exact native ARM64 STLR and genuine x86 GNU loader JIT/CPU state at true qword target")
        inst=re.search(r"^\s*(0x[0-9a-f]+):",v["instruction"])
        need(int(v["pc"],16)==int(inst[1],16)+4,
             "AArch64 hardware trap PC is immediately after authentic FEX stlr")
        good.append(v)
    expected={
        "pid":pid,"indices":RELA,
        "targets":[r["target"] for r in rows],
        "values":[r["candidate"] for r in rows],
        "all_147_same_guest_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False}
    need(final[1]==expected,
         "true one-process full 8-entry original FEX native GDB terminal marker with no closure claims")
    return {"same_native_linux_arm64_FEX_inferior_pid":pid,"live_writer_events":good,
            "first_watchpoint_window":first[1],"second_watchpoint_window":second[1]}

def forged(text:str,k:str,position:int,field:str,replacement):
    token="KERNIX_G0_L3_"+k+" "
    raw=list(re.finditer("^"+re.escape(token)+r"(\{[^\r\n]*\})$",text,re.M))
    need(len(raw)==COUNTS[NAMES.index(k)] and position<len(raw),
         "exact original GDB JSON event available for negative control "+k)
    hit=raw[position]
    record=json.loads(hit[1])
    need(field in record and record[field]!=replacement,
         "falsification must actually change original hardware provenance")
    record[field]=replacement
    return text[:hit.start()]+token+json.dumps(record,sort_keys=True)+text[hit.end():]

def adversarial(text:str,plan:dict):
    e=events(text)
    pid=e["FIRST_FOUR_HARDWARE_WRITERS_ARMED_ONE_PID"][0][1]["pid"]
    mutations=[
       ("pre77_pid","BEFORE",0,"pid",pid+1),
       ("pre84_pid","BEFORE",7,"pid",pid+1),
       ("pre77_index","BEFORE",0,"index",99),
       ("pre84_target","BEFORE",7,"target","0x1"),
       ("pre78_nonzero","BEFORE",1,"value","0x1"),
       ("first_window_pid","FIRST_FOUR_HARDWARE_WRITERS_ARMED_ONE_PID",0,"pid",pid+1),
       ("first_window_indices","FIRST_FOUR_HARDWARE_WRITERS_ARMED_ONE_PID",0,"indices",[77,78,79,81]),
       ("second_window_pid","SECOND_FOUR_HARDWARE_WRITERS_ARMED_SAME_PID",0,"pid",pid+1),
       ("second_window_indices","SECOND_FOUR_HARDWARE_WRITERS_ARMED_SAME_PID",0,"indices",[81,82,83,85]),
       ("second_window_prior_writes","SECOND_FOUR_HARDWARE_WRITERS_ARMED_SAME_PID",0,"already_observed",[77,78,79,81]),
    ]
    mutations += [(f"native_{i}_different_pid","LIVE_HARDWARE_WRITER",i,"pid",pid+1) for i in range(8)]
    mutations += [(f"native_{i}_wrong_target","LIVE_HARDWARE_WRITER",i,"target","0x1") for i in (0,3,4,7)]
    mutations += [(f"native_{i}_wrong_value","LIVE_HARDWARE_WRITER",i,"value","0x1") for i in (1,2,5,6)]
    mutations += [
       ("native_83_x4_wrong","LIVE_HARDWARE_WRITER",6,"x4","0x1"),
       ("native_84_x13_wrong","LIVE_HARDWARE_WRITER",7,"x13","0x1"),
       ("native_STLR_replaced_by_LDAR","LIVE_HARDWARE_WRITER",2,"instruction","0xffff00000104:\tldar x13, [x4]"),
       ("native_guest_x86_source_mutated","LIVE_HARDWARE_WRITER",5,"source_x86_3bytes","909090"),
       ("final_same_pid_mutated","EIGHT_REAL_ORIGINAL_RELOCATION_WRITERS_SAME_ARM64_FEX_PID",0,"pid",pid+1),
       ("final_source_targets_mutated","EIGHT_REAL_ORIGINAL_RELOCATION_WRITERS_SAME_ARM64_FEX_PID",0,"targets",["0x1"]*8),
    ]
    need(len(mutations)==32 and len({m[0] for m in mutations})==32,
         "exact thirty-two independent simulated false native hardware GDB proofs")
    denied=[]
    for name,label,i,field,value in mutations:
        altered=forged(text,label,i,field,value)
        try:attest(altered,plan)
        except (AssertionError,KeyError,ValueError,TypeError):denied.append(name)
        else:raise AssertionError("FORGED_G0_L3_EIGHT_SAME_FEX_NATIVE_WRITERS_ACCEPTED "+name)
    need(len(denied)==32,"all 32 forged native ARM64 register, window and PID evidence must fail closed")
    return denied

def run(triad:Path,prior131:Path,source71:Path,prior141:Path,source81:Path,
        prior147:Path,source_plan:Path,raw:Path,repo:Path,out:Path):
    rebuild=out/"reverified-source"
    original=rebuild_plan(triad,prior131,source71,prior141,source81,prior147,repo,rebuild)
    need(original["schema"]==SOURCE_SCHEMA
         and original["original_source_indices"]==RELA
         and original["new_same_FEX_process_original_writers_proven"]==0,
         "independent SHA original GNU 8-source source plan, no inflated runtime assumptions")
    for filename in (SOURCE_OUT,SOURCE_GDB):
        need(read(source_plan/filename,800000)==read(rebuild/filename,800000),
             "independently recreated original GNU 8-source GDB source plan parity "+filename)
    rawdoc=json.loads(read(raw/RAW,200000))
    trace=read(raw/LOG,650000).decode(errors="replace")
    gdb_exit=int(read(raw/"gdb.exit",50).decode().strip())
    need(rawdoc["schema"]=="kernix.g0.l3.original-gnu-eight-genuine-writers-one-arm64-FEX-PID-two-four-watchpoint-windows-raw.v1"
         and rawdoc["source_original_indices"]==RELA
         and rawdoc["raw_gdb_log_sha256"]==hashlib.sha256(trace.encode()).hexdigest()
         and rawdoc["gdb_exit_code"]==gdb_exit==0
         and rawdoc["one_real_arm64_FEX_guest_process_with_8_writers_in_two_four_watch_windows_raw"] is True
         and rawdoc["independently_certified_same_pid_eight_native_writers"] is False
         and rawdoc["all_147_same_guest_native_execution_proven"] is False
         and rawdoc["full_original_libc_147_process_relocation_closure_proven"] is False
         and rawdoc["Android_Bionic_Wine_Proton_games_proven"] is False,
         "separately SHA attested RAW one real ARM64 FEX host process has not self-certified full loader")
    verified=attest(trace,original)
    need(rawdoc["native_FEX_inferior_os_pid"]==verified["same_native_linux_arm64_FEX_inferior_pid"]
         and rawdoc["first_window"]==[verified["first_watchpoint_window"]]
         and rawdoc["second_window"]==[verified["second_watchpoint_window"]]
         and rawdoc["original_hardware_native_writer_events"]==verified["live_writer_events"],
         "raw report matches every exact original observed native hardware write and same stopped PID rearm")
    negative=adversarial(trace,original)
    output={
      "schema":SCHEMA,"source_original_libc_sha256":LIBC_SHA,
      "source_original_ldso_sha256":LDSO_SHA,"original_source_indices":RELA,
      "eight_individual_source_targets_written_in_one_real_native_ARM64_FEX_inferior_independently_attested":True,
      "same_real_linux_arm64_FEX_inferior_pid":verified["same_native_linux_arm64_FEX_inferior_pid"],
      "native_original_source_writer_events":verified["live_writer_events"],
      "first_four_source_watchpoint_window":verified["first_watchpoint_window"],
      "second_four_source_watchpoint_window":verified["second_watchpoint_window"],
      "raw_GDB_native_hardware_trace_sha256":hashlib.sha256(trace.encode()).hexdigest(),
      "thirtytwo_adversarial_native_hardware_fake_traces_rejected":negative,
      "same_process_independently_certified_original_GNU_source_writer_count":8,
      "all_147_same_guest_native_execution_proven":False,
      "full_original_libc_147_process_relocation_closure_proven":False,
      "Android_Bionic_Wine_Proton_games_proven":False,
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/OUT).write_text(json.dumps(output,indent=2)+"\n")
    print("KERNIX_G0_L3_EIGHT_REAL_GNU_ORIGINAL_ARM64_FEX_WRITERS_SAME_PID_INDEPENDENTLY_PROVEN",
          verified["same_native_linux_arm64_FEX_inferior_pid"],"FORGED_PROOFS_REJECTED_32 NOT_FULL_LOADER",flush=True)
    return output

if __name__=="__main__":
    need(len(sys.argv)==11,
         "usage original-triad prior131 original71 prior141 original81 canonical147 stage3-source stage3-raw repo out")
    run(*map(Path,sys.argv[1:]))
