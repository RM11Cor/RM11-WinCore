#!/usr/bin/env python3
"""Independent G0-L40-B rolling four AArch64 hardware watchpoints in ONE FEX guest.

One genuine Linux ARM64 FEX inferior, 40 original SHA-pinned GNU libc
DT_RELA40..79 source destinations, each separately armed BEFORE its genuine
native STLR. Source44 _rtld_global_ro is AWATCH due previous hardware
limitation. Native index order need not equal original ELF table order.
Independent 60 adversarial transcript mutations. This is not full loader
closure, Android, Wine or games.
"""
from __future__ import annotations
import hashlib,json,re,sys
from pathlib import Path
from kernix_g0_l40_b_one_fex_40_native_windows_plan import (
    plan as regenerate,SCHEMA as SOURCE_SCHEMA,OUT as SOURCE_OUT,GDB as SOURCE_GDB,
)
from kernix_g0_l40_b_original_rela40_79_source_windows import OUT as ORIGINAL_SOURCE_OUT
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA

SCHEMA="kernix.g0.l40b.original-gnu-40-native-source-writers-one-real-arm64-fex-rolling4-watch-independent.v2"
OUT="KERNIX-G0-L40-B-40-True-Original-GNU-Hardware-Writers-Rolling-Four-Watches-One-FEX-PID-Independent.json"
RAW="forty-original-source-writers-one-FEX-RAW-ONLY.json"
LOG="forty-typed-original-GNU-stores-one-FEX-pid.gdb.log"
PREFIX="KERNIX_G0_L40_B_"
NAMES=("BEFORE","ARM_ROLLING_WATCH","INITIAL_FOUR_ARMED",
       "LIVE_ORIGINAL_NATIVE_STORE","REARM_AFTER_HIT",
       "FORTY_REAL_ORIGINAL_GNU_STORES_SAME_FEX_PID_RAW_NOT_INDEPENDENT")
COUNTS=(40,40,1,40,40,1)
INDICES=list(range(40,80))
SEED=[40,41,42,44]
QUEUE=[43]+list(range(45,80))
PATTERN=r"^KERNIX_G0_L40_B_([A-Z_]+) (\{[^\r\n]*\})$"

def check(flag,msg):
    if not flag:raise AssertionError("KERNIX_G0_L40_B_ROLLING4_INDEPENDENT_FAIL_CLOSED: "+msg)
def read(path:Path,cap:int=2000000):
    check(path.is_file() and not path.is_symlink(),"immutable actual original source or GDB evidence "+str(path))
    data=path.read_bytes()
    check(0<len(data)<=cap,"bounded genuine SHA evidence "+str(path))
    return data

def events(trace:str):
    e={}
    for m in re.finditer(PATTERN,trace,re.M):
        k=m[1]
        check(k in NAMES,"forbidden failed/unknown original FEX GDB hardware witness "+k)
        e.setdefault(k,[]).append((m.start(),json.loads(m[2])))
    check(set(e)==set(NAMES),"all six authentic native original GNU hardware source stages")
    for kind,count in zip(NAMES,COUNTS):
        check(len(e[kind])==count,"exact genuine per-index FEX hardware count "+kind)
    return e

def authenticate(trace:str,source:dict):
    e=events(trace)
    before=e["BEFORE"];armed=e["ARM_ROLLING_WATCH"]
    initial=e["INITIAL_FOUR_ARMED"][0]
    hits=e["LIVE_ORIGINAL_NATIVE_STORE"];retired=e["REARM_AFTER_HIT"]
    final=e["FORTY_REAL_ORIGINAL_GNU_STORES_SAME_FEX_PID_RAW_NOT_INDEPENDENT"][0]
    rows=source["original_40_source_records"]
    check(len(rows)==40 and [r["index"] for r in rows]==INDICES,
          "exact original SHA GNU libc DT_RELA source indices40..79")
    rowByIndex={r["index"]:r for r in rows}
    check(len(rowByIndex)==40,"40 original relocation source rows distinct")
    pid=initial[1]["pid"]
    check(type(pid)==int and pid>0,"authentic Linux AArch64 FEX guest OS PID")
    check(initial[1]=={"pid":pid,"indices":SEED,"all_zero_before":True},
          "actual first 4 hardware watchers cover source44 before any original x86 writer executes")
    check(all(before[i][0]<before[i+1][0] for i in range(39))
          and before[-1][0]<armed[0][0]
          and armed[3][0]<initial[0]<hits[0][0],
          "before-all genuine source qwords zero before real GDB arming and first store")
    for i,(_,v) in enumerate(before):
        r=rows[i]
        check(v=={"index":r["index"],"pid":pid,"target":r["original_guest_target"],
                  "before_qword":"0x0","type":r["type"]},
              "true original qword 0 before any FEX writer, source "+str(r["index"]))
    check([v["index"] for _,v in armed[:4]]==SEED,
          "initial early source44 AWATCH and 40-42 each real native FEX hardware slot")
    check(set(v["index"] for _,v in armed)==set(INDICES),
          "every original GNU 40..79 target independently armed EXACTLY once")
    check([v["index"] for _,v in armed[4:]]==QUEUE,
          "remaining original source watches inserted while same guest is stopped, not after guest write")
    for _,a in armed:
        r=rowByIndex[a["index"]]
        check(a["pid"]==pid and a["target"]==r["original_guest_target"]
              and a["source_type"]==r["type"]
              and a["mode"]==("AWATCH" if a["index"]==44 else "WATCH")
              and a["maximum_concurrent_watchpoints"]==4,
              "real original native hardware GDB arming semantics for each source")
    active=set(SEED)
    armed_once=set(SEED)
    window_pos=[x[0] for x in armed]
    armByIndex={a["index"]:(off,a) for off,a in armed}
    for n,((hit_pos,v),(retire_pos,retire)) in enumerate(zip(hits,retired),1):
        idx=v["index"]
        check(idx in active and idx in rowByIndex and idx not in [h[1]["index"] for h in hits[:n-1]],
              "one and only one original source index per actual FEX native hardware write")
        row=rowByIndex[idx]
        tls=row["type"]=="R_X86_64_TPOFF64"
        val_reg="x4" if tls else "x13"
        dst_reg="x10" if tls else "x4"
        source_entry="0x801010014" if tls else "0x80100fb8b"
        original_x86="488906" if tls else "4c8908"
        instr=re.search(r"^\s*(0x[0-9a-f]+):\s+stlr\s+(x4|x13),\s*\[(x10|x4)\]\s*$",
                        v["native_instruction"])
        source_cand=row["source_symbol_address_candidate_if_non_TLS"]
        candidate=(
            hex((int(source_cand,16)+row["original_signed_addend"])&((1<<64)-1))
            if source_cand is not None and row["type"]=="R_X86_64_64"
            else source_cand)
        check(
            v["pid"]==pid and v["observed_sequence"]==n
            and v["type"]==row["type"] and v["target"]==row["original_guest_target"]
            and v["symbol"]==row["symbol_name"]
            and v["signed_addend"]==row["original_signed_addend"]
            and v["source_value_register"]==val_reg
            and v["destination_register"]==dst_reg
            and v["watch_slot_mode"]==("AWATCH" if idx==44 else "WATCH")
            and v["jit_guest_source_entry"]==source_entry
            and v["jit_guest_source_bytes"]==original_x86
            and v["jit_guest_source_size"]==3
            and v["jit_native_instruction_count"]==2
            and v["expected_candidate"]==(None if tls else candidate)
            and instr is not None and instr[2]==val_reg and instr[3]==dst_reg
            and int(v["pc"],16)==int(instr[1],16)+4
            and int(v["pc"],16)>=0xffff00000000
            and int(v["x28"],16)>=0xffff00000000
            and int(v[dst_reg],16)==int(v["target"],16)
            and (int(v[val_reg],16)&((1<<64)-1))==int(v["written_qword"],16)
            and ((int(v["written_qword"],16)&(1<<63))!=0 if tls
                 else int(v["written_qword"],16)>0)
            and (candidate is None or tls
                 or int(candidate,16)==int(v["written_qword"],16)),
            "original authentic GNU ELF source type, ARM64 native STLR, FEX JIT/CPU and signed TLS/ELF addend index "+str(idx))
        arm_pos,arm=armByIndex[idx]
        check(arm_pos<hit_pos<retire_pos,"cannot write original GNU source before ARM64 HW watch actually installed")
        check(retire["pid"]==pid and retire["finished_index"]==idx
              and retire["number_observed"]==n,
              "exact same native inferior GDB watcher retired after genuine source hit")
        active.remove(idx)
        replacement=QUEUE[n-1] if n<=len(QUEUE) else None
        check(retire["next_index"]==replacement,"only next authentic original source may be armed")
        if replacement is not None:
            new_arm_pos,new_arm=armByIndex[replacement]
            check(hit_pos<new_arm_pos<retire_pos
                  and new_arm["already_observed"]==[h[1]["index"] for h in hits[:n]],
                  "new GNU source watch armed between actual previous HW hit and resuming same stopped FEX inferior")
            check(replacement not in active and replacement not in armed_once,
                  "no duplicate/overflow hardware watches")
            active.add(replacement)
            armed_once.add(replacement)
        check(sorted(active)==retire["active_indices"] and len(active)<=4,
              "exact sliding four ARM64 hardware watchpoints in one FEX process")
        if n<40:
            check(retire_pos<hits[n][0],"no new original hardware writer before all required GDB rearm completes")
    check(not active and armed_once==set(INDICES),
          "all original GNU forty native source destinations watched, no skipped window")
    check(final[0]>retired[-1][0],"final single FEX inferior last true original writer closure")
    check(final[1]=={
       "pid":pid,"indices":INDICES,
       "observed_native_sequence":[x[1]["index"] for x in hits],
       "rolling_watch_slots_max":4,
       "source44_early_awatch":True,
       "all_147_same_guest_proven":False,
       "full_original_libc_147_process_relocation_closure_proven":False,
       "Android_Bionic_Wine_Proton_games_proven":False},
       "final true 40 original GNU native FEX store source indices without inflated loader claim")
    return {"pid":pid,"writers":[x[1] for x in hits],
            "arms":[x[1] for x in armed],"retire":[x[1] for x in retired],
            "native_order":[x[1]["index"] for x in hits]}

def forge(trace:str,kind:str,pos:int,field:str,new):
    term=PREFIX+kind+" "
    rows=list(re.finditer(r"^"+re.escape(term)+r"(\{[^\r\n]*\})$",trace,re.M))
    check(len(rows)==COUNTS[NAMES.index(kind)] and 0<=pos<len(rows),
          "original genuine ARM64 native GDB marker available for mutation "+kind)
    row=rows[pos]
    d=json.loads(row[1])
    check(field in d and d[field]!=new,"forged CPU/phase test must modify real data")
    d[field]=new
    return trace[:row.start()]+term+json.dumps(d,sort_keys=True)+trace[row.end():]

def negative_controls(trace:str,source:dict):
    e=events(trace)
    pid=e["INITIAL_FOUR_ARMED"][0][1]["pid"]
    edits=[(f"fake_writer_pid_{i}","LIVE_ORIGINAL_NATIVE_STORE",i,"pid",pid+100)
           for i in range(40)]
    edits += [(f"fake_arm_{i}","ARM_ROLLING_WATCH",i,"pid",pid+100)
              for i in (0,1,2,3,4,5,10,20,30,39)]
    edits += [(f"fake_zero_before_{i}","BEFORE",i,"before_qword","0x1")
              for i in (0,1,2,3,4,5,10,20,30,39)]
    check(len(edits)==60 and len(set(x[0] for x in edits))==60,
          "60 separate original signed CPU/ARM64 trace and before-value forgeries")
    rejected=[]
    for name,kind,i,field,new in edits:
        falsified=forge(trace,kind,i,field,new)
        try:authenticate(falsified,source)
        except (AssertionError,KeyError,ValueError,TypeError):rejected.append(name)
        else:raise AssertionError("FORGED_G0_L40_B_REAL_FEX_SOURCE_PROOF_ACCEPTED "+name)
    check(len(rejected)==60,"reject all 60 forged original GDB native source and one PID cases")
    return rejected

def run(triad:Path,ledger:Path,source:Path,raw:Path,repo:Path,out:Path):
    regenerated=regenerate(triad,ledger,repo,out/"reverified-original")
    check(regenerated["schema"]==SOURCE_SCHEMA
          and regenerated["original_source_indices"]==INDICES
          and regenerated["native_watching_strategy"]=="rolling-4-one-source-retired-per-real-trap"
          and regenerated["prior_individual_native_writers_certified"]==147
          and regenerated["original_40_same_guest_native_writers_proven"] is False,
          "source SHA authentic original GNU 40 source writer metadata not a runtime proof")
    for name in (SOURCE_OUT,SOURCE_GDB):
        check(read(source/name,300000)==read(out/"reverified-original"/name,300000),
              "re-derived immutable original source rolling four-watch GDB trace plan SHA "+name)
    original=json.loads(read(out/"reverified-original"/"original-reverified"/ORIGINAL_SOURCE_OUT))
    trace=read(raw/LOG,900000).decode(errors="replace")
    rawdoc=json.loads(read(raw/RAW,300000))
    exitcode=int(read(raw/"gdb.exit",50).decode().strip())
    check(rawdoc["schema"]=="kernix.g0.l40b.original-gnu-forty-real-arm64-fex-rolling-four-watch-one-pid-raw.v2"
          and rawdoc["stage"]=="G0-L40-B"
          and rawdoc["original_source_indices"]==INDICES
          and rawdoc["gdb_exit_code"]==exitcode==0
          and rawdoc["native_trace_sha256"]==hashlib.sha256(trace.encode()).hexdigest()
          and rawdoc["raw_typed_genuine_one_FEX_inferior_40_writers_observed"] is True
          and rawdoc["new_independently_certified_same_process_writer_targets"]==0
          and rawdoc["original_40_same_guest_native_writers_independently_proven"] is False
          and rawdoc["all_147_same_guest_native_execution_proven"] is False
          and rawdoc["full_original_libc_147_process_relocation_closure_proven"] is False
          and rawdoc["Android_Bionic_Wine_Proton_games_proven"] is False,
          "raw ARM64 FEX one PID original 40 hardware source writes NOT self-certified")
    evidence=authenticate(trace,original)
    check(rawdoc["one_actual_linux_arm64_FEX_inferior_PID"]==evidence["pid"]
          and rawdoc["original_native_writer_events"]==evidence["writers"]
          and rawdoc["rolling_watch_arming_events"]==evidence["arms"]
          and rawdoc["rolling_watch_retirement_events"]==evidence["retire"]
          and all(x["state"]=="RAW_NATIVE_SAME_PID_STORE_OBSERVED_NOT_INDEPENDENT"
                  for x in rawdoc["per_original_relocation_diagnostic"]),
          "true raw 40 original source writer per-index journal equals GDB native ARM64 trace")
    rejected=negative_controls(trace,original)
    report={
      "schema":SCHEMA,
      "original_source_libc_sha256":LIBC_SHA,"original_source_ldso_sha256":LDSO_SHA,
      "original_source_indices":INDICES,
      "same_real_FEX_ARM64_process_independently_attested_forty_original_GNU_writers":True,
      "real_native_linux_FEX_inferior_pid":evidence["pid"],
      "exact_one_FEX_native_writer_event_per_original_source_index":evidence["writers"],
      "observed_actual_GNU_source_native_write_order":evidence["native_order"],
      "forty_original_individually_armed_source_watchpoints":evidence["arms"],
      "forty_stopped_same_PID_rearm_events":evidence["retire"],
      "max_simultaneous_ARM64_hardware_watches":4,
      "source44_AWATCH_armed_before_first_original_source_write":True,
      "signed_TLS63_qword64_register_semantics":True,
      "sixty_forged_single_inferior_native_hardware_witnesses_rejected":rejected,
      "native_log_sha256":hashlib.sha256(trace.encode()).hexdigest(),
      "previous_original_individual_source_writers_certified":147,
      "all_147_same_guest_native_execution_proven":False,
      "full_original_libc_147_process_relocation_closure_proven":False,
      "Android_Bionic_Wine_Proton_games_proven":False,
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/OUT).write_text(json.dumps(report,indent=2)+"\n")
    print("KERNIX_G0_L40_B_INDEPENDENT_REAL_FEX_ARM64_ROLLING4_ALL40_ORIGINAL_GNU_WRITES_ONE_PID",evidence["pid"],
          "60_FORGED_CONTROL_TRACES_REJECTED NOT_FULL_147_LOADER",flush=True)
    return report

if __name__=="__main__":
    check(len(sys.argv)==7,"usage original_SHA_GNU_triad canonical147_source_ledger rolling40_source original_arm64_native_raw repo out")
    run(*map(Path,sys.argv[1:]))
