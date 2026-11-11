#!/usr/bin/env python3
"""Independent original GNU L40-A typed 40-target 10x4 single-FEX-PID gate.

Recompute immutable original GNU source and exact GDB plan, cross-check
40 real hardware traps in ONE Linux ARM64 FEX process and preserve
per-index original type, store-register, TLS JIT and native PC. Reject
60 mutated CPU/window/before-state events. Never use this proof for
Android/Bionic/Wine/Proton/game readiness or full 147 loader closure.
"""
from __future__ import annotations
import hashlib,json,re,sys
from pathlib import Path
from kernix_g0_l40_a_one_fex_40_native_windows_plan import (
    plan as source_plan,SCHEMA as SOURCE_SCHEMA,
    OUT as SOURCE_OUT,GDB as SOURCE_GDB,
)
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA

SCHEMA="kernix.g0.l40a.independent-forty-original-gnu-type-specific-native-writers-one-real-linux-arm64-fex-inferior.v1"
OUT="KERNIX-G0-L40-A-40-Original-GNU-Writers-One-Real-FEX-PID-Independent-Native-Only.json"
RAW="forty-original-source-writers-one-FEX-RAW-ONLY.json"
LOG="forty-typed-original-GNU-stores-one-FEX-pid.gdb.log"
KINDS=("BEFORE","ARM_WINDOW","LIVE_ORIGINAL_NATIVE_STORE","WINDOW_CHECKPOINT_SAME_PID",
       "FINAL_WINDOW_DONE","FORTY_REAL_ORIGINAL_GNU_STORES_SAME_FEX_PID_RAW_NOT_INDEPENDENT")
EXPECTED=(40,10,40,9,1,1)
PREFIX="KERNIX_G0_L40_A_"
RECORD=r"^KERNIX_G0_L40_A_([A-Z_]+) (\{[^\r\n]*\})$"

def require(ok,msg):
    if not ok:raise AssertionError("KERNIX_G0_L40_A_INDEPENDENT_NATIVE_FAIL_CLOSED: "+msg)
def read(p:Path,cap:int=3000000)->bytes:
    require(p.is_file() and not p.is_symlink(),"real immutable original source "+str(p))
    data=p.read_bytes()
    require(0<len(data)<=cap,"bounded SHA original evidence "+str(p))
    return data
def extract(text):
    out={}
    for m in re.finditer(RECORD,text,re.M):
        k=m[1]
        require(k in KINDS,"unapproved, failed or forged native GDB event "+str(k))
        out.setdefault(k,[]).append((m.start(),json.loads(m[2])))
    require(set(out)==set(KINDS),"all true real ARM64 FEX native event types")
    for k,n in zip(KINDS,EXPECTED):
        require(len(out[k])==n,"all true original FEX native source event counts "+k)
    return out
def validate(trace:str,source:dict):
    ev=extract(trace)
    b=ev["BEFORE"]
    armed=ev["ARM_WINDOW"]
    writes=ev["LIVE_ORIGINAL_NATIVE_STORE"]
    ck=ev["WINDOW_CHECKPOINT_SAME_PID"]
    final=ev["FORTY_REAL_ORIGINAL_GNU_STORES_SAME_FEX_PID_RAW_NOT_INDEPENDENT"][0]
    done=ev["FINAL_WINDOW_DONE"][0]
    require(len({h[1]["pid"] for h in writes})==1,"no mixed ARM64 FEX native inferior processes")
    pid=writes[0][1]["pid"]
    require(type(pid)==int and pid>0,"real nonzero Linux ARM64 FEX process ID")
    require(all(b[i][0]<b[i+1][0] for i in range(39)) and
            b[39][0]<armed[0][0],"40 original GNU source qword BEFORE values prior to initial watches")
    rows=source["original_40_source_records"]
    require(len(rows)==40 and [r["index"] for r in rows]==list(range(40)),
            "original GNU SHA ELF source 0..39 canonical indices")
    for i,(offset,e) in enumerate(b):
        r=rows[i]
        require(e=={"index":i,"pid":pid,"target":r["original_guest_target"],
                    "before_qword":"0x0","type":r["type"]},
                "authentic GNU before-CPU-relocation value index "+str(i))
    for window in range(10):
        start=4*window
        window_arm=armed[window]
        require(window_arm[1]=={
            "window":window+1,"pid":pid,
            "indices":list(range(start,start+4)),
            "max_hardware_watchpoints":4},
            "exact per-window original GNU four register-only GDB hardware watchpoints")
        part=writes[start:start+4]
        require(window_arm[0]<part[0][0] and
                all(part[i][0]<part[i+1][0] for i in range(3)) and
                (window==9 or part[-1][0]<armed[window+1][0]),
                "real 4 native stores after source arm and before rearm, one FEX PID")
        require(set(x[1]["index"] for x in part)==set(range(start,start+4)),
                "four original source indices in hardware watch window "+str(window+1))
        for pos,event in part:
            idx=event["index"]
            row=rows[idx]
            tls=row["type"]=="R_X86_64_TPOFF64"
            expectedJit="0x801010014" if tls else "0x80100fb8b"
            expectedCode="488906" if tls else "4c8908"
            valRegister="x4" if tls else "x13"
            dstRegister="x10" if tls else "x4"
            expectedType="R_X86_64_TPOFF64" if tls else row["type"]
            instruction=event["native_instruction"]
            m=re.search(r"(0x[0-9a-f]+):\s+stlr\s+(x4|x13),\s*\[(x10|x4)\]",instruction)
            require(
                event["pid"]==pid
                and event["window"]==window+1
                and event["type"]==expectedType
                and event["target"]==row["original_guest_target"]
                and event["symbol"]==row["symbol_name"]
                and event["signed_addend"]==row["original_signed_addend"]
                and event["source_value_register"]==valRegister
                and event["destination_register"]==dstRegister
                and event["jit_guest_source_entry"]==expectedJit
                and event["jit_guest_source_bytes"]==expectedCode
                and event["jit_guest_source_size"]==3
                and event["jit_native_instruction_count"]==2
                and m is not None and m[2]==valRegister and m[3]==dstRegister
                and int(event["pc"],16)==int(m[1],16)+4
                and int(event["pc"],16)>=0xffff00000000
                and int(event["x28"],16)>=0xffff00000000
                and int(event[dstRegister],16)==int(event["target"],16)
                and (int(event[valRegister],16)&((1<<64)-1))==int(event["written_qword"],16)
                and (int(event["written_qword"],16)&(1<<63)!=0 if tls
                     else int(event["written_qword"],16)!=0),
                "original SHA GNU source typed native ARM64 STLR and live register/JIT and correct guest address index "+str(idx))
            # Local source symbol candidates are not complete dynamic
            # interposition proofs; match only when the real original
            # ELF source defines one.
            source_candidate=row["source_symbol_address_candidate_if_non_TLS"]
            expected=(hex((int(source_candidate,16)+row["original_signed_addend"]) & ((1<<64)-1))
                      if source_candidate is not None and row["type"]=="R_X86_64_64"
                      else source_candidate)
            require(event["expected_candidate"]==(expected if not tls else None),
                    "original SHA libc candidate and signed addend diagnostics")
            require(expected is None or tls or int(event["written_qword"],16)==int(expected,16),
                    "original candidate matched actual FEX native x86 symbol value if source-defined")
        if window<9:
            checkpoint=ck[window]
            require(checkpoint[1]=={"finished_indices":list(range((window+1)*4)),
                                     "pid":pid,"next_window":window+2},
                    "after genuine native stores, next original four watched only inside SAME FEX process")
            require(armed[window+1][0]<checkpoint[0]<writes[(window+1)*4][0],
                    "GDB stopped native inferior, rearmed next four and resumed WITHOUT new process")
    require(done[1]=={"pid":pid,"count":40} and writes[-1][0]<done[0]<final[0],
            "fortieth genuine original writer and one-process final checkpoint")
    require(final[1]=={
        "pid":pid,"indices":list(range(40)),"windows":10,
        "all_147_same_guest_proven":False,
        "full_original_libc_147_process_relocation_closure_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False},
        "one original real ARM64 FEX inferior final proof, not full runtime closure")
    return {"pid":pid,"native_writes":[e for _,e in writes],
            "native_windows":[e for _,e in armed]}

def falsify(trace:str,k:str,pos:int,field:str,value):
    marker=PREFIX+k+" "
    matches=list(re.finditer(r"^"+re.escape(marker)+r"(\{[^\r\n]*\})$",trace,re.M))
    require(len(matches)==EXPECTED[KINDS.index(k)] and pos<len(matches),
            "mutation anchored to actual original FEX GDB log "+k)
    chosen=matches[pos]
    original=json.loads(chosen[1])
    require(field in original and original[field]!=value,
            "adversarial mutation must change real source evidence")
    original[field]=value
    return trace[:chosen.start()]+marker+json.dumps(original,sort_keys=True)+trace[chosen.end():]
def negatives(trace,src):
    ev=extract(trace)
    pid=ev["ARM_WINDOW"][0][1]["pid"]
    mutations=[(f"false_native_pid_{i}","LIVE_ORIGINAL_NATIVE_STORE",i,"pid",pid+100)
               for i in range(40)]
    mutations += [(f"false_window_{n}","ARM_WINDOW",n,"indices",[100,101,102,103])
                  for n in range(10)]
    mutations += [(f"false_before_source_{i}","BEFORE",i,"before_qword","0x1")
                  for i in (0,1,2,3,4,5,6,7,16,39)]
    require(len(mutations)==60 and len({m[0] for m in mutations})==60,
            "exact 60 independent negative source/window/CPU process evidence mutations")
    rejected=[]
    for name,k,pos,field,val in mutations:
        bogus=falsify(trace,k,pos,field,val)
        try:validate(bogus,src)
        except (AssertionError,KeyError,ValueError,TypeError):
            rejected.append(name)
        else:raise AssertionError("FORGED_ORIGINAL_40_ONE_FEX_PID_HARDWARE_TRACE_ACCEPTED "+name)
    require(len(rejected)==60,"all 60 falsified GNU source CPU provenance events must fail closed")
    return rejected

def run(triad:Path,ledger147:Path,sourceplan:Path,raw:Path,repo:Path,out:Path):
    regenerated=source_plan(triad,ledger147,repo,out/"rederived")
    require(regenerated["schema"]==SOURCE_SCHEMA and
            regenerated["original_source_indices"]==list(range(40)),
            "rederive genuine original 40 source type-specific native GDB plan")
    for filename in (SOURCE_OUT,SOURCE_GDB):
        require(read(sourceplan/filename,200000)==read(out/"rederived"/filename,200000),
                "exact original SHA GDB input matches reconstructed source-only plan "+filename)
    rawdoc=json.loads(read(raw/RAW))
    original=read(raw/LOG,850000).decode(errors="replace")
    exitcode=int(read(raw/"gdb.exit",50).decode().strip())
    require(rawdoc["schema"]=="kernix.g0.l40a.original-gnu-forty-real-arm64-fex-same-pid-ten-four-watchpoint-windows-raw.v1"
            and rawdoc["stage"]=="G0-L40-A"
            and rawdoc["original_source_indices"]==list(range(40))
            and rawdoc["native_trace_sha256"]==hashlib.sha256(original.encode()).hexdigest()
            and rawdoc["gdb_exit_code"]==exitcode==0
            and rawdoc["raw_typed_genuine_one_FEX_inferior_40_writers_observed"] is True
            and rawdoc["new_independently_certified_same_process_writer_targets"]==0
            and rawdoc["original_40_same_guest_native_writers_independently_proven"] is False
            and rawdoc["all_147_same_guest_native_execution_proven"] is False
            and rawdoc["Android_Bionic_Wine_Proton_games_proven"] is False,
            "one real GNU FEX ARM64 original 40-target native hardware log, not raw self-certification")
    trace=validate(original,json.loads(read(out/"rederived"/"original-reverified"/"KERNIX-G0-L40-A-Original-GNU-RELA0-39-40-Typed-Relocations-10-Windows-SOURCE-ONLY.json")))
    require(rawdoc["one_actual_linux_arm64_FEX_inferior_PID"]==trace["pid"]
            and rawdoc["original_native_writer_events"]==trace["native_writes"]
            and rawdoc["watchpoint_arm_windows"]==trace["native_windows"]
            and all(x["state"]=="RAW_NATIVE_SAME_PID_STORE_OBSERVED_NOT_INDEPENDENT" for x in
                    rawdoc["per_original_relocation_diagnostic"]),
            "original per-index native 40 records and SAME PID must exactly match real GDB trace")
    denied=negatives(original,json.loads(read(out/"rederived"/"original-reverified"/"KERNIX-G0-L40-A-Original-GNU-RELA0-39-40-Typed-Relocations-10-Windows-SOURCE-ONLY.json")))
    data={
      "schema":SCHEMA,
      "original_libc_sha256":LIBC_SHA,"original_ldso_sha256":LDSO_SHA,
      "original_source_indices":list(range(40)),
      "original_type_counts":{"R_X86_64_64":3,"R_X86_64_GLOB_DAT":22,"R_X86_64_TPOFF64":15},
      "all_forty_original_native_source_writers_one_real_FEX_ARM64_inferior_independently_attested":True,
      "one_same_native_FEX_process_pid":trace["pid"],
      "per_original_index_native_hardware_events":trace["native_writes"],
      "ten_rearmed_four_hardware_watchpoint_windows":trace["native_windows"],
      "raw_trace_sha256":hashlib.sha256(original.encode()).hexdigest(),
      "sixty_forged_native_source_window_pid_traces_rejected":denied,
      "previous_individual_source_writers_certified":147,
      "same_guest_process_147_original_sources_all_proven":False,
      "full_original_libc_147_process_relocation_closure_proven":False,
      "Android_Bionic_Wine_Proton_games_proven":False,
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/OUT).write_text(json.dumps(data,indent=2)+"\n")
    print("KERNIX_G0_L40_A_INDEPENDENT_TRUE_40_ORIGINAL_GNU_NATIVE_WRITERS_ONE_FEX_PID",
          trace["pid"],"FORGED_TRACES_REJECTED_60 NOT_FULL_LOADER",flush=True)
    return data

if __name__=="__main__":
    require(len(sys.argv)==7,
        "usage original_gnu_triad ledger147 source_only_40_same_FEX_plan raw_native_40 repo_root out")
    run(*map(Path,sys.argv[1:]))
