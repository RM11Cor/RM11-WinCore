#!/usr/bin/env python3
"""Independent fail-closed per-target original GNU DT_RELA31..40 native evidence auditor.

Ten separate original ELF relocation targets, two distinct FEX+GDB AArch64
processes per candidate; each individual target passes 16 falsified-hardware
negative controls. A failing target is quarantined without discarding unrelated
independently certified targets. Source-only and raw-only never increment 103.
"""
from __future__ import annotations
import hashlib
import json
import re
import sys
from pathlib import Path
from kernix_g0_original_globdat_batch41_50_source_after103 import (
    INDICES,SOURCE_NAME,SCHEMA,run as verify_source,
)
from kernix_g0_original_batch41_50_native_parallel_raw import (
    RAW_SCHEMA,PFX,MODES,make_native_gdb,
)
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import LDSO_BIAS

JIT="0x80100fb8b"
OPCODE=bytes.fromhex("4c8908")
SCHEMA_PROOF="kernix.g0.original-gnu-ten-target-independent-arm64-fex-source-writer-batch41-50-after103.v1"
OUT="KERNIX-G0-GNU-DTRELA41-50-Ten-Independent-Hardware-Writer-Audit-After103.json"

def need(ok,what):
    if not ok: raise AssertionError("KERNIX_G0_GNU_BATCH41_50_INDEPENDENT_FAIL_CLOSED: "+what)

def regular(path:Path,limit:int=2000000)->bytes:
    need(path.is_file() and not path.is_symlink(),"regular source/trace "+str(path))
    data=path.read_bytes()
    need(0<len(data)<=limit,"bounded source/trace "+str(path))
    return data

def once(pattern:str,trace:str,label:str):
    matches=list(re.finditer(pattern,trace,re.M))
    need(len(matches)==1,"unique "+label)
    return matches[0]

def native_markers(index:int,mode:str)->tuple[str,str,str]:
    return (f"KERNIX_G0_ORIGINAL_RELA{index}",
            f"KERNIX_G0_RELA{index}_{mode.upper()}_RAW_HIT",
            f"KERNIX_G0_RELA{index}_NATIVE_REGS")

def validate_log(trace:str,index:int,mode:str,row:dict)->dict:
    need(index in INDICES and mode in MODES,"exact original index and native watch mode")
    target=row["target"]
    rtype=row["relocation_type"]
    prefix,marker,regs_marker=native_markers(index,mode)
    arm=once(r"^"+prefix+r"_SOURCE_ARM type="+re.escape(rtype)+r" target="+target+
             r" initial=0x0 SOURCE_ONLY=1$",trace,"original source arm")
    first=once(r"^"+re.escape(target)+r":\s+0x0000000000000000$",trace,
               "original zero target before real hardware store")
    decl=("Hardware watchpoint 2:" if mode=="watch"
          else "Hardware access (read/write) watchpoint 2:")
    hits=list(re.finditer(r"^"+re.escape(decl)+r" -location "+
                         re.escape("*(unsigned long long *)"+target)+r"$",trace,re.M))
    need(len(hits)==2,"native ARM64 watchpoint must be declared and triggered exactly once")
    old=once(r"^Old value = 0$",trace,"actual old zero")
    new=once(r"^New value = ([0-9]+)$",trace,"actual postwrite new qword")
    written=int(new[1])
    need(0<written<2**64,"observed nonzero bounded hardware written qword")
    hit=once(r"^"+marker+r" target="+target+
             r" pc=(0x[0-9a-f]+) x4=(0x[0-9a-f]+) x13=(0x[0-9a-f]+) x28=(0x[0-9a-f]+) NOT_CERTIFIED=1$",
             trace,"real native FEX hardware trap and registers")
    post=once(r"^"+re.escape(target)+r":\s+0x"+format(written,"016x")+r"$",
              trace,"actual target memory matches observed native store")
    ins=once(r"^\s*(0x[0-9a-f]+):\s+stlr\s+x13,\s*\[x4\]$",trace,
             "native AArch64 STLR store after GDB trap")
    regs=once(r"^"+regs_marker+r" x4=(0x[0-9a-f]+) x13=(0x[0-9a-f]+) x28=(0x[0-9a-f]+)$",
              trace,"independent ARM64 x4/x13/x28 evidence")
    jit=once(r"^KERNIX_G0_RELA"+str(index)+
             r"_FEX_JIT guest_entry=(0x[0-9a-f]+) source_size=(0x[0-9a-f]+) native_count=(\d+)$",
             trace,"original guest JIT block mapping")
    x86=once(r"^"+re.escape(JIT)+r":\s+0x4c\s+0x89\s+0x08\s+0x8b\s+0x43\s+0x08",
             trace,"original GNU loader genuine x86 source store opcode")
    footer=once(r"^"+prefix+r"_ZERO_NATIVE_CERTIFICATION_FROM_SOURCE_DISCOVERY=1$",
                trace,"source did not pretend native certification")
    need(arm.start()<first.start()<hits[0].start()<hits[1].start()
         <old.start()<new.start()<hit.start()<post.start()<ins.start()
         <regs.start()<jit.start()<x86.start()<footer.start(),
         "authentic ARM64 hardware observation source/GDB/STLR/FEX/ELF event chronology")
    pc=int(hit[1],16)
    need(pc>=0xffff00000000 and int(ins[1],16)==pc-4,
         "native ARM64 hardware trap is immediately after STLR")
    need(int(hit[2],16)==int(target,16)
         and int(hit[3],16)==written
         and int(regs[1],16)==int(target,16)
         and int(regs[2],16)==written
         and int(regs[3],16)>=0xffff00000000
         and int(regs[3],16)==int(hit[4],16),
         "real native x4 target and x13 value match actual original qword")
    need(jit[1]==JIT and jit[2]=="0x3" and int(jit[3])==2,
         "3 exact authentic GNU x86 source bytes mapped to 2 native JIT ops")
    candidate=(row["symbol"] or {}).get("source_definition_address_candidate_if_non_TLS")
    if candidate is not None:
        need(written==int(candidate,16),
             "live hardware symbol resolution must match original ELF definition candidate for locally defined symbol")
    return {
        "source_index":index,
        "original_source_relocation_type":rtype,
        "original_source_symbol_index":row["symbol_index"],
        "original_source_symbol_name":(row["symbol"] or {}).get("symbol_name"),
        "original_guest_hardware_write_target":target,
        "original_guest_old_qword":"0x0",
        "native_observed_written_qword":hex(written),
        "native_observed_written_decimal":written,
        "original_symbol_ELF_candidate":candidate,
        "candidate_matches_observed_native_writer":(candidate is None or written==int(candidate,16)),
        "original_source_memory_backing":row["original_memory_backing"],
        "native_real_AArch64_store":"stlr x13, [x4]",
        "native_source_value_register":"x13",
        "native_target_address_register":"x4",
        "native_source_register_value":hex(written),
        "native_target_register_value":target,
        "original_GNU_x86_loader_JIT_entry":JIT,
        "original_GNU_x86_loader_store_opcode":"4c8908",
        "native_real_FEX_JIT_instruction_count":2,
        "source_x86_to_arm64_hardware_writer_independently_proven":True,
        "full_dynamic_symbol_scope_preemption_and_versioning_proven":False,
        "all_147_same_guest_native_execution_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }

def forged_cases(trace:str,index:int,row:dict)->list[str]:
    target=row["target"]
    ttype=row["relocation_type"]
    _,hit,reg=native_markers(index,"watch")
    cur=validate_log(trace,index,"watch",row)
    written=cur["native_observed_written_decimal"]
    newhex=hex(written)
    pre=target+":\t0x0000000000000000"
    post=target+":\t0x"+format(written,"016x")
    pc=once(r"^"+hit+r" target="+target+r" pc=(0x[0-9a-f]+) x4=",trace,"real hit PC")[1]
    xx=once(r"^"+reg+r" x4=(0x[0-9a-f]+) x13=(0x[0-9a-f]+) x28=(0x[0-9a-f]+)$",
            trace,"real x28 from raw ARM64")
    x28=xx[3]
    store=once(r"^\s*(0x[0-9a-f]+):\s+stlr\s+x13,\s*\[x4\]$",trace,"real STORE")
    insline=store[0]
    changes=[
      ("alter_original_source_type",f"SOURCE_ARM type={ttype}", "SOURCE_ARM type=R_FAKE"),
      ("alter_original_prewrite_zero",pre,target+":\t0x0000000000000001"),
      ("erase_hardware_trap","Hardware watchpoint 2: -location *(unsigned long long *)"+target,
                             "Hardware watchpoint 2: NATIVE_WATCH_MISSING"),
      ("alter_old_qword","Old value = 0","Old value = 1"),
      ("alter_new_qword","New value = "+str(written),"New value = 0"),
      ("alter_trapped_target",hit+" target="+target,hit+" target=0x1"),
      ("alter_native_PC",hit+" target="+target+" pc="+pc,hit+" target="+target+" pc=0x1"),
      ("replace_native_STLR_with_read",insline,insline.replace("stlr","ldar")),
      ("alter_native_target_register",reg+" x4="+target,reg+" x4=0x1"),
      ("alter_native_value_register"," x13="+newhex+" x28="+x28,
                                      " x13=0x0 x28="+x28),
      ("alter_real_FEX_x28"," x28="+x28," x28=0x1"),
      ("alter_original_guest_JIT_entry",f"RELA{index}_FEX_JIT guest_entry="+JIT,
                                         f"RELA{index}_FEX_JIT guest_entry=0x1"),
      ("alter_original_guest_JIT_size","source_size=0x3","source_size=0x4"),
      ("alter_native_JIT_instruction_count","native_count=2","native_count=1"),
      ("alter_original_GNU_x86_store_bytes",JIT+":\t0x4c\t0x89\t0x08",
                                             JIT+":\t0x90\t0x89\t0x08"),
      ("alter_original_source_footer",f"KERNIX_G0_ORIGINAL_RELA{index}_ZERO_NATIVE_CERTIFICATION_FROM_SOURCE_DISCOVERY=1",
                                       f"KERNIX_G0_ORIGINAL_RELA{index}_ZERO_NATIVE_CERTIFICATION_FROM_SOURCE_DISCOVERY=0"),
    ]
    need(len(changes)==16 and len({name for name,_,_ in changes})==16,
         "exact unique 16 fake hardware negative tests")
    denied=[]
    for name,original,fake in changes:
        need(original in trace and original!=fake, "source of deliberate mutation present "+name)
        falsified=trace.replace(original,fake,1)
        try:
            validate_log(falsified,index,"watch",row)
        except AssertionError:
            denied.append(name)
        else:
            raise AssertionError("FORGED_ORIGINAL_GNU_NATIVE_HARDWARE_EVIDENCE_ACCEPTED index="+str(index)+" "+name)
    need(len(denied)==16,"all sixteen corrupted hardware traces must be rejected")
    return denied

def verify_one(index:int,row:dict,source:Path,native:Path,batch_summary:dict)->dict:
    target=row["target"]
    n=next(r for r in batch_summary["ten_isolated_source_target_results"] if r["index"]==index)
    need(n["raw_capture_complete_for_both_modes"] is True,
         "original guest watch and awatch completed independently; else quarantine")
    gdb_original=regular(source/f"original-gnu-dtrela{index}-source-only.gdb").decode()
    sub=native/f"index{index}"
    logs={}
    receipts={}
    for mode in MODES:
        stem=sub/mode
        expected=make_native_gdb(gdb_original,index,target,mode)
        need(regular(stem.with_suffix(".gdb")).decode()==expected,
             "native GDB equals original SHA source plus exact instrumentation "+mode)
        need(regular(stem.with_suffix(".exit")).decode().strip()=="0",
             "real FEX native guest GDB exit 0 "+mode)
        raw=regular(stem.with_suffix(".log"),600000).decode(errors="replace")
        metadata=json.loads(regular(stem.with_suffix(".json")))
        need(metadata["schema"]==RAW_SCHEMA
             and metadata["source_index"]==index
             and metadata["source_relocation_type"]==row["relocation_type"]
             and metadata["original_symbol_index"]==row["symbol_index"]
             and metadata["source_guest_target"]==target
             and metadata["mode"]==mode
             and metadata["native_arm_seen"] is True
             and metadata["raw_native_hardware_declaration_and_hit_count"]==2
             and metadata["raw_old_qword"]=="0"
             and metadata["raw_new_qword"] is not None
             and metadata["gdb_exit_code"]==0
             and metadata["raw_FEX_GDB_log_sha256"]==hashlib.sha256(raw.encode()).hexdigest()
             and metadata["native_source_hardware_write_independently_attested"] is False
             and metadata["prior_independently_certified_native_writer_count"]==103
             and metadata["Android_Bionic_Wine_Proton_games_proven"] is False,
             "independent raw GDB text SHA and exact no-certification per-target metadata")
        logs[mode]=raw
        receipts[mode]=validate_log(raw,index,mode,row)
        need(metadata["raw_x4"]==target
             and metadata["raw_x13"]==receipts[mode]["native_observed_written_qword"]
             and metadata["raw_guest_JIT_entry"]==JIT
             and metadata["raw_guest_JIT_size"]=="0x3"
             and int(metadata["raw_new_qword"])==receipts[mode]["native_observed_written_decimal"],
             "actual CPU register metadata and original guest JIT match raw trace")
    need(logs["watch"]!=logs["awatch"],"two distinct native ARM64 FEX GDB guest processes")
    need(receipts["watch"]["native_observed_written_qword"]==
         receipts["awatch"]["native_observed_written_qword"] and
         receipts["watch"]["native_real_AArch64_store"]==
         receipts["awatch"]["native_real_AArch64_store"],
         "both independent guest executions observe identical original qword store")
    rejected=forged_cases(logs["watch"],index,row)
    receipt=receipts["watch"]
    receipt.update({
        "native_WATCH_log_sha256":hashlib.sha256(logs["watch"].encode()).hexdigest(),
        "native_AWATCH_log_sha256":hashlib.sha256(logs["awatch"].encode()).hexdigest(),
        "two_separate_native_arm64_fex_processes_independently_verified":True,
        "sixteen_falsified_native_hardware_traces_rejected":rejected,
        "independent_real_hardware_writer_certified":True,
    })
    return receipt

def run(triad:Path,prior:Path,source:Path,raw:Path,repo:Path,dist:Path)->dict:
    verified=dist/"reverified_source"
    plan=verify_source(triad,prior,repo,verified)
    need(plan["original_source_indices"]==INDICES and plan["schema"]==SCHEMA,
         "ten genuine original unmodified SHA GNU targets")
    for name in [SOURCE_NAME,*[f"original-gnu-dtrela{i}-source-only.gdb" for i in INDICES]]:
        need(regular(source/name,500000)==regular(verified/name,500000),
             "independent SHA original source GDB plan parity "+name)
    ldso=regular(triad/"lib64/ld-linux-x86-64.so.2")
    op=source_offset(ldso,int(JIT,16)-LDSO_BIAS,3,5)
    need(ldso[op:op+3]==OPCODE,"3 original GNU x86 loader store bytes SHA-verified")
    batch=json.loads(regular(raw/"batch41-50-raw-only-summary.json"))
    need(batch["schema"]==RAW_SCHEMA
         and batch["original_source_indices"]==INDICES
         and batch["source_original_libc_sha256"]==LIBC_SHA
         and batch["source_original_ldso_sha256"]==LDSO_SHA
         and batch["prior_independently_certified_native_writer_count"]==103
         and batch["new_independently_certified_native_writers_from_raw_batch"]==0
         and batch["native_proof_requires_separate_independent_verifier"] is True
         and batch["same_guest_process_all_10_targets_proven"] is False
         and batch["all_147_same_guest_native_execution_proven"] is False
         and batch["Android_Bionic_Wine_Proton_games_proven"] is False
         and len(batch["ten_isolated_source_target_results"])==10
         and [r["index"] for r in batch["ten_isolated_source_target_results"]]==INDICES,
         "ten distinct raw process summaries provide zero prior certification")
    per={}
    for index,row in zip(INDICES,plan["ten_original_gnu_source_relocation_metadata"]):
        try:
            proof=verify_one(index,row,source,raw,batch)
        except (AssertionError,KeyError,ValueError,UnicodeError,OSError) as error:
            per[str(index)]={
                "source_index":index,"status":"QUARANTINED_NOT_CERTIFIED",
                "original_relocation_type":row["relocation_type"],
                "reason":(type(error).__name__+": "+str(error))[:380],
                "new_native_hardware_writer_attestations":0,
            }
            print("KERNIX_G0_BATCH41_50_QUARANTINE index="+str(index)+
                  " type="+row["relocation_type"]+
                  " cause="+type(error).__name__+": "+str(error)[:140],flush=True)
        else:
            per[str(index)]={"source_index":index,"status":"INDEPENDENTLY_CERTIFIED",
                             "native_hardware_writer_receipt":proof,
                             "new_native_hardware_writer_attestations":1}
            print("KERNIX_G0_BATCH41_50_CERTIFIED index="+str(index)+
                  " type="+row["relocation_type"]+
                  " native_written="+proof["native_observed_written_qword"]+
                  " 16_forgery_tests_rejected=1",flush=True)
    accepted=[i for i in INDICES if per[str(i)]["status"]=="INDEPENDENTLY_CERTIFIED"]
    rejected=[i for i in INDICES if i not in accepted]
    need(len(accepted)+len(rejected)==10 and not (set(accepted)&set(rejected)),
         "exact independent 10-target partition")
    output={
        "schema":SCHEMA_PROOF,
        "original_source_libc_sha256":LIBC_SHA,
        "original_source_ldso_sha256":LDSO_SHA,
        "original_source_indices":INDICES,
        "original_relocations_total":147,
        "previously_certified_distinct_native_source_target_count":103,
        "new_independently_certified_distinct_native_source_target_count":len(accepted),
        "combined_distinct_native_source_target_count_if_ledger_verifies":103+len(accepted),
        "independently_certified_source_indices":accepted,
        "uncertified_source_indices_with_isolated_failures":rejected,
        "per_original_source_index_evidence":per,
        "total_forged_hardware_negative_controls_rejected":len(accepted)*16,
        "no_duplicate_original_source_index_counted":True,
        "same_guest_all_10_native_writes_proven":False,
        "all_147_same_guest_native_execution_proven":False,
        "full_dynamic_symbol_preemption_and_versioning_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    dist.mkdir(parents=True,exist_ok=True)
    (dist/OUT).write_text(json.dumps(output,indent=2)+"\n")
    print("KERNIX_G0_BATCH41_50_INDEPENDENT_NATIVE_HARDWARE_RECEIPTS "+
          str(len(accepted))+"/10; 103_BASELINE, NO_ANDROID, "+str(len(rejected))+"_QUARANTINED")
    return output

if __name__=="__main__":
    need(len(sys.argv)==7,
         "usage GNU-source-triad ledger103-file original-ten-source-dir ten-raw-parent-dir repo-root output-dir")
    run(*map(Path,sys.argv[1:]))
