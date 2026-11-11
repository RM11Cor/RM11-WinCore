#!/usr/bin/env python3
"""Ten authentic source-target native ARM64 FEX WATCH+AWATCH tests, isolated and bounded.

A single previously SHA-audited FEX build is shared across tasks. Each target gets
two separate real GDB/FEX guest processes; each failure is quarantined locally.
NO runtime certification is issued by this raw-capture stage.
"""
from __future__ import annotations
import concurrent.futures
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from kernix_g0_original_globdat_batch61_70_source_after122 import (
    INDICES,SCHEMA,SOURCE_NAME,make_gdb,run as source_run,
)
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA

RAW_SCHEMA="kernix.g0.original-gnu-ten-isolated-native-fex-raw61-70-no-indep-proofs.v1"
PFX="KERNIX-G0-BATCH61-70-RAW"
MODES=("watch","awatch")

def require(ok,msg):
    if not ok: raise AssertionError("KERNIX_G0_BATCH61_70_NATIVE_RAW_FAIL_CLOSED: "+msg)

def regular(p:Path,limit=2000000)->bytes:
    require(p.is_file() and not p.is_symlink(),"regular original input "+str(p))
    b=p.read_bytes()
    require(0<len(b)<=limit,"bounded original input "+str(p))
    return b

def make_native_gdb(source:str,index:int,target:str,mode:str)->str:
    require(index in INDICES and mode in MODES,"real single source relocation")
    arm=f"KERNIX_G0_ORIGINAL_RELA{index}_RAW_HIT"
    hit=f"KERNIX_G0_RELA{index}_{mode.upper()}_RAW_HIT"
    require(source.count(arm)==1,"single authentic source hit marker")
    require(source.count("watch -location *(unsigned long long *)"+target)==1,
            "only one original source target hardware watch")
    require(source.count("x/i $pc-4\n")==1,"unique original JIT trap disassembly")
    s=source.replace(arm,hit)
    if mode=="awatch":
        s=s.replace("watch -location *(unsigned long long *)"+target,
                    "awatch -location *(unsigned long long *)"+target)
    addon=(
       f'printf "KERNIX_G0_RELA{index}_NATIVE_REGS x4=0x%lx x13=0x%lx x28=0x%lx\\n",$x4,$x13,$x28\n'
       'set $hdr=*(unsigned long long *)$x28\n'
       'set $off=*(unsigned int *)$hdr\n'
       'set $tail=$hdr+$off\n'
       'set $entry=*(unsigned long long *)($tail+8)\n'
       'set $size=*(unsigned long long *)($tail+16)\n'
       'set $cnt=*(unsigned int *)($tail+24)\n'
       f'printf "KERNIX_G0_RELA{index}_FEX_JIT guest_entry=0x%lx source_size=0x%lx native_count=%u\\n",$entry,$size,$cnt\n'
       'x/16bx $entry\n'
    )
    s=s.replace("x/i $pc-4\n","x/i $pc-4\n"+addon)
    require(s.count(hit)==1 and s.count(f"KERNIX_G0_RELA{index}_FEX_JIT")==1,
            "exact native GDB instrumentation and original source markers")
    return s

def run_one(index:int,row:dict,source_gdb:Path,root:Path,executable:Path,output:Path)->dict:
    target=row["target"]
    d=output/f"index{index}"
    d.mkdir(parents=True,exist_ok=True)
    base=regular(source_gdb).decode()
    per_mode={}
    for mode in MODES:
        stem=d/mode
        script=make_native_gdb(base,index,target,mode)
        (stem.with_suffix(".gdb")).write_text(script)
        cmd=["timeout","-k","5s","180s","gdb","-q","-nx","-batch",
             "-x",str(stem.with_suffix(".gdb")),
             "--args",str(executable),str(root)]
        env=dict(os.environ)
        # ABI and shared FEX library remain exact SHA-audited stage outputs.
        try:
            p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                             timeout=196,env=env,check=False)
            rc=p.returncode
            text=p.stdout.decode("utf-8",errors="replace")
        except subprocess.TimeoutExpired as error:
            rc=124
            text=(error.stdout or b"").decode("utf-8",errors="replace")+"\nKERNIX_RAW_GDB_TIMEOUT\n"
        (stem.with_suffix(".log")).write_text(text)
        (stem.with_suffix(".exit")).write_text(str(rc)+"\n")
        marker=("Hardware watchpoint 2:" if mode=="watch"
                else "Hardware access (read/write) watchpoint 2:")
        event_re=(r"^"+re.escape(marker)+r" -location "+
                  re.escape("*(unsigned long long *)"+target)+r"$")
        events=len(re.findall(event_re,text,re.M))
        old=re.search(r"^Old value = (-?\d+)$",text,re.M)
        new=re.search(r"^New value = (-?\d+)$",text,re.M)
        registers=re.search(
            rf"^KERNIX_G0_RELA{index}_NATIVE_REGS x4=(0x[0-9a-f]+) x13=(0x[0-9a-f]+) x28=(0x[0-9a-f]+)$",
            text,re.M)
        guest=re.search(
            rf"^KERNIX_G0_RELA{index}_FEX_JIT guest_entry=(0x[0-9a-f]+) source_size=(0x[0-9a-f]+) native_count=(\d+)$",
            text,re.M)
        data={
            "schema":RAW_SCHEMA,
            "source_index":index,"source_relocation_type":row["relocation_type"],
            "original_symbol_index":row["symbol_index"],
            "source_guest_target":target,"mode":mode,
            "native_arm_seen":f"KERNIX_G0_ORIGINAL_RELA{index}_SOURCE_ARM" in text,
            "raw_native_hardware_declaration_and_hit_count":events,
            "raw_old_qword":old.group(1) if old else None,
            "raw_new_qword":new.group(1) if new else None,
            "raw_x4":registers.group(1) if registers else None,
            "raw_x13":registers.group(2) if registers else None,
            "raw_x28":registers.group(3) if registers else None,
            "raw_guest_JIT_entry":guest.group(1) if guest else None,
            "raw_guest_JIT_size":guest.group(2) if guest else None,
            "gdb_exit_code":rc,
            "raw_FEX_GDB_log_sha256":hashlib.sha256(text.encode()).hexdigest(),
            "native_source_hardware_write_independently_attested":False,
            "prior_independently_certified_native_writer_count":122,
            "Android_Bionic_Wine_Proton_games_proven":False,
        }
        (stem.with_suffix(".json")).write_text(json.dumps(data,indent=2)+"\n")
        per_mode[mode]={
            "rc":rc,"raw_hardware_watch_declarations":events,
            "raw_old_qword":data["raw_old_qword"],"raw_new_qword":data["raw_new_qword"],
            "native_registers_observed":bool(registers),"gdb_log_sha256":data["raw_FEX_GDB_log_sha256"],
        }
    ok=all(v["rc"]==0 and v["raw_hardware_watch_declarations"]==2
           and v["raw_old_qword"]=="0" and v["raw_new_qword"] is not None
           and v["native_registers_observed"] for v in per_mode.values())
    result={"index":index,"type":row["relocation_type"],
            "candidate":(row["symbol"] or {}).get("source_definition_address_candidate_if_non_TLS"),
            "raw_capture_complete_for_both_modes":ok,
            "raw_only_independent_attestation":False,
            "modes":per_mode}
    print("KERNIX_G0_BATCH61_70_NATIVE_RAW index="+str(index)+
          " type="+row["relocation_type"]+" capture="+("2_OF_2" if ok else "INCOMPLETE")+
          " independently_certified=0",flush=True)
    return result

def run(root:Path,prior:Path,source:Path,repo:Path,exe:Path,dist:Path)->dict:
    # Recreate all ten source records against original SHA-pinned GNU files,
    # then reject any altered source plan or any duplicated source target.
    require(exe.is_file() and not exe.is_symlink(),"original built FEX guest host executable")
    rebuilt=dist/"rebuilt_source"
    plan=source_run(root,prior,repo,rebuilt)
    for name in [SOURCE_NAME,*[f"original-gnu-dtrela{i}-source-only.gdb" for i in INDICES]]:
        require(regular(source/name,500000)==regular(rebuilt/name,500000),
                "exact independent SHA original source plan parity "+name)
    require(plan["schema"]==SCHEMA and plan["original_source_indices"]==INDICES,
            "ten exact original source targets")
    rows=plan["ten_original_gnu_source_relocation_metadata"]
    dest=dist/PFX
    dest.mkdir(parents=True,exist_ok=True)
    # Bounded simultaneous GDB/FEX guest processes to avoid OOM on ARM64.
    # All ten tasks are scheduled together, each produces independent logs.
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures={pool.submit(run_one,i,rows[i-61],
                             source/f"original-gnu-dtrela{i}-source-only.gdb",
                             root,exe,dest):i for i in INDICES}
        results={}
        for future in concurrent.futures.as_completed(futures):
            i=futures[future]
            try:
                results[i]=future.result()
            except Exception as ex:
                results[i]={"index":i,"error_type":type(ex).__name__,
                            "error":str(ex)[:200],
                            "raw_capture_complete_for_both_modes":False,
                            "raw_only_independent_attestation":False}
                print(f"KERNIX_G0_BATCH61_70_TARGET_{i}_ISOLATED_RAW_FAILURE {type(ex).__name__}",flush=True)
    ordered=[results[i] for i in INDICES]
    record={
        "schema":RAW_SCHEMA,"original_source_indices":INDICES,
        "source_original_libc_sha256":LIBC_SHA,"source_original_ldso_sha256":LDSO_SHA,
        "prior_independently_certified_native_writer_count":122,
        "new_independently_certified_native_writers_from_raw_batch":0,
        "ten_isolated_source_target_results":ordered,
        "raw_complete_target_count":sum(x["raw_capture_complete_for_both_modes"] for x in ordered),
        "native_proof_requires_separate_independent_verifier":True,
        "same_guest_process_all_10_targets_proven":False,
        "all_147_same_guest_native_execution_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    (dest/"batch61-70-raw-only-summary.json").write_text(json.dumps(record,indent=2)+"\n")
    print("KERNIX_G0_BATCH61_70_PARALLEL_RAW_SUMMARY "+
          str(record["raw_complete_target_count"])+"/10 CAPTURE_ONLY_NOT_INDEPENDENT_HARDWARE_PROOF")
    return record

if __name__=="__main__":
    require(len(sys.argv)==7,"usage original-triad-root ledger122-dir-file original-source-batch-dir repo-root compiled-FEX-guest-executable output")
    run(*map(Path,sys.argv[1:]))
