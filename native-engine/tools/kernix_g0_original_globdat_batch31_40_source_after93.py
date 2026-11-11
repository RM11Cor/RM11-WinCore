#!/usr/bin/env python3
"""Source-only GNU libc DT_RELA31..40 ten-target manifest after certified 93.

Each original relocation is independently identified from SHA-locked genuine ELF,
not from copied constants. Zero runtime certification from this source scan.
"""
from __future__ import annotations
import hashlib, json, sys
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA,decode_original_libc,classify
from kernix_g0_original_dt_rela29_source_type_and_writer_plan_after_91 import original_dynsym
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import LIBC_BIAS,GUEST_MAIN

INDICES=list(range(31,41))
SCHEMA="kernix.g0.original-gnu-libc-globdat-ten-original-source-targets31-40-after-93.v1"
SOURCE_NAME="KERNIX-G0-Original-GNU-DTRELA31-40-Source-Batch-Only-No-Native-Proof.json"

def require(ok,what):
    if not ok: raise AssertionError("KERNIX_G0_GLOBDAT_BATCH31_40_SOURCE_FAIL_CLOSED: "+what)

def read(p:Path,maximum:int=2500000):
    require(p.is_file() and not p.is_symlink(),"source input file "+str(p))
    b=p.read_bytes()
    require(0<len(b)<=maximum,"bounded input "+str(p))
    return b

def make_gdb(index:int,target:str,kind:str,host_line:int)->str:
    require(index in INDICES and kind in ("R_X86_64_GLOB_DAT","R_X86_64_64","R_X86_64_TPOFF64"),"one original typed ELF source")
    marker=f"KERNIX_G0_ORIGINAL_RELA{index}"
    return (
      "set pagination off\nset confirm off\nset breakpoint pending on\n"
      "handle SIGBUS nostop noprint pass\nhandle SIGCHLD nostop noprint pass\n"
      f"break {GUEST_MAIN}:{host_line}\n"
      "commands\nsilent\n"
      f'printf "{marker}_SOURCE_ARM type={kind} target={target} initial=0x0 SOURCE_ONLY=1\\n"\n'
      f"x/gx {target}\n"
      f"watch -location *(unsigned long long *){target}\n"
      "condition 2 $pc >= 0xffff00000000 && $x28 >= 0xffff00000000\n"
      "continue\nend\nrun\n"
      f'printf "{marker}_RAW_HIT target={target} pc=0x%lx x4=0x%lx x13=0x%lx x28=0x%lx NOT_CERTIFIED=1\\n",$pc,$x4,$x13,$x28\n'
      f"x/gx {target}\n"
      "x/i $pc-4\n"
      f'printf "{marker}_ZERO_NATIVE_CERTIFICATION_FROM_SOURCE_DISCOVERY=1\\n"\n'
      "quit\n"
    )

def run(triad:Path,prior93:Path,repository:Path,dist:Path)->dict:
    libc=read(triad/"lib/x86_64-linux-gnu/libc.so.6")
    ldso=read(triad/"lib64/ld-linux-x86-64.so.2",500000)
    require(len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA,"original GNU libc exact SHA")
    require(len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA,"original GNU ldso exact SHA")
    rows=decode_original_libc(libc)
    require(classify(rows)["original_total_RELA_and_JMPREL"]==147,"exact source 147")
    prior=json.loads(read(prior93))
    require(prior["schema"]=="kernix.g0.original-gnu-libc-147-relocation-cohort-native-writer-ledger93.v1"
            and prior["source_original_libc_sha256"]==LIBC_SHA
            and prior["source_original_ldso_sha256"]==LDSO_SHA
            and prior["original_relocations_total"]==147
            and prior["previously_independently_attested_native_writer_target_count"]==93
            and prior["remaining_requires_separate_native_hardware_evidence"]==54
            and prior["remaining_non_IFUNC_DT_RELA_indices"]==list(range(31,85))
            and prior["remaining_IFUNC_indices"]==[]
            and prior["native_GNU_DT_RELA30_GLOBDAT_sym1584_loc2_REAL_FEX_ARM64_STORE_independently_proven"] is True
            and prior["all_147_same_guest_native_execution_proven"] is False
            and prior["Android_Bionic_Wine_Proton_games_proven"] is False,
            "SHA-matched independently certified 93 prior original targets")
    certified=prior["previously_attested_original_source_indices"]
    require(len(set(certified))==len(certified)==93 and not (set(INDICES)&set(certified)),
            "ten distinct uncounted source indices")
    require(len(prior["original_147_relocation_source_records"])==147,"full 147 preserved source rows")
    host=repository/GUEST_MAIN
    require(host.is_file() and not host.is_symlink(),"original unchanged FEX GNU native host driver")
    markers=[i for i,line in enumerate(host.read_text().splitlines(),1)
             if line.strip()=="++RealOriginalLdsoLibcCloses;"]
    require(len(markers)==1,"unique FEX driver before original relocation writer")
    dist.mkdir(parents=True,exist_ok=True)
    manifest=[]
    targets=set()
    TYPES={1:"R_X86_64_64",6:"R_X86_64_GLOB_DAT",18:"R_X86_64_TPOFF64"}
    for index in INDICES:
        r=rows[index]
        require(r["index"]==index and r["table"]=="DT_RELA" and r["table_index"]==index
                and r["r_type"] in TYPES and r["r_sym"]>=0
                and r["original_source_qword"]=="0x0",
                f"original source {index} must be supported GNU nonIFUNC type")
        target=r["source_guest_target"]
        require(target==hex(LIBC_BIAS+int(r["r_offset"],16)) and target not in targets,
                f"distinct original GNU source target {index}")
        targets.add(target)
        loc=source_offset(libc,int(r["r_offset"],16),8,r["r_type"],nonexec=True)
        require(libc[loc:loc+8]==bytes(8), f"unmodified original {index} target qword")
        prev=prior["original_147_relocation_source_records"][index]
        require(prev["source_index"]==index
                and prev["source_table"]=="DT_RELA"
                and prev["source_table_ordinal"]==index
                and prev["source_relocation_type"]==TYPES[r["r_type"]]
                and prev["original_source_guest_target"]==target
                and prev["original_source_file_old_qword"]=="0x0",
                f"index {index} exact source cohort source parity")
        sym=original_dynsym(libc,r["r_sym"]) if r["r_sym"] else None
        require((sym is None and r["r_sym"]==0) or (sym is not None and sym["symbol_index"]==r["r_sym"] and sym["symbol_name"]),
                f"original ELF dynamic symbol {index}")
        rec={
            "index":index, "table":"DT_RELA", "table_index":index,
            "relocation_type":TYPES[r["r_type"]], "relocation_type_id":r["r_type"],
            "relocation_offset":r["r_offset"], "symbol_index":r["r_sym"],
            "symbol":sym, "signed_addend":r["r_addend"], "target":target,
            "initial_qword":"0x0", "full_runtime_symbol_preemption_proven":False,
            "separately_native_writer_proven":False,
        }
        manifest.append(rec)
        gdb=make_gdb(index,target,rec["relocation_type"],markers[0])
        require(gdb.count("watch -location *(unsigned long long *)"+target)==1
                and gdb.count(f"KERNIX_G0_ORIGINAL_RELA{index}_RAW_HIT")==1,
                f"unique original source watch index {index}")
        (dist/f"original-gnu-dtrela{index}-source-only.gdb").write_text(gdb)
    require(len(manifest)==len(targets)==10 and [r["index"] for r in manifest]==INDICES,
            "exact ten independent original source targets 31..40")
    output={
        "schema":SCHEMA,
        "original_source_libc_sha256":LIBC_SHA,"original_source_ldso_sha256":LDSO_SHA,
        "original_relocations_total":147,
        "prior_independently_certified_original_writer_count":93,
        "remaining_requires_individual_hardware_proof":54,
        "original_source_indices":INDICES,
        "ten_original_gnu_source_relocation_metadata":manifest,
        "new_native_hardware_writer_target_attestations_from_source_scan":0,
        "all_147_same_guest_native_execution_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    (dist/SOURCE_NAME).write_text(json.dumps(output,indent=2)+"\n")
    for rec in manifest:
        sym=rec["symbol"]
        print(f"KERNIX_G0_BATCH31_40_SOURCE index={rec['index']} type={rec['relocation_type']} symbol={(sym or {}).get('symbol_name','NONE')}"
              f" sym={rec['symbol_index']} addend={rec['signed_addend']} target={rec['target']} candidate="
              f"{(sym or {}).get('source_definition_address_candidate_if_non_TLS') or 'UNDEFINED'}"
              " NO_NATIVE_PROOF=1")
    return output

if __name__=="__main__":
    require(len(sys.argv)==5,"usage ORIGINAL_TRIAD CERTIFIED_LEDGER93 REPO_ROOT OUTPUT")
    run(*map(Path,sys.argv[1:]))
