#!/usr/bin/env python3
"""SHA-pinned original GNU DT_RELA[65..84] 20 independent source-only test plans.

This is a CONCURRENT REGRESSION/Fault-isolation batch, NOT 20 relocations
running in one FEX process and NOT extra certified source targets. All 147
individual original relocation targets were already certified; this rechecks
their real native hardware stores without inflating the process-level gate.
"""
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA,LDSO_SHA,decode_original_libc,classify,
)
from kernix_g0_original_dt_rela29_source_type_and_writer_plan_after_91 import original_dynsym
from kernix_g0_original_globdat_batch71_80_source_after131 import original_zero_memory_backing
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import LIBC_BIAS,GUEST_MAIN

INDICES=list(range(65,85))
TYPES={1:"R_X86_64_64",6:"R_X86_64_GLOB_DAT"}
SCHEMA="kernix.g0.parallel20.original-gnu-rela65-84-source-only-independent-native-process-plan.v1"
OUT="KERNIX-G0-Parallel20-Original-GNU-RELA65-84-SOURCE-ONLY.json"

def need(ok,msg):
    if not ok:raise AssertionError("KERNIX_G0_PARALLEL20_ORIGINAL_SOURCE_FAIL_CLOSED: "+msg)
def regular(p:Path,maxbytes=2800000):
    need(p.is_file() and not p.is_symlink(),"real immutable source file "+str(p))
    b=p.read_bytes()
    need(0<len(b)<=maxbytes,"bounded original source "+str(p))
    return b

def gdb_script(index:int,target:str,kind:str,host_line:int):
    need(index in INDICES and kind in TYPES.values(),"one original ELF relocation")
    label=f"KERNIX_G0_ORIGINAL_RELA{index}"
    # Exact same original source watch source semantics as source71..80.
    s=("set pagination off\nset confirm off\nset breakpoint pending on\n"
       "handle SIGBUS nostop noprint pass\nhandle SIGCHLD nostop noprint pass\n"
       f"break {GUEST_MAIN}:{host_line}\ncommands\nsilent\n"
       f'printf "{label}_SOURCE_ARM type={kind} target={target} initial=0x0 SOURCE_ONLY=1\\n"\n'
       f"x/gx {target}\n"
       f"watch -location *(unsigned long long *){target}\n"
       "condition 2 $pc >= 0xffff00000000 && $x28 >= 0xffff00000000\n"
       "continue\nend\nrun\n"
       f'printf "{label}_RAW_HIT target={target} pc=0x%lx x4=0x%lx x13=0x%lx x28=0x%lx NOT_CERTIFIED=1\\n",$pc,$x4,$x13,$x28\n'
       f"x/gx {target}\nx/i $pc-4\n"
       f'printf "{label}_ZERO_NATIVE_CERTIFICATION_FROM_SOURCE_DISCOVERY=1\\n"\n'
       "quit\n")
    need(s.count(f"{label}_SOURCE_ARM")==1 and s.count(f"{label}_RAW_HIT")==1,
         "single real ARM64 host source GDB breakpoint and actual native target")
    return s

def build(triad:Path,canonical147:Path,repo:Path,out:Path):
    libc=regular(triad/"lib/x86_64-linux-gnu/libc.so.6")
    ldso=regular(triad/"lib64/ld-linux-x86-64.so.2",600000)
    need(len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA,
         "true GNU original libc exact bytes SHA256")
    need(len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA,
         "true GNU original ld-linux original bytes SHA256")
    rows=decode_original_libc(libc)
    need(classify(rows)["original_total_RELA_and_JMPREL"]==147 and len(rows)==147,
         "original GNU source 147 relocation tuples, nothing synthesized")
    ledger=json.loads(regular(canonical147))
    need(ledger["schema"]=="kernix.g0.original-gnu-libc-147-distinct-source-writer-receipts-specialized-dtrela44-after146.v1"
         and ledger["original_relocations_total"]==147
         and ledger["source_original_libc_sha256"]==LIBC_SHA
         and ledger["source_original_ldso_sha256"]==LDSO_SHA
         and ledger["previously_attested_original_source_indices"]==list(range(147))
         and ledger["previously_independently_attested_native_writer_target_count"]==147
         and ledger["remaining_requires_separate_native_hardware_evidence"]==0
         and ledger["all_147_same_guest_native_execution_proven"] is False
         and ledger["Android_Bionic_Wine_Proton_games_proven"] is False,
         "canonical individually proven 147 original sources, no same-process claim")
    host=repo/GUEST_MAIN
    need(host.is_file() and not host.is_symlink(),"actual native FEX guest driver source")
    lines=[i for i,line in enumerate(host.read_text().splitlines(),1)
           if line.strip()=="++RealOriginalLdsoLibcCloses;"]
    need(len(lines)==1,"single genuine FEX host breakpoint before GNU relocation loop")
    out.mkdir(parents=True,exist_ok=True)
    manifest=[]
    targetset=set()
    for index in INDICES:
        r=rows[index]
        need(r["index"]==index and r["table"]=="DT_RELA" and r["table_index"]==index
             and r["r_type"] in TYPES and r["original_source_qword"]=="0x0",
             "original GNU source source index and relocation type 65..84 "+str(index))
        target=r["source_guest_target"]
        need(target==hex(LIBC_BIAS+int(r["r_offset"],16))
             and target not in targetset,"unique SHA original GNU ELF target "+str(index))
        targetset.add(target)
        old=ledger["original_147_relocation_source_records"][index]
        need(old["source_index"]==index
             and old["source_table"]=="DT_RELA"
             and old["source_table_ordinal"]==index
             and old["source_relocation_type"]==TYPES[r["r_type"]]
             and old["original_source_guest_target"]==target
             and old["original_source_file_old_qword"]=="0x0",
             "exact original independent canonical source row "+str(index))
        sym=original_dynsym(libc,r["r_sym"]) if r["r_sym"] else None
        need(sym is not None and sym["symbol_index"]==r["r_sym"],
             "original source dynsym definition "+str(index))
        backing=original_zero_memory_backing(libc,int(r["r_offset"],16))
        source_script=gdb_script(index,target,TYPES[r["r_type"]],lines[0])
        script_name=f"original-gnu-dtrela{index}-source-only.gdb"
        (out/script_name).write_text(source_script)
        candidate=sym["source_definition_address_candidate_if_non_TLS"]
        # A source symbol candidate does NOT prove scope/versioning or runtime
        # preemption; signed addends for R_X86_64_64 must not be dropped.
        expected=((int(candidate,16)+(int(r["r_addend"]) if r["r_type"]==1 else 0))
                  & ((1<<64)-1)) if candidate is not None else None
        manifest.append({
          "index":index,"table":"DT_RELA","source_type":TYPES[r["r_type"]],
          "source_type_id":r["r_type"],"signed_addend":r["r_addend"],
          "target":target,"symbol_index":r["r_sym"],
          "symbol_name":sym["symbol_name"],"source_dynsym":sym,
          "candidate_symbol_resolution_without_full_interposition_proof":candidate,
          "expected_candidate_plus_signed_addend_if_defined":hex(expected) if expected is not None else None,
          "source_original_qword":"0x0","original_memory_backing":backing,
          "source_gdb_script":script_name,
          "source_gdb_sha256":hashlib.sha256(source_script.encode()).hexdigest(),
          "each_native_FEX_process_isolated":True,
          "new_independently_certified_target_writers":0,
        })
    need(len(manifest)==len(targetset)==20 and [r["index"] for r in manifest]==INDICES,
         "twenty distinct SHA original GNU source indices")
    output={
      "schema":SCHEMA,
      "source_original_libc_sha256":LIBC_SHA,
      "source_original_ldso_sha256":LDSO_SHA,
      "original_total_relocation_source_indices":147,
      "original_source_indices":INDICES,
      "twenty_independently_isolated_GNU_source_targets":manifest,
      "number_of_separate_native_case_jobs_requested":20,
      "one_compiled_original_FEXCore_shared_from_preparation_job":True,
      "max_parallel_original_gdb_case_jobs":20,
      "matrix_fail_fast":False,
      "new_certified_individual_source_writers":0,
      "same_guest_process_20_targets_proven":False,
      "all_147_same_guest_native_execution_proven":False,
      "full_original_libc_147_process_relocation_closure_proven":False,
      "Android_Bionic_Wine_Proton_games_proven":False,
    }
    (out/OUT).write_text(json.dumps(output,indent=2)+"\n")
    for r in manifest:
        print(f"KERNIX_G0_PARALLEL20_SOURCE index={r['index']} type={r['source_type']}"
              f" symbol={r['symbol_name']} target={r['target']} expected={r['expected_candidate_plus_signed_addend_if_defined']}"
              " SOURCE_ONLY_NO_NEW_NATIVE_PROOF",flush=True)
    return output

if __name__=="__main__":
    need(len(sys.argv)==5,"usage SHA_original_GNU_triad canonical_147_individual_source_ledger repository_root output_dir")
    build(*map(Path,sys.argv[1:]))
