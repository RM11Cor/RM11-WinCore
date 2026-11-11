#!/usr/bin/env python3
"""G0-L40-A original GNU ELF SHA-pinned 40-target one-process source plan ONLY.

Stage A covers 0..39, with 10 bounded windows of at most four active
native GDB hardware watchpoints in one continuous FEX inferior.  Read
original ELF semantics, not 40 preexisting separate native proofs as if
they were from a single guest. No 40 same-process claim from this module.
"""
from __future__ import annotations
import hashlib,json,sys
from collections import Counter
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA,LDSO_SHA,decode_original_libc,classify,
)
from kernix_g0_original_dt_rela29_source_type_and_writer_plan_after_91 import original_dynsym
from kernix_g0_original_globdat_batch41_50_source_after103 import original_zero_memory_backing
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import LIBC_BIAS,GUEST_MAIN

SCHEMA="kernix.g0.l40a.authentic-original-gnu-dtrela0-39-ten-four-target-windows-source-only.v1"
OUT="KERNIX-G0-L40-A-Original-GNU-RELA0-39-40-Typed-Relocations-10-Windows-SOURCE-ONLY.json"
INDICES=list(range(40))
TYPES={1:"R_X86_64_64",6:"R_X86_64_GLOB_DAT",18:"R_X86_64_TPOFF64",37:"R_X86_64_IRELATIVE"}
def require(ok,msg):
    if not ok:raise AssertionError("KERNIX_G0_L40_A_SOURCE_FAIL_CLOSED: "+msg)
def read(p,limit=2500000):
    require(p.is_file() and not p.is_symlink(),"immutable regular source "+str(p))
    data=p.read_bytes()
    require(0<len(data)<=limit,"bounded GNU source "+str(p))
    return data

def build(triad:Path,certified147:Path,repository:Path,out:Path):
    libc=read(triad/"lib/x86_64-linux-gnu/libc.so.6")
    ldso=read(triad/"lib64/ld-linux-x86-64.so.2",600000)
    require(len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA,
            "genuine original GNU libc SHA256")
    require(len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA,
            "genuine original GNU loader SHA256")
    source=decode_original_libc(libc)
    meta=classify(source)
    require(len(source)==147 and meta["original_total_RELA_and_JMPREL"]==147,
            "authentic ELF 147 source relocation indexes")
    ledger=json.loads(read(certified147))
    require(
         ledger["schema"]=="kernix.g0.original-gnu-libc-147-distinct-source-writer-receipts-specialized-dtrela44-after146.v1"
         and ledger["source_original_libc_sha256"]==LIBC_SHA
         and ledger["source_original_ldso_sha256"]==LDSO_SHA
         and ledger["original_relocations_total"]==147
         and ledger["previously_attested_original_source_indices"]==list(range(147))
         and ledger["previously_independently_attested_native_writer_target_count"]==147
         and ledger["remaining_requires_separate_native_hardware_evidence"]==0
         and ledger["all_147_same_guest_native_execution_proven"] is False
         and ledger["Android_Bionic_Wine_Proton_games_proven"] is False,
         "147 independently proven ORIGINAL writer targets, not same process")
    entries=ledger["original_147_relocation_source_records"]
    require(len(entries)==147,"exact all147 canonical source records")
    host=repository/GUEST_MAIN
    require(host.is_file() and not host.is_symlink(),"original unchanged FEX host driver")
    marker=[i for i,x in enumerate(host.read_text().splitlines(),1) if x.strip()=="++RealOriginalLdsoLibcCloses;"]
    require(len(marker)==1,"unique real FEX host stop point before original GNU relocation execution")
    records=[]
    targets=set()
    for index in INDICES:
        r=source[index]
        require(r["index"]==index and r["table"]=="DT_RELA"
                and r["table_index"]==index and r["r_type"] in TYPES
                and r["original_source_qword"]=="0x0",
                "untouched original DT_RELA source index "+str(index))
        target=r["source_guest_target"]
        require(target==hex(LIBC_BIAS+int(r["r_offset"],16)) and target not in targets,
                "SHA-pinned unique real ELF guest target "+str(index))
        targets.add(target)
        old=entries[index]
        require(old["source_index"]==index
                and old["source_table"]=="DT_RELA"
                and old["source_table_ordinal"]==index
                and old["source_relocation_type"]==TYPES[r["r_type"]]
                and old["original_source_guest_target"]==target
                and old["original_source_file_old_qword"]==r["original_source_qword"],
                "match original source against independent 147 target ledger")
        sym=original_dynsym(libc,r["r_sym"]) if r["r_sym"] else None
        if r["r_sym"]:
            require(sym is not None and sym["symbol_index"]==r["r_sym"],
                    "actual original GNU symtab entry "+str(index))
        candidate=sym["source_definition_address_candidate_if_non_TLS"] if sym else None
        records.append({
           "index":index,
           "source_table":r["table"],"source_ordinal":r["table_index"],
           "type_id":r["r_type"],"type":TYPES[r["r_type"]],
           "symbol_index":r["r_sym"],"symbol_name":sym["symbol_name"] if sym else None,
           "original_signed_addend":r["r_addend"],
           "original_relocation_offset":r["r_offset"],
           "original_guest_target":target,"original_qword":"0x0",
           "source_symbol_address_candidate_if_non_TLS":candidate,
           "original_zero_memory_backing":original_zero_memory_backing(libc,int(r["r_offset"],16)),
           "window_number":index//4+1,
           "window_slot":index%4,
           "guest_interpreter_exact_type_specific_write_and_CPU_register_proof_required":True,
           "native_hardware_observation":None,
           "same_FEX_guest_process_proven":False,
        })
    windows=[]
    for start in range(0,40,4):
        indexes=list(range(start,start+4))
        windows.append({
           "window":start//4+1,"source_indices":indexes,
           "exact_original_guest_targets":[records[i]["original_guest_target"] for i in indexes],
           "watch_slots_at_most":4,
           "rearm_at_verified_stopped_same_FEX_inferior":start>0,
           "no_late_arming_after_original_guest_store":True,
           "same_process_native_hardware_pass":False,
        })
    require(len(records)==40 and len(targets)==40 and len(windows)==10,"40 distinct original source targets in ten windows")
    require([i for w in windows for i in w["source_indices"]]==INDICES,"no skipped or duplicated source index")
    counts=dict(sorted(Counter(r["type"] for r in records).items()))
    # Never claim particular ABI layouts until true GDB/ARM64 native CPU evidence.
    out.mkdir(parents=True,exist_ok=True)
    doc={
       "schema":SCHEMA,"original_libc_sha256":LIBC_SHA,"original_loader_sha256":LDSO_SHA,
       "original_canonical_source_relocation_total":147,
       "prior_individually_certified_source_writer_count":147,
       "stage":"G0-L40-A","stage_original_source_indices":INDICES,
       "typed_source_counts":counts,
       "original_40_source_records":records,
       "ten_bounded_four-watchpoint_windows":windows,
       "one_fresh_real_linux_ARM64_FEX_inferior_required":True,
       "source_arming_anchor":GUEST_MAIN,"source_arming_line":marker[0],
       "single_process_journal_required":True,
       "per_target_failed_or_unobserved_diagnostic_required":True,
       "new_same_guest_process_native_writers_proven":0,
       "stage_40_source_native_hardware_writes_in_one_PID_proven":False,
       "all_147_same_guest_native_execution_proven":False,
       "full_original_libc_147_process_relocation_closure_proven":False,
       "Android_Bionic_Wine_Proton_games_proven":False,
    }
    (out/OUT).write_text(json.dumps(doc,indent=2)+"\n")
    print("KERNIX_G0_L40_A_TRUE_GNU_40_TYPED_RELOCATIONS_SOURCE_ONLY",
          "types="+json.dumps(counts,sort_keys=True),
          "windows=10", "previous_individual=147",
          "new_same_PID_hardware_proofs=0",flush=True)
    return doc

if __name__=="__main__":
    require(len(sys.argv)==5,"usage genuine_original_GNU_guest_triad exact_147_individual_receipts repo_root output_dir")
    build(*map(Path,sys.argv[1:]))
