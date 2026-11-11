#!/usr/bin/env python3
"""Original SHA GNU libc 147 unique source-writer ledger, 147th from source44.

The 147 receipts attest real ARM64 FEX native relocation stores at distinct
original GNU source targets in separate runs, NOT the closure of all relocations
in one guest process, all dynamic-loader symbol semantics, or running games.
"""
from __future__ import annotations
import hashlib,json,re,sys
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA,LDSO_SHA,decode_original_libc,classify
)
SCHEMA="kernix.g0.original-gnu-libc-147-distinct-source-writer-receipts-specialized-dtrela44-after146.v1"
PROOF_SCHEMA="kernix.g0.original-gnu-rela44-two-separate-arm64-fex-awatch-independent-writer.v1"
OUT="KERNIX-G0-Original-147-Source-Writers-147-Distinct-Native-Proofs-No-Full-Loader-Claim.json"

def need(ok,msg):
    if not ok:raise AssertionError("KERNIX_G0_147_ORIGINAL_SOURCE44_FINAL_LEDGER_FAIL_CLOSED: "+msg)

def read(p:Path,cap:int=2500000)->bytes:
    need(p.is_file() and not p.is_symlink(),"regular immutable original source "+str(p))
    x=p.read_bytes()
    need(0<len(x)<=cap,"source/proof bytes in bounds "+str(p))
    return x

def main(triad:Path,prior146_file:Path,source44_receipt:Path,out:Path)->dict:
    libc=read(triad/"lib/x86_64-linux-gnu/libc.so.6")
    ldso=read(triad/"lib64/ld-linux-x86-64.so.2")
    need(hashlib.sha256(libc).hexdigest()==LIBC_SHA
         and hashlib.sha256(ldso).hexdigest()==LDSO_SHA,
         "original GNU libc and ldso exact SHA256 source ELF")
    rows=decode_original_libc(libc)
    need(classify(rows)["original_total_RELA_and_JMPREL"]==147
         and len(rows)==147,"exactly 147 original ELF64 relocation source tuples")
    original44=rows[44]
    need(original44["source_guest_target"]=="0x804202eb0"
         and original44["r_type"]==6
         and original44["r_sym"]==7
         and original44["original_source_qword"]=="0x0",
         "unmodified exact original GNU R_X86_64_GLOB_DAT _rtld_global_ro target44")
    p=json.loads(read(prior146_file))
    need(p["schema"]==
         "kernix.g0.original-gnu-147-native-writer-source-ledger-specialized-tpoff64-63-after145.v1"
         and p["source_original_libc_sha256"]==LIBC_SHA
         and p["source_original_ldso_sha256"]==LDSO_SHA
         and p["original_relocations_total"]==147
         and p["previously_independently_attested_native_writer_target_count"]==146
         and p["remaining_requires_separate_native_hardware_evidence"]==1
         and p["remaining_non_IFUNC_DT_RELA_indices"]==[44]
         and p["remaining_IFUNC_indices"]==[]
         and p["native_TLS63_original_signed_TPOFF64_minus72_source_writer_independently_proven"] is True
         and p["full_TLS_module_offset_semantics_and_thread_allocation_proven"] is False
         and p["independent_new_batch_source_indices_certified"]==[63]
         and p["all_147_same_guest_native_execution_proven"] is False
         and p["Android_Bionic_Wine_Proton_games_proven"] is False,
         "current SHA-certified 146 native source writers, exactly only unresolved original index44")
    old=p["previously_attested_original_source_indices"]
    need(len(old)==len(set(old))==146 and set(range(147))-set(old)=={44},
         "original unique per-source writer indices, no duplicate 44")
    record=p["original_147_relocation_source_records"]
    need(len(record)==147
         and record[44]["source_index"]==44
         and record[44]["source_table"]=="DT_RELA"
         and record[44]["source_table_ordinal"]==44
         and record[44]["source_relocation_type"]=="R_X86_64_GLOB_DAT"
         and record[44]["original_source_guest_target"]==original44["source_guest_target"]
         and record[44]["original_source_file_old_qword"]==original44["original_source_qword"],
         "per-index independent GNU original 147 source tuple equality")
    proof=json.loads(read(source44_receipt))
    expected={
        "schema":PROOF_SCHEMA,
        "original_source_index":44,
        "source_original_libc_sha256":LIBC_SHA,
        "source_original_ldso_sha256":LDSO_SHA,
        "original_relocation_type":"R_X86_64_GLOB_DAT",
        "original_symbol":"_rtld_global_ro",
        "original_guest_target":"0x804202eb0",
        "original_native_written_value":"0x801037aa0",
        "two_separate_original_native_AWATCH_GDB_processes":True,
        "raw_guest_process_provenance_run_ids":[43058296364,43062041734],
        "raw_guest_process_provenance_artifact_ids":[13872068529,13873374524],
        "byte_identical_deterministic_logs_permitted":True,
        "independently_falsified_traces_rejected":32,
        "native_ARM64_source_writer_independently_attested":True,
        "watch_only_guest_run_known_fail_closed":True,
        "full_GLOB_DAT_scope_preemption_versioning_proven":False,
        "all_147_same_guest_native_execution_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    need(all(proof.get(k)==v for k,v in expected.items()),
         "exact two separately archived original FEX native hardware AWATCH receipts for _rtld_global_ro, 32 adversarial negatives")
    hashes=proof.get("original_native_AWATCH_process_log_sha256")
    need(isinstance(hashes,list) and len(hashes)==2
         and all(isinstance(h,str) and re.fullmatch("[0-9a-f]{64}",h)
                 for h in hashes),
         "both individual true ARM64 GDB AWATCH log SHA256; deterministic identical log bytes allowed")
    ids=proof["raw_guest_process_provenance_run_ids"]
    art=proof["raw_guest_process_provenance_artifact_ids"]
    need(len(ids)==len(set(ids))==2 and len(art)==len(set(art))==2,
         "separate real independently archived original FEX runners, not two hits in one run")
    done=sorted(set(old)|{44})
    remain=[i for i in range(147) if i not in done]
    need(len(done)==147 and remain==[],"147 distinct source writers, zero missing source index")
    done_set=set(done)
    for entry in record:
        need(entry["source_index"] in done_set,"all 147 original source index records remain present")
        entry["native_writer_ledger_reference"]="PREVIOUSLY_INDEPENDENTLY_ATTESTED_147_TARGET_LEDGER_REFERENCE"
        entry["new_runtime_native_hardware_proof_generated_by_this_batch"]=False
    for group in p["source_cohort_release_groups"]:
        g=set(group["original_indices"])
        group["previously_independently_certified_target_count"]=len(g&done_set)
        group["remaining_separate_native_target_evidence_count"]=len(g-done_set)
    p.update({
        "schema":SCHEMA,
        "independent_new_batch_source_indices_certified":[44],
        "independent_new_batch_source_indices_quarantined":[],
        "independently_audited_original_DTRELA44_two_separate_AWATCH_native_guest_processes":True,
        "independently_audited_original_DTRELA44_true_hardware_writer_and_source_value":"0x801037aa0",
        "original_DTRELA44_independent_writer_audit_provenance":
            "https://github.com/RM11Cor/RM11-WinCore/actions/runs/43067719901",
        "original_DTRELA44_native_hardware_proof_two_archived_run_ids":ids,
        "original_DTRELA44_native_hardware_proof_two_archived_artifact_ids":art,
        "original_DTRELA44_native_hardware_proof_two_SHA256":hashes,
        "original_DTRELA44_raw_watch_only_run_known_fail_closed":True,
        "original_DTRELA44_awatch_adversarial_trace_rejections":32,
        "independent_verified_target_receipts_from_batch":1,
        "previously_independently_attested_native_writer_target_count":147,
        "previously_attested_original_source_indices":done,
        "remaining_requires_separate_native_hardware_evidence":0,
        "remaining_non_IFUNC_DT_RELA_indices":[],
        "remaining_IFUNC_indices":[],
        "full_GLOB_DAT_dynamic_symbol_scope_preemption_and_versioning_proven":False,
        "full_TLS_module_offset_semantics_and_thread_allocation_proven":False,
        "new_native_hardware_attestations_in_this_source_inventory":0,
        "new_hardware_writer_attestations_from_this_batch":0,
        "new_GNU_CALL_RET_stack_READ_attestations_from_this_batch":0,
        "all_147_same_guest_native_execution_proven":False,
        "original_libc_all_147_same_process_relocation_closure_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    })
    need(sum(g["previously_independently_certified_target_count"]
             for g in p["source_cohort_release_groups"])==147
         and sum(g["remaining_separate_native_target_evidence_count"]
                 for g in p["source_cohort_release_groups"])==0,
         "all original GNU ELF type cohorts reconcile 147 individual native writers")
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(p,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_GNU_ALL_147_INDIVIDUALLY_INDEPENDENT_NATIVE_WRITER_TARGETS_CERTIFIED",
          "147/147, 0_pending, original44_dual_AWATCH_32_adversarial=1",
          "all_147_in_one_process_proven=0 Android_proven=0 full_loader=0")
    return p

if __name__=="__main__":
    need(len(sys.argv)==5,"usage original GNU triad canonical146 source44 independent AWATCH receipt output")
    main(*map(Path,sys.argv[1:]))
