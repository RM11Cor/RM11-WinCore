#!/usr/bin/env python3
"""Reconcile authentic GNU all-147 source ledger after four independently audited targets.

Each accepted source index has its own two native WATCH/AWATCH hardware process
receipts and 16 falsified cases rejected. Failing targets stay pending; their
successful siblings are NOT replayed or downgraded.
"""
from __future__ import annotations
import hashlib
import json
import re
import sys
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA,decode_original_libc,classify
from kernix_g0_original_dt_rela29_source_type_and_writer_plan_after_91 import original_dynsym
from kernix_g0_original_batch81_84_source_after141 import (
    INDICES,original_zero_memory_backing,
)
from kernix_g0_original_batch81_84_native_independent_gate import (
    SCHEMA_PROOF,
)
SCHEMA="kernix.g0.original-gnu-libc-147-native-writer-ledger-conditional-four-target-batch81-84-after141.v1"

def need(ok,msg):
    if not ok:raise AssertionError("KERNIX_G0_BATCH81_84_147_SOURCE_LEDGER_FAIL_CLOSED: "+msg)

def load(path:Path,maximum:int=2500000):
    need(path.is_file() and not path.is_symlink(),"original authentic input "+str(path))
    data=path.read_bytes()
    need(0<len(data)<=maximum,"bounded original immutable input "+str(path))
    return data

def run(triad:Path,prior141:Path,audit:Path,out:Path)->dict:
    libc=load(triad/"lib/x86_64-linux-gnu/libc.so.6")
    ldso=load(triad/"lib64/ld-linux-x86-64.so.2")
    need(len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA,
         "unchanged original GNU libc source SHA")
    need(len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA,
         "unchanged original GNU loader source SHA")
    rows=decode_original_libc(libc)
    need(classify(rows)["original_total_RELA_and_JMPREL"]==147,
         "all original 147 relocation sources")
    previous=json.loads(load(prior141))
    need(previous["schema"]=="kernix.g0.original-gnu-libc-147-native-writer-ledger-conditional-ten-target-batch71-80-after131.v1"
         and previous["source_original_libc_sha256"]==LIBC_SHA
         and previous["source_original_ldso_sha256"]==LDSO_SHA
         and previous["original_relocations_total"]==147
         and previous["previously_independently_attested_native_writer_target_count"]==141
         and previous["remaining_requires_separate_native_hardware_evidence"]==6
         and previous["remaining_non_IFUNC_DT_RELA_indices"]==[44,63]+list(range(81,85))
         and previous["remaining_IFUNC_indices"]==[]
         and previous["native_GNU_DT_RELA30_GLOBDAT_sym1584_loc2_REAL_FEX_ARM64_STORE_independently_proven"] is True
         and previous["independent_new_batch_source_indices_certified"]==list(range(71,81))
         and previous["independent_new_batch_source_indices_quarantined"]==[]
         and previous["all_147_same_guest_native_execution_proven"] is False
         and previous["Android_Bionic_Wine_Proton_games_proven"] is False,
         "certified unchanged prior 141 GNU native writers")
    old=previous["previously_attested_original_source_indices"]
    need(len(old)==len(set(old))==141 and not (set(old)&set(INDICES)),
         "none of new batch target indices already counted")
    need(len(previous["original_147_relocation_source_records"])==147,
         "preserve all original 147 source cohorts")
    proof=json.loads(load(audit))
    need(proof["schema"]==SCHEMA_PROOF
         and proof["original_source_libc_sha256"]==LIBC_SHA
         and proof["original_source_ldso_sha256"]==LDSO_SHA
         and proof["original_source_indices"]==INDICES
         and proof["original_relocations_total"]==147
         and proof["previously_certified_distinct_native_source_target_count"]==141
         and proof["no_duplicate_original_source_index_counted"] is True
         and proof["same_guest_all_4_native_writes_proven"] is False
         and proof["all_147_same_guest_native_execution_proven"] is False
         and proof["full_dynamic_symbol_preemption_and_versioning_proven"] is False
         and proof["Android_Bionic_Wine_Proton_games_proven"] is False,
         "original 141 ledger-compatible independent typed batch auditor")
    accepted=proof["independently_certified_source_indices"]
    denied=proof["uncertified_source_indices_with_isolated_failures"]
    need(len(accepted)==len(set(accepted)) and len(denied)==len(set(denied))
         and sorted(accepted+denied)==INDICES
         and not (set(accepted)&set(denied))
         and proof["new_independently_certified_distinct_native_source_target_count"]==len(accepted)
         and proof["combined_distinct_native_source_target_count_if_ledger_verifies"]==141+len(accepted)
         and proof["total_forged_hardware_negative_controls_rejected"]==16*len(accepted),
         "exact split of four original distinct source indices without unproven inflation")
    per=proof["per_original_source_index_evidence"]
    need(set(per)==set(map(str,INDICES)),"all four isolated original source target outcomes")
    for index in INDICES:
        item=per[str(index)]
        source=rows[index]
        prev=previous["original_147_relocation_source_records"][index]
        need(item["source_index"]==index
             and prev["source_index"]==index
             and prev["source_table"]=="DT_RELA"
             and prev["source_table_ordinal"]==index
             and prev["original_source_guest_target"]==source["source_guest_target"]
             and prev["original_source_file_old_qword"]==source["original_source_qword"],
             "previous SHA-locked individual original source index "+str(index))
        if index in denied:
            need(item["status"]=="QUARANTINED_NOT_CERTIFIED"
                 and item["new_native_hardware_writer_attestations"]==0
                 and "native_hardware_writer_receipt" not in item,
                 "failed original source index may not contain hardware proof")
            continue
        need(item["status"]=="INDEPENDENTLY_CERTIFIED"
             and item["new_native_hardware_writer_attestations"]==1,
             "accepted source index individually attested exactly one target")
        receipt=item["native_hardware_writer_receipt"]
        sym=original_dynsym(libc,source["r_sym"]) if source["r_sym"] else None
        symname=(sym or {}).get("symbol_name")
        candidate=(sym or {}).get("source_definition_address_candidate_if_non_TLS")
        target=source["source_guest_target"]
        v=receipt["native_observed_written_decimal"]
        need(receipt["source_index"]==index
             and receipt["original_source_relocation_type"]==prev["source_relocation_type"]
             and receipt["original_source_symbol_index"]==source["r_sym"]
             and receipt["original_source_symbol_name"]==symname
             and receipt["original_guest_hardware_write_target"]==target
             and receipt["original_guest_old_qword"]=="0x0"
             and receipt["native_observed_written_qword"]==hex(v)
             and isinstance(v,int) and 0<v<2**64
             and receipt["original_symbol_ELF_candidate"]==candidate
             and (candidate is None or v==int(candidate,16))
             and receipt["original_source_memory_backing"]==
                 original_zero_memory_backing(libc,int(source["r_offset"],16))
             and receipt["native_real_AArch64_store"]=="stlr x13, [x4]"
             and receipt["native_source_value_register"]=="x13"
             and receipt["native_target_address_register"]=="x4"
             and receipt["native_source_register_value"]==hex(v)
             and receipt["native_target_register_value"]==target
             and receipt["original_GNU_x86_loader_JIT_entry"]=="0x80100fb8b"
             and receipt["original_GNU_x86_loader_store_opcode"]=="4c8908"
             and receipt["native_real_FEX_JIT_instruction_count"]==2
             and receipt["source_x86_to_arm64_hardware_writer_independently_proven"] is True
             and receipt["two_separate_native_arm64_fex_processes_independently_verified"] is True
             and receipt["full_dynamic_symbol_scope_preemption_and_versioning_proven"] is False
             and receipt["all_147_same_guest_native_execution_proven"] is False
             and receipt["Android_Bionic_Wine_Proton_games_proven"] is False,
             "per-index actual x86 GNU source, native register chronology and independent ARM64 hardware proof")
        negatives=receipt["sixteen_falsified_native_hardware_traces_rejected"]
        need(len(negatives)==len(set(negatives))==16,
             "16 unique false hardware source traces rejected for original index "+str(index))
        need(bool(re.fullmatch(r"[a-f0-9]{64}",receipt["native_WATCH_log_sha256"]))
             and bool(re.fullmatch(r"[a-f0-9]{64}",receipt["native_AWATCH_log_sha256"]))
             and receipt["native_WATCH_log_sha256"]!=receipt["native_AWATCH_log_sha256"],
             "two SHA-scoped separate real native FEX GDB process traces")
    done=set(old)|set(accepted)
    remaining=[i for i in range(147) if i not in done]
    need(len(done)==141+len(accepted) and len(remaining)==6-len(accepted)
         and remaining==[44,63]+[i for i in range(81,85) if i not in accepted],
         "count genuine original 147 targets exactly, no duplicates")
    for entry in previous["original_147_relocation_source_records"]:
        n=entry["source_index"]
        entry["native_writer_ledger_reference"]=(
            "PREVIOUSLY_INDEPENDENTLY_ATTESTED_"+str(len(done))+"_TARGET_LEDGER_REFERENCE"
            if n in done else "NOT_IN_"+str(len(done))+"_INDIVIDUALLY_CERTIFIED_WRITER_TARGETS"
        )
        entry["new_runtime_native_hardware_proof_generated_by_this_batch"]=False
    for group in previous["source_cohort_release_groups"]:
        g=set(group["original_indices"])
        group["previously_independently_certified_target_count"]=len(g&done)
        group["remaining_separate_native_target_evidence_count"]=len(g-done)
    previous.update({
        "schema":SCHEMA,
        "independent_new_batch_source_indices_certified":accepted,
        "independent_new_batch_source_indices_quarantined":denied,
        "independent_verified_target_receipts_from_batch":len(accepted),
        "independent_batch_receipt_provenance":
            "https://github.com/RM11Cor/RM11-WinCore/actions/runs/43065752077",
        "previously_independently_attested_native_writer_target_count":len(done),
        "previously_attested_original_source_indices":sorted(done),
        "remaining_requires_separate_native_hardware_evidence":len(remaining),
        "remaining_non_IFUNC_DT_RELA_indices":remaining,
        "remaining_IFUNC_indices":[],
        "full_GLOB_DAT_dynamic_symbol_scope_preemption_and_versioning_proven":False,
        "new_native_hardware_attestations_in_this_source_inventory":0,
        "new_hardware_writer_attestations_from_this_batch":0,
        "new_GNU_CALL_RET_stack_READ_attestations_from_this_batch":0,
        "all_147_same_guest_native_execution_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    })
    need(sum(g["previously_independently_certified_target_count"]
             for g in previous["source_cohort_release_groups"])==len(done)
         and sum(g["remaining_separate_native_target_evidence_count"]
                 for g in previous["source_cohort_release_groups"])==len(remaining)
         and len(done)+len(remaining)==147,
         "original 147 source cohort sums reconcile strict 141 baseline plus independently audited")
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(previous,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_147_INDEPENDENT_TEN_TARGET_SOURCE_LEDGER"+
          str(len(done))+"_PENDING_"+str(len(remaining))+
          "_ACCEPTED_"+str(accepted)+"_QUARANTINED_"+str(denied))
    return previous

if __name__=="__main__":
    need(len(sys.argv)==5,"usage original-SHA-triad certified-ledger103 independent-batch81-84-audit output-ledger")
    run(*map(Path,sys.argv[1:]))
