#!/usr/bin/env python3
"""Fail-closed GNU libc 147-source ledger93: add independently proven DT_RELA30 loc2 native writer only.

Source inventory alone adds zero new runtime writes. No single-guest 147 proof, full
symbol preemption/versioning, Android, Bionic, Wine, Proton or games claimed.
"""
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA,LDSO_SHA,decode_original_libc,classify,
)

SOURCE=(30,"DT_RELA",30,6,1584,"0x202e50",0,"0x804202e50","0x0")
PRIOR_SCHEMA="kernix.g0.original-gnu-libc-147-relocation-cohort-native-writer-ledger92.v1"
PROOF_SCHEMA="kernix.g0.original-gnu-dt-rela30-globdat-sym1584-real-native-arm64-fex-independent-writer.v1"
RESULT_SCHEMA="kernix.g0.original-gnu-libc-147-relocation-cohort-native-writer-ledger93.v1"
PROOF_KEY="native_GNU_DT_RELA30_GLOBDAT_sym1584_loc2_REAL_FEX_ARM64_STORE_independently_proven"
POINTER="0x80420b030"
POINTER_INT=34428989488

def need(value,label):
    if not value: raise AssertionError("KERNIX_G0_LEDGER93_FAIL_CLOSED: "+label)

def read(path,max_size=2500000):
    need(path.is_file() and not path.is_symlink(),"regular input "+str(path))
    buf=path.read_bytes()
    need(0<len(buf)<=max_size,"bounded input "+str(path))
    return buf

def run(triad:Path,prior92:Path,receipt93:Path,output:Path)->dict:
    libc=read(triad/"lib/x86_64-linux-gnu/libc.so.6")
    ldso=read(triad/"lib64/ld-linux-x86-64.so.2")
    need(len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA,
         "authentic unmodified original GNU libc")
    need(len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA,
         "authentic unmodified original GNU ld.so")
    rows=decode_original_libc(libc)
    need(classify(rows)["original_total_RELA_and_JMPREL"]==147,
         "exact original 147 GNU libc source records")
    row=rows[30]
    need((row["index"],row["table"],row["table_index"],row["r_type"],row["r_sym"],
          row["r_offset"],row["r_addend"],row["source_guest_target"],
          row["original_source_qword"])==SOURCE,
         "exact original DT_RELA30 loc2 symbol 1584, zero QWORD")

    previous=json.loads(read(prior92))
    need(previous["schema"]==PRIOR_SCHEMA
         and previous["source_original_libc_sha256"]==LIBC_SHA
         and previous["source_original_ldso_sha256"]==LDSO_SHA
         and previous["original_relocations_total"]==147
         and previous["previously_independently_attested_native_writer_target_count"]==92
         and previous["remaining_requires_separate_native_hardware_evidence"]==55
         and previous["remaining_non_IFUNC_DT_RELA_indices"]==list(range(30,85))
         and previous["remaining_IFUNC_indices"]==[]
         and previous["native_GNU_DT_RELA29_GLOBDAT_sym655___curbrk_REAL_FEX_ARM64_STORE_independently_proven"] is True
         and previous["full_GLOB_DAT_dynamic_symbol_scope_preemption_and_versioning_proven"] is False
         and previous["all_147_same_guest_native_execution_proven"] is False
         and previous["Android_Bionic_Wine_Proton_games_proven"] is False,
         "certified genuine prior92 ledger, unique 55 remaining, fail closed")
    done=set(previous["previously_attested_original_source_indices"])
    need(len(done)==92 and len(previous["previously_attested_original_source_indices"])==92
         and 30 not in done and len(previous["original_147_relocation_source_records"])==147,
         "no duplicate writer targets or missing source rows")
    entry=previous["original_147_relocation_source_records"][30]
    need(entry["source_index"]==30
         and entry["source_table"]=="DT_RELA"
         and entry["source_table_ordinal"]==30
         and entry["original_source_guest_target"]==SOURCE[7]
         and entry["original_source_file_old_qword"]=="0x0"
         and entry["source_relocation_type"]=="R_X86_64_GLOB_DAT",
         "original prior92 source30 target tuple matches hashed ELF")
    proof=json.loads(read(receipt93))
    need(proof["schema"]==PROOF_SCHEMA
         and proof["original_source_libc_sha256"]==LIBC_SHA
         and proof["original_source_ldso_sha256"]==LDSO_SHA
         and proof["original_source_indices"]==[30]
         and proof["prior_independently_certified_native_hardware_target_count"]==92
         and proof["new_distinct_original_GNU_native_hardware_writer_targets"]==1
         and proof["unique_original_libc_native_hardware_writer_target_count"]==93
         and proof["two_separate_FEX_guest_original_GLOBDAT_hardware_write_processes"] is True
         and proof["original_GLOB_DAT_full_dynamic_symbol_scope_preemption_and_versioning_proven"] is False
         and proof["one_single_FEX_guest_process_for_all_93_writers_proven"] is False
         and proof["original_147_relocations_all_in_single_guest_proven"] is False
         and proof["Android_Bionic_Wine_Proton_games_proven"] is False,
         "only authentic independently proven 93rd native hardware target")
    negatives=proof["sixteen_fake_original_GLOBDAT_native_hardware_traces_rejected"]
    need(len(negatives)==len(set(negatives))==16,"all sixteen falsified hardware trace tests rejected")
    w=proof["one_original_GNU_RELA30_GLOBDAT_Sym1584_native_writer_receipt"]
    need(w["genuine_source_index"]==30
         and w["original_table"]=="DT_RELA"
         and w["original_relocation_type"]=="R_X86_64_GLOB_DAT"
         and w["source_symbol_index"]==1584
         and w["source_symbol_name"]=="loc2"
         and w["original_source_signed_addend"]==0
         and w["source_original_qword"]=="0x0"
         and w["original_guest_hardware_write_target"]==SOURCE[7]
         and w["observed_native_writer_qword"]==POINTER
         and w["observed_native_pointer_value"]==POINTER_INT
         and w["source_defined_ELF_address_candidate"]==POINTER
         and w["actual_two_guest_native_value_matches_original_ELF_candidate"] is True
         and w["native_real_AArch64_store"]=="stlr x13, [x4]"
         and w["native_source_value_register"]=="x13"
         and w["native_source_register_value"]==POINTER
         and w["native_target_address_register"]=="x4"
         and w["native_target_register_value"]==SOURCE[7]
         and w["original_x86_GNU_loader_JIT_entry"]=="0x80100fb8b"
         and w["original_GNU_x86_loader_store_opcode"]=="4c8908"
         and w["native_real_FEX_JIT_instruction_count"]==2
         and w["source_guest_x86_to_ARM64_hardware_writer_proven"] is True
         and w["full_GLOB_DAT_symbol_scope_preemption_versioning_proven"] is False
         and w["original_all_147_same_guest_relocations_proven"] is False,
         "separately observed original x86 loader JIT STLR register provenance and real pointer")
    done.add(30)
    pending=[i for i in range(147) if i not in done]
    need(len(done)==93 and pending==list(range(31,85)) and len(pending)==54,
         "93 distinct indices plus 54 pending equals 147")
    for item in previous["original_147_relocation_source_records"]:
        idx=item["source_index"]
        item["native_writer_ledger_reference"]=(
            "PREVIOUSLY_INDEPENDENTLY_ATTESTED_93_TARGET_LEDGER_REFERENCE"
            if idx in done else "NOT_IN_93_INDIVIDUALLY_CERTIFIED_WRITER_TARGETS")
        item["new_runtime_native_hardware_proof_generated_by_this_batch"]=False
    for group in previous["source_cohort_release_groups"]:
        group_indices=set(group["original_indices"])
        group["previously_independently_certified_target_count"]=len(group_indices & done)
        group["remaining_separate_native_target_evidence_count"]=len(group_indices-done)
    previous.update({
        "schema":RESULT_SCHEMA,
        "previously_independently_attested_native_writer_target_count":93,
        "previously_attested_original_source_indices":sorted(done),
        "remaining_requires_separate_native_hardware_evidence":54,
        "remaining_IFUNC_indices":[],
        "remaining_non_IFUNC_DT_RELA_indices":pending,
        PROOF_KEY:True,
        "full_GLOB_DAT_dynamic_symbol_scope_preemption_and_versioning_proven":False,
        "new_native_hardware_attestations_in_this_source_inventory":0,
        "new_hardware_writer_attestations_from_this_batch":0,
        "new_GNU_CALL_RET_stack_READ_attestations_from_this_batch":0,
        "all_147_same_guest_native_execution_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    })
    need(sum(g["previously_independently_certified_target_count"]
             for g in previous["source_cohort_release_groups"])==93
         and sum(g["remaining_separate_native_target_evidence_count"]
                 for g in previous["source_cohort_release_groups"])==54,
         "147 source cohort count reconciles exactly with 93 native receipts")
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(previous,indent=2)+"\n")
    print("KERNIX_G0_GNU_147_SOURCE_LEDGER93_54_PENDING_ONLY_IF_INDEPENDENT_FEX_PROOF")
    return previous

if __name__=="__main__":
    need(len(sys.argv)==5,"usage triad ledger92 independent-native-proof93 output-ledger93")
    run(*map(Path,sys.argv[1:]))
