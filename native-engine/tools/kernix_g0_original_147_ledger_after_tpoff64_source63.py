#!/usr/bin/env python3
"""Merge only independently verified real GNU TPOFF64 DT_RELA63 native writer.

Real original source of truth: 145/147 immutable all-target ledger and
separately completed, SHA-pinned two-process real FEX ARM64 TLS source writer
evidence. The single original DT_RELA44 remains pending, and neither complete
TLS ABI layout nor a runnable Windows/Android gaming runtime is claimed.
"""
from __future__ import annotations
import hashlib,json,re,sys
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA,LDSO_SHA,decode_original_libc,classify
)
from kernix_g0_original_tpoff64_source63_independent_writer_gate import SCHEMA as TLS_SCHEMA

SCHEMA="kernix.g0.original-gnu-147-native-writer-source-ledger-specialized-tpoff64-63-after145.v1"
OUT="KERNIX-G0-Original-147-Source-Ledger-146-Native-Writers-Only-Original44-Pending.json"

def require(ok,msg):
    if not ok: raise AssertionError("KERNIX_G0_SOURCE63_146_WRITER_LEDGER_FAIL_CLOSED: "+msg)

def read(p:Path,limit:int=2500000)->bytes:
    require(p.is_file() and not p.is_symlink(),"regular immutable evidence "+str(p))
    data=p.read_bytes()
    require(0<len(data)<=limit,"bounded immutable evidence "+str(p))
    return data

def main(triad:Path,prior145:Path,source63_proof:Path,output:Path)->dict:
    libc=read(triad/"lib/x86_64-linux-gnu/libc.so.6")
    ldso=read(triad/"lib64/ld-linux-x86-64.so.2")
    require(hashlib.sha256(libc).hexdigest()==LIBC_SHA
            and hashlib.sha256(ldso).hexdigest()==LDSO_SHA,
            "exact unmodified original GNU libc and ldso ELF SHA256")
    rows=decode_original_libc(libc)
    require(classify(rows)["original_total_RELA_and_JMPREL"]==147,
            "all genuine 147 original ELF relocation tuples")
    source=rows[63]
    require(source["source_guest_target"]=="0x804202f38"
            and source["r_type"]==18
            and source["r_sym"]==1523
            and source["original_source_qword"]=="0x0",
            "the exact SHA-locked original TLS DT_RELA63 qword, symbol and type")
    prior=json.loads(read(prior145))
    require(prior["schema"]==
            "kernix.g0.original-gnu-libc-147-native-writer-ledger-conditional-four-target-batch81-84-after141.v1"
            and prior["source_original_libc_sha256"]==LIBC_SHA
            and prior["source_original_ldso_sha256"]==LDSO_SHA
            and prior["original_relocations_total"]==147
            and prior["previously_independently_attested_native_writer_target_count"]==145
            and prior["remaining_requires_separate_native_hardware_evidence"]==2
            and prior["remaining_non_IFUNC_DT_RELA_indices"]==[44,63]
            and prior["remaining_IFUNC_indices"]==[]
            and prior["independent_new_batch_source_indices_certified"]==[81,82,83,84]
            and prior["independent_new_batch_source_indices_quarantined"]==[]
            and prior["all_147_same_guest_native_execution_proven"] is False
            and prior["Android_Bionic_Wine_Proton_games_proven"] is False,
            "current canonical 145 independently certified native source writer ledger")
    old=prior["previously_attested_original_source_indices"]
    require(len(old)==len(set(old))==145
            and 63 not in old and 44 not in old
            and set(range(147))-set(old)=={44,63},
            "original remaining two indices unique no double-count")
    records=prior["original_147_relocation_source_records"]
    require(len(records)==147 and records[63]["source_index"]==63
            and records[63]["source_table"]=="DT_RELA"
            and records[63]["source_table_ordinal"]==63
            and records[63]["source_relocation_type"]=="R_X86_64_TPOFF64"
            and records[63]["original_source_guest_target"]==source["source_guest_target"]
            and records[63]["original_source_file_old_qword"]==source["original_source_qword"],
            "immutable original source63 relocation record and unmodified initial zero")
    proof=json.loads(read(source63_proof))
    checks={
        "schema":TLS_SCHEMA,
        "original_source_index":63,
        "source_libc_sha256":LIBC_SHA,
        "source_ldso_sha256":LDSO_SHA,
        "source_symbol":"__libc_dlerror_result",
        "source_relocation_type":"R_X86_64_TPOFF64",
        "original_guest_target":"0x804202f38",
        "original_guest_old_qword":"0x0",
        "actual_signed_TLS_offset":-72,
        "actual_unsigned_TLS_offset_qword":"0xffffffffffffffb8",
        "actual_original_guest_x86_loader_JIT_entry":"0x801010014",
        "original_guest_x86_opcode":"488906",
        "native_real_ARM64_writer_instruction":"stlr x4, [x10]",
        "native_value_register_x4":"0xffffffffffffffb8",
        "hardware_target_changed_twice_in_distinct_guest_processes":True,
        "native_destination_register_x10_value_was_directly_logged":False,
        "full_TLS_module_offset_semantics_and_thread_allocation_proven":False,
        "real_original_source63_x86_to_ARM64_individual_native_writer_independently_proven":True,
        "not_an_additional_independent_source_proof_for_any_other_index":True,
        "prior_original_source_writer_ledger_122_left_untouched":True,
        "source_count_prior_to_separate_current_ledger_merge":122,
        "full_original_libc_147_process_relocation_closure_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    require(all(proof.get(key)==val for key,val in checks.items()),
            "original per-index specialized TLS -72 native writer proof cannot be substituted")
    negative=proof["seventeen_falsified_TLS_hardware_traces_rejected"]
    require(len(negative)==len(set(negative))==17
            and all(isinstance(n,str) and n for n in negative),
            "seventeen separate forged original TLS hardware traces rejected")
    hashes=proof["two_native_process_watch_and_awatch_sha256"]
    require(set(hashes)=={"watch","awatch"}
            and all(isinstance(v,str) and re.fullmatch("[0-9a-f]{64}",v)
                    for v in hashes.values())
            and hashes["watch"]!=hashes["awatch"],
            "two distinct SHA original FEX native writer GDB processes")
    done=sorted(set(old)|{63})
    pending=[i for i in range(147) if i not in done]
    require(len(done)==146 and pending==[44] and len(done)+len(pending)==147,
            "unique real original target 63 added once to correct current ledger")
    for entry in records:
        n=entry["source_index"]
        entry["native_writer_ledger_reference"]=(
            "PREVIOUSLY_INDEPENDENTLY_ATTESTED_146_TARGET_LEDGER_REFERENCE"
            if n in done else "NOT_IN_146_INDIVIDUALLY_CERTIFIED_WRITER_TARGETS")
        entry["new_runtime_native_hardware_proof_generated_by_this_batch"]=False
    for group in prior["source_cohort_release_groups"]:
        g=set(group["original_indices"])
        group["previously_independently_certified_target_count"]=len(g&set(done))
        group["remaining_separate_native_target_evidence_count"]=len(g-set(done))
    prior.update({
        "schema":SCHEMA,
        "independent_new_batch_source_indices_certified":[63],
        "independent_new_batch_source_indices_quarantined":[],
        "native_TLS63_original_signed_TPOFF64_minus72_source_writer_independently_proven":True,
        "original_TLS63_native_hardware_proof_source_run":
            "https://github.com/RM11Cor/RM11-WinCore/actions/runs/43066729036",
        "original_TLS63_native_hardware_proof_two_gdb_process_sha256":hashes,
        "original_TLS63_native_hardware_proof_rejected_forged_traces":17,
        "original_TLS63_native_destination_x10_value_explicitly_logged":False,
        "full_TLS_module_offset_semantics_and_thread_allocation_proven":False,
        "independent_verified_target_receipts_from_batch":1,
        "previously_independently_attested_native_writer_target_count":146,
        "previously_attested_original_source_indices":done,
        "remaining_requires_separate_native_hardware_evidence":1,
        "remaining_non_IFUNC_DT_RELA_indices":[44],
        "remaining_IFUNC_indices":[],
        "full_GLOB_DAT_dynamic_symbol_scope_preemption_and_versioning_proven":False,
        "new_native_hardware_attestations_in_this_source_inventory":0,
        "new_hardware_writer_attestations_from_this_batch":0,
        "new_GNU_CALL_RET_stack_READ_attestations_from_this_batch":0,
        "all_147_same_guest_native_execution_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    })
    require(sum(g["previously_independently_certified_target_count"]
                for g in prior["source_cohort_release_groups"])==146
            and sum(g["remaining_separate_native_target_evidence_count"]
                    for g in prior["source_cohort_release_groups"])==1,
            "all original 147 source type-cohort sums reconcile 146/147")
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(prior,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_147_INDEPENDENT_TLS_SOURCE63_NATIVE_WRITER_LEDGER146_PENDING_1_ONLY_ORIGINAL_44",
          "TLS_minus72_native_writer=1 full_TLS_ABI=0 Android=0")
    return prior

if __name__=="__main__":
    require(len(sys.argv)==5,"usage GNU-original-triad certified145-original-ledger independent-TLS63-writer-proof output-ledger")
    main(*map(Path,sys.argv[1:]))
