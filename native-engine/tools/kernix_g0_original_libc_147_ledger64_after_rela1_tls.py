#!/usr/bin/env python3
"""Strict original GNU libc all-147 relocation source ledger after TLS row1 proof.

No execution and zero new native evidence in this script. All previous source
writer receipts AND the independently certified new TLS TPOFF64 one writer
are required before publishing a cumulative 64/147 target-only count.
"""
from __future__ import annotations
import json,sys
from pathlib import Path
from kernix_g0_original_libc_147_ledger63_after_rela0_res import (
    run as prior63_run,require,
)
from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA,LDSO_SHA,decode_original_libc,
)

NEW=frozenset((1,))

def run(root:Path,prior124:Path,four125:Path,four129:Path,four133:Path,
        four137:Path,four141:Path,two145:Path,ifunc85:Path,rela0:Path,
        rela1:Path)->dict:
    previous=prior63_run(root,prior124,four125,four129,four133,four137,
                         four141,two145,ifunc85,rela0)
    require(previous["schema"]==
            "kernix.g0.original-gnu-libc-147-relocation-cohort-native-writer-ledger63.v1",
            "prior exact original 147 GNU source ledger63 schema")
    require(previous["previously_independently_attested_native_writer_target_count"]==63
            and previous["remaining_requires_separate_native_hardware_evidence"]==84
            and previous["remaining_non_IFUNC_DT_RELA_indices"]==list(range(1,85))
            and previous["remaining_IFUNC_indices"]==[]
            and previous["native_GNU_DT_RELA0_R64_res_REAL_FEX_ARM64_JIT_source_store_writer_independently_proven"] is True
            and previous["full_symbol_lookup_preemption_version_semantics_proven"] is False
            and previous["all_147_same_guest_native_execution_proven"] is False
            and previous["Android_Bionic_Wine_Proton_games_proven"] is False,
            "previous 63 genuine original native writer targets, index1 unproven")
    require(rela1.is_file() and not rela1.is_symlink(),
            "one genuine new independent original GNU x86 TLS source writer proof")
    data=json.loads(rela1.read_text())
    require(data["schema"]==
            "kernix.g0.original-gnu-dt-rela1-tpoff64-real-native-arm64-fex-independent-writer.v1",
            "exact original GNU DT_RELA1 TLS independent proof schema")
    require(data["original_source_libc_sha256"]==LIBC_SHA
            and data["original_source_ldso_sha256"]==LDSO_SHA
            and data["original_source_indices"]==[1]
            and data["prior_independently_certified_native_hardware_target_count"]==63
            and data["new_distinct_original_GNU_native_hardware_writer_targets"]==1
            and data["unique_original_libc_native_hardware_writer_target_count"]==64
            and data["two_separate_FEX_guest_original_TLS_hardware_write_processes"] is True
            and data["one_single_FEX_guest_process_for_all_64_writers_proven"] is False
            and data["original_undefined_symbol_zero_TLS_model_and_runtime_module_offset_fully_proven"] is False
            and data["original_147_relocations_all_in_single_guest_proven"] is False
            and data["original_GNU_CALL_RET_stack_READ_for_this_TPOFF64_writer_proven"] is False
            and data["Android_Bionic_Wine_Proton_games_proven"] is False,
            "prior 63 and exactly one independent original GNU TLS target no full TLS/Android claims")
    rejected=data["sixteen_fake_original_TLS_native_hardware_traces_rejected"]
    require(len(rejected)==16 and len(set(rejected))==16,
            "sixteen uniquely rejected forged ARM64 TLS JIT native logs")
    receipt=data["one_original_GNU_RELA1_TLS_TPOFF64_native_writer_receipt"]
    src=decode_original_libc((root/"lib/x86_64-linux-gnu/libc.so.6").read_bytes())[1]
    require((src["index"],src["table"],src["table_index"],src["r_type"],
             src["r_sym"],src["r_offset"],src["r_addend"],
             src["source_guest_target"],src["original_source_qword"])==
            (1,"DT_RELA",1,18,0,"0x202d80",56,"0x804202d80","0x0"),
            "immutable real GNU x86 source TLS TPOFF64 STN_UNDEF r_sym0 addend +56")
    require(receipt["genuine_source_index"]==1
            and receipt["original_table"]=="DT_RELA"
            and receipt["original_relocation_type"]=="R_X86_64_TPOFF64"
            and receipt["source_symbol_index"]==0
            and receipt["original_source_signed_addend"]==56
            and receipt["original_guest_hardware_write_target"]==src["source_guest_target"]
            and receipt["source_original_qword"]=="0x0"
            and receipt["observed_native_writer_qword"]=="0xffffffffffffffb0"
            and receipt["observed_native_signed_value"]==-80
            and receipt["native_real_AArch64_store"]=="stlr x4, [x10]"
            and receipt["native_source_value_register"]=="x4"
            and receipt["native_source_register_value"]=="0xffffffffffffffb0"
            and receipt["original_x86_GNU_loader_JIT_entry"]=="0x801010014"
            and receipt["original_GNU_x86_loader_store_opcode"]=="488906"
            and receipt["native_real_FEX_JIT_instruction_count"]==2
            and receipt["source_guest_x86_to_ARM64_hardware_writer_proven"] is True
            and receipt["original_TLS_module_offset_and_all_TP_semantics_proven"] is False
            and receipt["original_all_147_same_guest_relocations_proven"] is False,
            "actual real original source loader x86 MOV into native FEX AArch64 STLR TLS -80 qword target")
    existing=set(previous["previously_attested_original_source_indices"])
    require(len(existing)==63 and 1 not in existing
            and 1 in set(previous["remaining_non_IFUNC_DT_RELA_indices"]),
            "TLS source index1 not previously attested; no duplicate count")
    newledger=existing|NEW
    require(len(newledger)==64 and newledger<=set(range(147)),
            "64 unique original source relocation target writer indices")
    for row in previous["original_147_relocation_source_records"]:
        i=row["source_index"]
        row["native_writer_ledger_reference"]=(
            "PREVIOUSLY_INDEPENDENTLY_ATTESTED_64_TARGET_LEDGER_REFERENCE"
            if i in newledger else "NOT_IN_64_INDIVIDUALLY_CERTIFIED_WRITER_TARGETS")
        row["new_runtime_native_hardware_proof_generated_by_this_batch"]=False
    for group in previous["source_cohort_release_groups"]:
        members=set(group["original_indices"])
        group["previously_independently_certified_target_count"]=len(members&newledger)
        group["remaining_separate_native_target_evidence_count"]=len(members-newledger)
    pending=[i for i in range(147) if i not in newledger]
    require(pending==list(range(2,85)) and len(pending)==83,
            "exact 83 non-IFUNC DT_RELA writer indices 2..84 still awaiting genuine proof")
    previous.update({
        "schema":"kernix.g0.original-gnu-libc-147-relocation-cohort-native-writer-ledger64.v1",
        "independent_existing_ledger_proof_anchor":
          "https://github.com/RM11Cor/RM11-WinCore/actions/runs/42875160762",
        "previously_independently_attested_native_writer_target_count":64,
        "previously_attested_original_source_indices":sorted(newledger),
        "remaining_requires_separate_native_hardware_evidence":83,
        "remaining_IFUNC_indices":[],
        "remaining_non_IFUNC_DT_RELA_indices":pending,
        "native_GNU_DT_RELA1_TLS_TPOFF64_sym0_addend56_REAL_FEX_ARM64_STORE_independently_proven":True,
        "full_TLS_runtime_module_layout_symbol_preemption_versioning_proven":False,
        "new_native_hardware_attestations_in_this_source_inventory":0,
        "new_hardware_writer_attestations_from_this_batch":0,
        "new_GNU_CALL_RET_stack_READ_attestations_from_this_batch":0,
        "all_147_same_guest_native_execution_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    })
    require(sum(g["previously_independently_certified_target_count"]
                for g in previous["source_cohort_release_groups"])==64
            and sum(g["remaining_separate_native_target_evidence_count"]
                    for g in previous["source_cohort_release_groups"])==83,
            "all original 147 source cohorts agree on 64 observed and 83 pending")
    require(len(previous["original_147_relocation_source_records"])==147,
            "preserve full original GNU source row evidence")
    return previous

if __name__=="__main__":
    require(len(sys.argv)==13,
            "usage original-triad prior124 four125 four129 four133 four137 four141 two145 IFUNC85 R64-RELA0 TLS-RELA1 output")
    result=run(*map(Path,sys.argv[1:12]))
    out=Path(sys.argv[12])
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_147_SOURCE_LEDGER64_83_NON_IFUNC_STILL_PENDING_NO_NEW_NATIVE_PROOF_FROM_LEDGER")
