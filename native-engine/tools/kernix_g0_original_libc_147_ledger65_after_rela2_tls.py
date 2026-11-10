#!/usr/bin/env python3
"""Original GNU source ledger65, conditional on REAL independent DT_RELA2 FEX.

Source inventory alone adds ZERO hardware attestation. Distinct original GNU
x86 source target index2 is eligible only after genuine ARM64 FEX watch/awatch
writer, SHA original guest JIT, sixteen falsified log rejections and previous
64 distinct independent source target receipts are all validated.
"""
from __future__ import annotations
import json,sys
from pathlib import Path
from kernix_g0_original_libc_147_ledger64_after_rela1_tls import (
    run as prior64_run,require,
)
from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA,LDSO_SHA,decode_original_libc,
)

NEW=frozenset((2,))

def run(root:Path,prior124:Path,four125:Path,four129:Path,four133:Path,
        four137:Path,four141:Path,two145:Path,ifunc85:Path,rela0:Path,
        rela1:Path,rela2:Path)->dict:
    prev=prior64_run(root,prior124,four125,four129,four133,
                     four137,four141,two145,ifunc85,rela0,rela1)
    require(prev["schema"]==
            "kernix.g0.original-gnu-libc-147-relocation-cohort-native-writer-ledger64.v1",
            "actual prior64 exact GNU source cohort ledger")
    require(prev["previously_independently_attested_native_writer_target_count"]==64
            and prev["remaining_requires_separate_native_hardware_evidence"]==83
            and prev["remaining_non_IFUNC_DT_RELA_indices"]==list(range(2,85))
            and prev["remaining_IFUNC_indices"]==[]
            and prev["native_GNU_DT_RELA0_R64_res_REAL_FEX_ARM64_JIT_source_store_writer_independently_proven"] is True
            and prev["native_GNU_DT_RELA1_TLS_TPOFF64_sym0_addend56_REAL_FEX_ARM64_STORE_independently_proven"] is True
            and prev["full_TLS_runtime_module_layout_symbol_preemption_versioning_proven"] is False
            and prev["all_147_same_guest_native_execution_proven"] is False
            and prev["Android_Bionic_Wine_Proton_games_proven"] is False,
            "prior64 evidence true and index2 original TLS still awaiting writer")
    require(rela2.is_file() and not rela2.is_symlink(),
            "new genuine exact independent native source FEX writer proof artifact")
    d=json.loads(rela2.read_text())
    require(d["schema"]==
            "kernix.g0.original-gnu-dt-rela2-tpoff64-real-native-arm64-fex-independent-writer.v1",
            "original DT_RELA2 exact independent proof schema")
    require(d["original_source_libc_sha256"]==LIBC_SHA
            and d["original_source_ldso_sha256"]==LDSO_SHA
            and d["original_source_indices"]==[2]
            and d["prior_independently_certified_native_hardware_target_count"]==64
            and d["new_distinct_original_GNU_native_hardware_writer_targets"]==1
            and d["unique_original_libc_native_hardware_writer_target_count"]==65
            and d["two_separate_FEX_guest_original_TLS_hardware_write_processes"] is True
            and d["one_single_FEX_guest_process_for_all_65_writers_proven"] is False
            and d["original_undefined_symbol_zero_TLS_model_and_runtime_module_offset_fully_proven"] is False
            and d["original_147_relocations_all_in_single_guest_proven"] is False
            and d["original_GNU_CALL_RET_stack_READ_for_this_TPOFF64_writer_proven"] is False
            and d["Android_Bionic_Wine_Proton_games_proven"] is False,
            "new independent writer must be just one original GNU TLS hardware target")
    neg=d["sixteen_fake_original_TLS_native_hardware_traces_rejected"]
    require(len(neg)==16 and len(set(neg))==16,
            "all sixteen original ARM64 guest source/hardware forgeries independently rejected")
    src=decode_original_libc((root/"lib/x86_64-linux-gnu/libc.so.6").read_bytes())[2]
    require((src["index"],src["table"],src["table_index"],src["r_type"],src["r_sym"],
             src["r_offset"],src["r_addend"],src["source_guest_target"],
             src["original_source_qword"])==
            (2,"DT_RELA",2,18,0,"0x202d88",48,"0x804202d88","0x0"),
            "unchanged original x86 GNU DT_RELA2 TPOFF64 sym0 addend48 source")
    w=d["one_original_GNU_RELA2_TLS_TPOFF64_native_writer_receipt"]
    require(w["genuine_source_index"]==2
            and w["original_table"]=="DT_RELA"
            and w["original_relocation_type"]=="R_X86_64_TPOFF64"
            and w["source_symbol_index"]==0
            and w["original_source_signed_addend"]==48
            and w["original_guest_hardware_write_target"]==src["source_guest_target"]
            and w["source_original_qword"]=="0x0"
            and w["observed_native_writer_qword"]=="0xffffffffffffffa8"
            and w["observed_native_signed_value"]==-88
            and w["native_real_AArch64_store"]=="stlr x4, [x10]"
            and w["native_source_value_register"]=="x4"
            and w["native_source_register_value"]=="0xffffffffffffffa8"
            and w["original_x86_GNU_loader_JIT_entry"]=="0x801010014"
            and w["original_GNU_x86_loader_store_opcode"]=="488906"
            and w["native_real_FEX_JIT_instruction_count"]==2
            and w["source_guest_x86_to_ARM64_hardware_writer_proven"] is True
            and w["original_TLS_module_offset_and_all_TP_semantics_proven"] is False
            and w["original_all_147_same_guest_relocations_proven"] is False,
            "exact source-to-FEX ARM64 native STLR -88 writable target")
    prior=set(prev["previously_attested_original_source_indices"])
    require(len(prior)==64 and 2 not in prior
            and 2 in set(prev["remaining_non_IFUNC_DT_RELA_indices"]),
            "new original source target never double counted")
    final=prior|NEW
    require(len(final)==65 and final<=set(range(147)),
            "all 65 unique original source writer locations")
    for row in prev["original_147_relocation_source_records"]:
        idx=row["source_index"]
        row["native_writer_ledger_reference"]=(
            "PREVIOUSLY_INDEPENDENTLY_ATTESTED_65_TARGET_LEDGER_REFERENCE"
            if idx in final else "NOT_IN_65_INDIVIDUALLY_CERTIFIED_WRITER_TARGETS")
        row["new_runtime_native_hardware_proof_generated_by_this_batch"]=False
    for group in prev["source_cohort_release_groups"]:
        members=set(group["original_indices"])
        group["previously_independently_certified_target_count"]=len(members&final)
        group["remaining_separate_native_target_evidence_count"]=len(members-final)
    pending=[i for i in range(147) if i not in final]
    require(pending==list(range(3,85)) and len(pending)==82,
            "exact 82 original non-IFUNC DT_RELA target writers remain source indices 3..84")
    prev.update({
        "schema":"kernix.g0.original-gnu-libc-147-relocation-cohort-native-writer-ledger65.v1",
        "independent_existing_ledger_proof_anchor":
          "https://github.com/RM11Cor/RM11-WinCore/actions/runs/42882001386",
        "previously_independently_attested_native_writer_target_count":65,
        "previously_attested_original_source_indices":sorted(final),
        "remaining_requires_separate_native_hardware_evidence":82,
        "remaining_IFUNC_indices":[],
        "remaining_non_IFUNC_DT_RELA_indices":pending,
        "native_GNU_DT_RELA2_TLS_TPOFF64_sym0_addend48_REAL_FEX_ARM64_STORE_independently_proven":True,
        "full_TLS_runtime_module_layout_symbol_preemption_versioning_proven":False,
        "new_native_hardware_attestations_in_this_source_inventory":0,
        "new_hardware_writer_attestations_from_this_batch":0,
        "new_GNU_CALL_RET_stack_READ_attestations_from_this_batch":0,
        "all_147_same_guest_native_execution_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    })
    require(len(prev["original_147_relocation_source_records"])==147,
            "all original 147 source rows retained without alias")
    require(sum(g["previously_independently_certified_target_count"]
                for g in prev["source_cohort_release_groups"])==65
            and sum(g["remaining_separate_native_target_evidence_count"]
                    for g in prev["source_cohort_release_groups"])==82,
            "strict all-cohort source count 65 proved + 82 pending = 147")
    return prev

if __name__=="__main__":
    require(len(sys.argv)==14,
            "usage original-triad prior124 four125 four129 four133 four137 four141 two145 IFUNC85 R64-RELA0 TLS-RELA1 TLS-RELA2 output")
    data=run(*map(Path,sys.argv[1:13]))
    output=Path(sys.argv[13])
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(data,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_GNU_147_SOURCE_LEDGER65_82_NONIFUNC_REMAIN_AFTER_TRUE_FEX_INDEPENDENT_ONLY")
