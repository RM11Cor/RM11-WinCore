#!/usr/bin/env python3
"""Original GNU libc exact all-147 source ledger after independent R64 RELA0 _res.

SOURCE INVENTORY ONLY. It adds ZERO native runtime proof. Previous 62 genuine
distinct FEX AArch64 hardware writer target receipts plus one independent
source-to-native GNU x86 writer #0 are strict prerequisites for 63/147.
"""
from __future__ import annotations
import json,sys
from pathlib import Path
from kernix_g0_original_libc_147_ledger62_after_ifunc85_zero_writer import (
    run as prior62_run,require,
)
from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA,LDSO_SHA,decode_original_libc,
)

NEW=frozenset((0,))

def run(root:Path,prior124:Path,four125:Path,four129:Path,four133:Path,
        four137:Path,four141:Path,two145:Path,ifunc85:Path,rela0:Path)->dict:
    previous=prior62_run(root,prior124,four125,four129,four133,
                         four137,four141,two145,ifunc85)
    require(previous["schema"]==
            "kernix.g0.original-gnu-libc-147-relocation-cohort-native-writer-ledger62.v1",
            "must reference exact previous 62-row source ledger version")
    require(previous["previously_independently_attested_native_writer_target_count"]==62
            and previous["remaining_requires_separate_native_hardware_evidence"]==85
            and previous["remaining_non_IFUNC_DT_RELA_indices"]==list(range(85))
            and previous["remaining_IFUNC_indices"]==[]
            and previous["native_IFUNC85_DT_RELA_real_zero_to_zero_FEX_JIT_hardware_STORE_independently_proven"] is True,
            "strict prior 62 native writers, exactly 85 original R64/TPOFF/GLOB source targets")
    require(rela0.is_file() and not rela0.is_symlink(),
            "strict newly independent original GNU RELA0 FEX hardware writer artifact")
    proof=json.loads(rela0.read_text())
    require(proof["schema"]=="kernix.g0.original-gnu-rela0-symbolic-64-native-fex-independent-one-writer.v1",
            "original real native R64 #0 certificate schema")
    require(proof["original_source_libc_sha256"]==LIBC_SHA
            and proof["original_source_ldso_sha256"]==LDSO_SHA
            and proof["original_source_indices"]==[0]
            and proof["prior_independently_certified_native_hardware_target_count"]==62
            and proof["new_distinct_original_GNU_native_hardware_writer_targets"]==1
            and proof["unique_original_libc_native_hardware_writer_target_count"]==63,
            "source genuine 62+1 exact independent relocation target provenance")
    negatives=proof["fourteen_native_hardware_and_original_JIT_forged_witnesses_rejected"]
    require(len(negatives)==14 and len(set(negatives))==14,
            "all fourteen uniquely rejected original native hardware/JIT tampered logs")
    require(proof["two_separate_FEX_guest_processes_hardware_write_observed"] is True
            and proof["one_single_FEX_guest_process_for_all_63_writers_proven"] is False
            and proof["original_full_symbol_preemption_lookup_and_version_semantics_proven"] is False
            and proof["original_DT_RELA0_CALL_RET_stack_HARDWARE_READ_proven"] is False
            and proof["all_147_original_libc_RELA_JMPREL_writers_same_process_proven"] is False
            and proof["Android_Bionic_Wine_Proton_games_proven"] is False,
            "do not mistake one original x86 store with a completed GNU loader or Android game")
    rows=decode_original_libc((root/"lib/x86_64-linux-gnu/libc.so.6").read_bytes())
    r=rows[0]
    require((r["index"],r["table"],r["table_index"],r["r_type"],r["r_sym"],
             r["r_offset"],r["r_addend"],r["source_guest_target"],
             r["original_source_qword"])==
            (0,"DT_RELA",0,1,2726,"0x1ffc68",0,"0x8041ffc68","0x0"),
            "real first original GNU non-IFUNC R_X86_64_64 immutable ELF source")
    receipt=proof["one_original_RELA0_R_X86_64_64_res_native_writer_receipt"]
    require(receipt["original_source_index"]==0
            and receipt["original_table"]=="DT_RELA"
            and receipt["original_relocation_type"]=="R_X86_64_64"
            and receipt["original_symbol_name"]=="_res"
            and receipt["original_symbol_index"]==2726
            and receipt["original_guest_target"]==r["source_guest_target"]
            and receipt["original_old_qword"]=="0x0"
            and receipt["observed_new_qword"]=="0x80420b680"
            and receipt["source_defined_GNU_BSS_symbol_address"]=="0x80420b680"
            and receipt["original_GNU_x86_loader_store_guest_entry"]=="0x80100fb8b"
            and receipt["original_GNU_x86_loader_store_opcode"]=="4c8908"
            and receipt["real_native_AArch64_store"]=="stlr x13, [x4]"
            and receipt["real_native_store_source_reg"]=="x13"
            and receipt["real_native_store_target_reg"]=="x4"
            and receipt["real_guest_source_JIT_native_count"]==2
            and receipt["native_source_hardware_write_independently_attested"] is True
            and receipt["original_GNU_symbol_interposition_versioning_all_lookups_proven"] is False
            and receipt["one_guest_all_147_relocation_closure_proven"] is False,
            "original GNU x86 MOV [RAX],R9 -> genuine native STLR X13,[X4] exact qword target/value")
    already=set(previous["previously_attested_original_source_indices"])
    require(len(already)==62 and 0 not in already
            and 0 in set(previous["remaining_non_IFUNC_DT_RELA_indices"]),
            "never double count the first original R_X86_64_64 source")
    newledger=already|NEW
    require(len(newledger)==63 and newledger<=set(range(147)),
            "63 unique actual original source row targets no aliases")
    for record in previous["original_147_relocation_source_records"]:
        idx=record["source_index"]
        record["native_writer_ledger_reference"]=(
            "PREVIOUSLY_INDEPENDENTLY_ATTESTED_63_TARGET_LEDGER_REFERENCE"
            if idx in newledger else
            "NOT_IN_63_INDIVIDUALLY_CERTIFIED_WRITER_TARGETS")
        record["new_runtime_native_hardware_proof_generated_by_this_batch"]=False
    for group in previous["source_cohort_release_groups"]:
        members=set(group["original_indices"])
        group["previously_independently_certified_target_count"]=len(members&newledger)
        group["remaining_separate_native_target_evidence_count"]=len(members-newledger)
    pending=[i for i in range(147) if i not in newledger]
    require(len(pending)==84 and pending==list(range(1,85)),
            "exact 84 remaining non-IFUNC source targets 1..84")
    previous.update({
        "schema":"kernix.g0.original-gnu-libc-147-relocation-cohort-native-writer-ledger63.v1",
        "independent_existing_ledger_proof_anchor":
          "https://github.com/RM11Cor/RM11-WinCore/actions/runs/42870979057",
        "previously_independently_attested_native_writer_target_count":63,
        "previously_attested_original_source_indices":sorted(newledger),
        "remaining_requires_separate_native_hardware_evidence":84,
        "remaining_IFUNC_indices":[],
        "remaining_non_IFUNC_DT_RELA_indices":pending,
        "native_GNU_DT_RELA0_R64_res_REAL_FEX_ARM64_JIT_source_store_writer_independently_proven":True,
        "full_symbol_lookup_preemption_version_semantics_proven":False,
        "new_native_hardware_attestations_in_this_source_inventory":0,
        "new_hardware_writer_attestations_from_this_batch":0,
        "new_GNU_CALL_RET_stack_READ_attestations_from_this_batch":0,
        "all_147_same_guest_native_execution_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    })
    require(sum(g["previously_independently_certified_target_count"]
                for g in previous["source_cohort_release_groups"])==63,
            "63 distinct fully recorded original source cohort native hardware writer targets")
    require(sum(g["remaining_separate_native_target_evidence_count"]
                for g in previous["source_cohort_release_groups"])==84,
            "84 original source cohort qwords still pending distinct hardware writer evidence")
    require(len(previous["original_147_relocation_source_records"])==147,
            "preserve all original SHA-locked relocation source records")
    return previous

if __name__=="__main__":
    require(len(sys.argv)==12,
            "usage original-triad prior124 four125 four129 four133 four137 four141 two145 IFUNC85 first-RELA0 output")
    result=run(*map(Path,sys.argv[1:11]))
    out=Path(sys.argv[11])
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_147_SOURCE_LEDGER63_84_NON_IFUNC_DT_RELA_STILL_PENDING_NO_NEW_NATIVE_FROM_LEDGER")
