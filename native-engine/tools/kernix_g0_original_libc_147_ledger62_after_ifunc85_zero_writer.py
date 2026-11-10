#!/usr/bin/env python3
"""Source-only exact original 147 GNU libc ledger after conditional IFUNC85 proof.

No FEX execution happens here. One independent original zero-to-zero native
writer receipt must be prevalidated; otherwise the certified subtotal is 61.
"""
from __future__ import annotations
import json,sys
from pathlib import Path

from kernix_g0_original_libc_147_ledger61_after_twentytwo_native_batch import run as prior61_run, require
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA,decode_original_libc

NEW=frozenset((85,))


def run(root:Path, prior124:Path, four125:Path, four129:Path, four133:Path,
        four137:Path, four141:Path, two145:Path, single85:Path)->dict:
    previous=prior61_run(root,prior124,four125,four129,four133,four137,four141,two145)
    require(previous["previously_independently_attested_native_writer_target_count"]==61,
            "prior 61 original independent hardware writer receipts")
    require(previous["remaining_requires_separate_native_hardware_evidence"]==86,
            "exact prior remaining 86 targets")
    require(previous["remaining_IFUNC_indices"]==[85],
            "only this original DT_RELA IRELATIVE remains among 46 original source IFUNCs")
    require(previous["native_batch145_146_proven_in_two_separate_FEX_guest_processes"] is True,
            "prior two target writer proofs are strictly separate FEX guest runs")
    require(single85.is_file() and not single85.is_symlink(),
            "genuine independent IFUNC85 AArch64 zero-store proof")
    data=json.loads(single85.read_text())
    require(data["original_source_libc_sha256"]==LIBC_SHA
            and data["original_source_ldso_sha256"]==LDSO_SHA,
            "new exact immutable original x86 GNU source SHA")
    require(data["original_source_indices"]==[85]
            and data["prior_independently_certified_native_hardware_target_count"]==61
            and data["new_distinct_original_GNU_native_hardware_writer_targets"]==1
            and data["unique_original_libc_native_hardware_writer_target_count"]==62,
            "independent prior 61 plus exactly one new original IFUNC85 target")
    require(data["original_IFUNC85_CALL_C3_RET_native_stack_HW_READ_proven"] is False
            and data["all_147_original_libc_RELA_JMPREL_writers_same_process_proven"] is False
            and data["Android_Bionic_Wine_Proton_games_proven"] is False,
            "native writer-only evidence does not mean loader, Android or game")
    require(len(data["twelve_original_IFUNC85_native_forged_witnesses_rejected"])==12
            and len(set(data["twelve_original_IFUNC85_native_forged_witnesses_rejected"]))==12,
            "reject all twelve independent forged zero-store native witnesses")
    receipt=data["one_original_IFUNC85_independent_same_zero_native_hardware_writer_receipt"]
    rows=decode_original_libc((root/"lib/x86_64-linux-gnu/libc.so.6").read_bytes())
    r=rows[85]
    require((r["index"],r["table"],r["table_index"],r["r_type"],r["r_sym"],
             r["r_offset"],r["r_addend"],r["original_source_qword"])==
            (85,"DT_RELA",85,37,0,"0x2014c8",0xc8570,"0x0"),
            "the actual original zero-to-zero source target")
    require(receipt["original_source_index"]==85 and
            receipt["source_table"]=="DT_RELA" and
            receipt["original_guest_target"]==r["source_guest_target"] and
            receipt["original_guest_resolver"]=="0x8040c8570" and
            receipt["original_initial_qword"]=="0x0" and
            receipt["observed_native_stlr_store_value"]=="0x0" and
            receipt["observed_arm64_native_store"]=="stlr x4, [x19]" and
            receipt["source_original_guest_x86_ldso_store"]=="0x80100fd60" and
            receipt["source_original_guest_x86_ldso_opcode"]=="498906" and
            receipt["native_source_hardware_write_independently_attested"] is True and
            receipt["original_same_guest_CALL_RET_stack_READ_proven"] is False,
            "exact original x86 loader JIT store -> native real ARM64 same-zero qword evidence")
    already=set(previous["previously_attested_original_source_indices"])
    require(len(already)==61 and 85 not in already,
            "original target 85 never double-counted in 61 previous receipts")
    ledger=already|NEW
    require(len(ledger)==62 and len(ledger & set(range(147)))==62,
            "62 distinct original GNU relocation target writer locations")
    for record in previous["original_147_relocation_source_records"]:
        idx=record["source_index"]
        record["native_writer_ledger_reference"]=(
            "PREVIOUSLY_INDEPENDENTLY_ATTESTED_62_TARGET_LEDGER_REFERENCE"
            if idx in ledger else "NOT_IN_62_INDIVIDUALLY_CERTIFIED_WRITER_TARGETS")
        record["new_runtime_native_hardware_proof_generated_by_this_batch"]=False
    for group in previous["source_cohort_release_groups"]:
        members=set(group["original_indices"])
        group["previously_independently_certified_target_count"]=len(members&ledger)
        group["remaining_separate_native_target_evidence_count"]=len(members-ledger)
    previous.update({
        "schema":"kernix.g0.original-gnu-libc-147-relocation-cohort-native-writer-ledger62.v1",
        "independent_existing_ledger_proof_anchor":"https://github.com/RM11Cor/RM11-WinCore/actions/runs/42864516665",
        "previously_independently_attested_native_writer_target_count":62,
        "previously_attested_original_source_indices":sorted(ledger),
        "remaining_requires_separate_native_hardware_evidence":85,
        "remaining_IFUNC_indices":[],
        "native_IFUNC85_DT_RELA_real_zero_to_zero_FEX_JIT_hardware_STORE_independently_proven":True,
        "new_native_hardware_attestations_in_this_source_inventory":0,
        "new_hardware_writer_attestations_from_this_batch":0,
        "new_GNU_CALL_RET_stack_READ_attestations_from_this_batch":0,
        "all_147_same_guest_native_execution_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    })
    require(len(previous["remaining_non_IFUNC_DT_RELA_indices"])==85
            and not previous["remaining_IFUNC_indices"],
            "85 non-IFUNC DT_RELA remain; all 46 original IFUNC source writer targets done")
    require(sum(c["previously_independently_certified_target_count"]
                for c in previous["source_cohort_release_groups"])==62,
            "62 certified exact source cohort targets")
    require(sum(c["remaining_separate_native_target_evidence_count"]
                for c in previous["source_cohort_release_groups"])==85,
            "85 exact original GNU pending source rows")
    require(len(previous["original_147_relocation_source_records"])==147,
            "all 147 exact source records retained")
    return previous


if __name__=="__main__":
    require(len(sys.argv)==11,
            "usage original triad prior124 proof four125 four129 four133 four137 four141 two145 IFUNC85 output")
    result=run(*map(Path,sys.argv[1:10]))
    out=Path(sys.argv[10])
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_147_SOURCE_LEDGER62_85_NON_IFUNC_REMAIN_NO_NEW_NATIVE_FROM_LEDGER")
