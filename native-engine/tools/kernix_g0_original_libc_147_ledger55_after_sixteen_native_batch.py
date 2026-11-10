#!/usr/bin/env python3
"""Original GNU libc 147 source cohorts: 39+4+4+4+4 native writer proof chain.

No new native execution or CALL/RET stack-read proof is produced in this script.
All four independently attested four-process GNU FEX batches are mandatory inputs.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

from kernix_g0_original_libc_147_ledger51_after_twelve_native_batch import run as prior51_run, require
from kernix_g0_original_libc_relocation_type_transition_gate import decode_original_libc, LIBC_SHA, LDSO_SHA

NEW=frozenset((137,138,139,140))
PRIOR=frozenset((133,134,135,136))


def run(root:Path, prior124:Path, four125:Path, four129:Path, four133:Path, four137:Path)->dict:
    previous=prior51_run(root,prior124,four125,four129,four133)
    require(previous["previously_independently_attested_native_writer_target_count"]==51,"must have prior genuine 51 writer receipts")
    require(previous["remaining_requires_separate_native_hardware_evidence"]==96,"old pending 96")
    require(previous["native_batch133_136_proven_in_four_separate_FEX_guest_processes"] is True,"prior four were separate native guests")
    require(four137.is_file() and not four137.is_symlink(),"genuine next four independent native receipts")
    data=json.loads(four137.read_text())
    require(data["original_source_libc_sha256"]==LIBC_SHA
            and data["original_source_ldso_sha256"]==LDSO_SHA,"new batch source SHA parity")
    require(data["original_source_indices"]==sorted(NEW),"exact new four indices")
    require(data["prior_independently_certified_native_hardware_target_count"]==51,"new proof references prior 51")
    require(data["new_distinct_original_GNU_native_hardware_writer_targets"]==4
            and data["unique_original_libc_native_hardware_writer_target_count"]==55,"51+4 exact new native ledger")
    require(data["four_separate_FEX_guest_processes_share_one_FEX_build"] is True
            and data["one_single_FEX_guest_process_for_all_four_writes_proven"] is False
            and data["original_IFUNC137_140_CALL_C3_RET_native_stack_HW_READ_proven"] is False,
            "never invent one-guest or new guest RET hardware read")
    require(data["Android_Bionic_Wine_Proton_games_proven"] is False
            and data["all_147_original_libc_RELA_JMPREL_writers_same_process_proven"] is False,
            "Linux batch never proves Android or entire 147 one guest")
    negatives=data["forty_native_hardware_tamper_cases_rejected"]
    require(sorted(negatives)==["137","138","139","140"]
            and sum(len(v) for v in negatives.values())==40,"forty independently rejected counterfeit log mutations")
    receipts=data["four_independent_native_hardware_writer_receipts"]
    require(len(receipts)==4,"four new independent on-hardware receipts")
    rows=decode_original_libc((root/"lib/x86_64-linux-gnu/libc.so.6").read_bytes())
    for index,receipt in zip(sorted(NEW),receipts):
        row=rows[index]
        require(receipt["original_source_index"]==index,"original index")
        require(row["table"]=="DT_JMPREL" and row["table_index"]==index-86
                and row["r_type"]==37,"original GNU ELF ordinal/type")
        require(receipt["original_guest_target"]==row["source_guest_target"]
                and receipt["original_target_old_qword"]==row["original_source_qword"],"immutable target qword parity")
        require(receipt["native_source_hardware_write_independently_attested"] is True
                and receipt["native_same_guest_RET_hardware_read_attested"] is False,"writer proven, RET pending")
    already=set(previous["previously_attested_original_source_indices"])
    require(len(already)==51 and not (NEW&already) and PRIOR<=already,"no old/new double counting")
    ledger=already|NEW
    require(len(ledger)==55,"55 unique original relocations")
    for record in previous["original_147_relocation_source_records"]:
        index=record["source_index"]
        record["native_writer_ledger_reference"]=(
            "PREVIOUSLY_INDEPENDENTLY_ATTESTED_55_TARGET_LEDGER_REFERENCE"
            if index in ledger else "NOT_IN_55_INDIVIDUALLY_CERTIFIED_WRITER_TARGETS")
        record["new_runtime_native_hardware_proof_generated_by_this_batch"]=False
    for cohort in previous["source_cohort_release_groups"]:
        members=set(cohort["original_indices"])
        cohort["previously_independently_certified_target_count"]=len(members&ledger)
        cohort["remaining_separate_native_target_evidence_count"]=len(members-ledger)
    previous.update({
        "schema":"kernix.g0.original-gnu-libc-147-relocation-cohort-native-writer-ledger55.v1",
        "independent_existing_ledger_proof_anchor":"https://github.com/RM11Cor/RM11-WinCore/actions/runs/42844416071",
        "previously_independently_attested_native_writer_target_count":55,
        "previously_attested_original_source_indices":sorted(ledger),
        "remaining_requires_separate_native_hardware_evidence":92,
        "remaining_IFUNC_indices":[85,*range(141,147)],
        "native_batch137_140_proven_in_four_separate_FEX_guest_processes":True,
        "new_native_hardware_attestations_in_this_source_inventory":0,
        "new_hardware_writer_attestations_from_this_batch":0,
        "new_GNU_CALL_RET_stack_READ_attestations_from_this_batch":0,
        "all_147_same_guest_native_execution_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    })
    require(len(previous["remaining_IFUNC_indices"])==7
            and len(previous["remaining_non_IFUNC_DT_RELA_indices"])==85,"85 non-IFUNC plus 7 IFUNC pending")
    require(sum(c["previously_independently_certified_target_count"] for c in previous["source_cohort_release_groups"])==55,"55 exact cohort source count")
    require(sum(c["remaining_separate_native_target_evidence_count"] for c in previous["source_cohort_release_groups"])==92,"92 exact pending source cohorts")
    require(len(previous["original_147_relocation_source_records"])==147,"all original source rows remain")
    return previous


if __name__=="__main__":
    require(len(sys.argv)==8,"usage original triad prior124 full proof four125 proof four129 proof four133 proof four137 proof output")
    out=run(*map(Path,sys.argv[1:7]))
    path=Path(sys.argv[7])
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(out,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_GNU_SOURCE_COHORTS_147_55_PREVIOUSLY_INDEPENDENT_NATIVE_WRITERS_92_REMAINING_ZERO_NEW_RUNTIME_EXECUTION")
