#!/usr/bin/env python3
"""Source-only 147 GNU libc relocation type cohorts after genuine writer ledger 43.

This calls the exact previous immutable 147-source verifier, then advances only
the CERTIFIED ledger using a separately attested four-native-process FEX proof.
Never claim a second execution or full return chain from this metadata stage.
"""
from __future__ import annotations
import hashlib
import json
import sys
from pathlib import Path

from kernix_g0_original_libc_147_batch_source_coverage_gate import (
    LIBC_SHA, LDSO_SHA, CERTIFIED_INDICES, BIAS, build, decode_original_libc,
)

NEW=frozenset((125,126,127,128))
ALL=CERTIFIED_INDICES|NEW
OUTPUT="original-libc-147-source-batch-native-proof-ledger43-NO-NEW-HW-RUN.json"


def require(ok:bool,reason:str)->None:
    if not ok:
        raise AssertionError("FAIL-CLOSED G0 batch native-ledger43 original source: "+reason)


def run(root:Path, proof124_path:Path, batch_path:Path)->dict:
    lc=root/"lib/x86_64-linux-gnu/libc.so.6"
    ld=root/"lib64/ld-linux-x86-64.so.2"
    for p in (lc,ld,proof124_path,batch_path):
        require(p.is_file() and not p.is_symlink(),str(p)+" immutable source input")
    libc,ldso=lc.read_bytes(),ld.read_bytes()
    require(len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA,"original libc source SHA")
    require(len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA,"original interpreter source SHA")
    oldproof=json.loads(proof124_path.read_text())
    report=build(libc,ldso,oldproof)
    require(report["previously_independently_attested_native_writer_target_count"]==39,"prior exact 39")
    require(len(report["original_147_relocation_source_records"])==147,"all 147 source rows")
    newproof=json.loads(batch_path.read_text())
    require(newproof["original_source_libc_sha256"]==LIBC_SHA and newproof["original_source_ldso_sha256"]==LDSO_SHA,"original SHA equality")
    require(newproof["original_source_indices"]==list(sorted(NEW)),"exact four new independent indices")
    require(newproof["prior_independently_certified_native_hardware_target_count"]==39,"four proof prior ledger")
    require(newproof["new_distinct_original_GNU_native_hardware_writer_targets"]==4,"four proven new writer targets")
    require(newproof["unique_original_libc_native_hardware_writer_target_count"]==43,"independent #43")
    require(newproof["four_separate_FEX_guest_processes_share_one_FEX_build"] is True,"honest separate processes")
    require(newproof["one_single_FEX_guest_process_for_all_four_writes_proven"] is False,"never same guest process")
    require(newproof["original_IFUNC125_128_CALL_C3_RET_native_stack_HW_READ_proven"] is False,"RET still pending")
    require(newproof["Android_Bionic_Wine_Proton_games_proven"] is False,"no phone game proof")
    receipts=newproof["four_independent_native_hardware_writer_receipts"]
    require(len(receipts)==4,"four independent actual original source write receipts")
    rejection=newproof["forty_native_hardware_tamper_cases_rejected"]
    require(sorted(rejection)==["125","126","127","128"] and sum(len(v) for v in rejection.values())==40,"forty negative controls")
    rows=decode_original_libc(libc)
    for i,receipt in enumerate(receipts,125):
        row=rows[i]
        require(receipt["original_source_index"]==i,"actual source index parity")
        require(row["r_type"]==37 and row["table_index"]==i-86 and row["table"]=="DT_JMPREL","original source ordinal")
        require(receipt["original_guest_target"]==row["source_guest_target"],"actual independent original source target parity")
        require(receipt["original_target_old_qword"]==row["original_source_qword"],"actual old target qword parity")
        require(receipt["native_source_hardware_write_independently_attested"] is True,"each hardware target certified")
        require(receipt["native_same_guest_RET_hardware_read_attested"] is False,"do not claim new RET")
    require(len(ALL)==43 and not (NEW&CERTIFIED_INDICES),"no duplicate target ledger entries")
    for row in report["original_147_relocation_source_records"]:
        i=row["source_index"]
        row["native_writer_ledger_reference"]=("PREVIOUSLY_INDEPENDENTLY_ATTESTED_43_TARGET_LEDGER_REFERENCE"
            if i in ALL else "NOT_IN_43_INDIVIDUALLY_CERTIFIED_WRITER_TARGETS")
        row["new_runtime_native_hardware_proof_generated_by_this_batch"]=False
    for group in report["source_cohort_release_groups"]:
        indices=set(group["original_indices"])
        group["previously_independently_certified_target_count"]=len(indices&ALL)
        group["remaining_separate_native_target_evidence_count"]=len(indices-ALL)
    report["schema"]="kernix.g0.original-gnu-libc-147-relocation-cohort-native-writer-ledger43.v1"
    report["independent_existing_ledger_proof_anchor"]="https://github.com/RM11Cor/RM11-WinCore/actions/runs/42832626066"
    report["prior_original_IFUNC124_full_independent_native_proof_anchor"]="https://github.com/RM11Cor/RM11-WinCore/actions/runs/42827886594"
    report["previously_independently_attested_native_writer_target_count"]=43
    report["previously_attested_original_source_indices"]=sorted(ALL)
    report["remaining_requires_separate_native_hardware_evidence"]=104
    report["remaining_IFUNC_indices"]=[85,*range(129,147)]
    report["native_batch125_128_proven_in_four_separate_FEX_guest_processes"]=True
    report["new_native_hardware_attestations_in_this_source_inventory"]=0
    report["source_147_inventory_is_NOT_same_guest_native_hardware_proof"]=True
    require(len(report["remaining_non_IFUNC_DT_RELA_indices"])==85,"85 missing non-IFUNC entries")
    require(len(report["remaining_IFUNC_indices"])==19,"19 pending original IFUNC entries")
    require(sum(g["previously_independently_certified_target_count"] for g in report["source_cohort_release_groups"])==43,"new source cohort 43 sum")
    require(sum(g["remaining_separate_native_target_evidence_count"] for g in report["source_cohort_release_groups"])==104,"new source cohort 104 sum")
    require(report["all_147_same_guest_native_execution_proven"] is False,"not full guest")
    require(report["Android_Bionic_Wine_Proton_games_proven"] is False,"no Android/Windows")
    require(report["new_hardware_writer_attestations_from_this_batch"]==0,"metadata batch doesn't run FEX")
    return report


if __name__=="__main__":
    require(len(sys.argv)==5,"usage original-triad-root prior-IFUNC124-full-proof four-FEX-native-batch-proof output-json")
    result=run(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))
    output=Path(sys.argv[4])
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,indent=2)+"\n")
    print("KERNIX_G0_SHA_LOCKED_147_SOURCE_COHORT_COUNTS_UPDATED_PREVIOUSLY_NATIVE_ATTESTED_43_REMAINING_104_ZERO_NEW_RUNTIME_EXECUTIONS")
