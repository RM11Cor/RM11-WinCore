#!/usr/bin/env python3
"""Fail-closed source ledger92: append only independently proven GNU DT_RELA29 __curbrk writer.

Requires authentic SHA-pinned triad, certified prior91 ledger, independently verified
FEX AArch64 native hardware receipt and 16 rejected false traces. This aggregation
does not prove all 147 relocations in one guest or Android, Wine, Proton, or games.
"""
from __future__ import annotations
import hashlib
import json
import sys
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA, LDSO_SHA, decode_original_libc, classify,
)

SOURCE = (29, "DT_RELA", 29, 6, 655, "0x202e48", 0, "0x804202e48", "0x0")
PRIOR_SCHEMA = "kernix.g0.original-gnu-libc-147-relocation-cohort-native-writer-ledger91.v1"
PROOF_SCHEMA = "kernix.g0.original-gnu-dt-rela29-globdat-sym655-real-native-arm64-fex-independent-writer.v1"
RESULT_SCHEMA = "kernix.g0.original-gnu-libc-147-relocation-cohort-native-writer-ledger92.v1"
PROOF_KEY = "native_GNU_DT_RELA29_GLOBDAT_sym655___curbrk_REAL_FEX_ARM64_STORE_independently_proven"
POINTER = "0x80420ad70"
POINTER_DECIMAL = 34428988784

def need(value: bool, label: str) -> None:
    if not value:
        raise AssertionError("KERNIX_G0_LEDGER92_FAIL_CLOSED: " + label)

def read_regular(path: Path, size_limit: int = 2000000) -> bytes:
    need(path.is_file() and not path.is_symlink(), "regular input " + str(path))
    data = path.read_bytes()
    need(0 < len(data) <= size_limit, "bounded source input " + str(path))
    return data

def run(triad: Path, previous: Path, independent: Path, output: Path) -> dict:
    libc = read_regular(triad / "lib/x86_64-linux-gnu/libc.so.6", 2500000)
    ldso = read_regular(triad / "lib64/ld-linux-x86-64.so.2")
    need(len(libc) == 2118168 and hashlib.sha256(libc).hexdigest() == LIBC_SHA,
         "unchanged GNU original libc SHA256")
    need(len(ldso) == 235408 and hashlib.sha256(ldso).hexdigest() == LDSO_SHA,
         "unchanged GNU original ld.so SHA256")
    source = decode_original_libc(libc)
    need(classify(source)["original_total_RELA_and_JMPREL"] == 147,
         "exact unchanged 147 original relocation records")
    row = source[29]
    record = (row["index"], row["table"], row["table_index"], row["r_type"],
              row["r_sym"], row["r_offset"], row["r_addend"],
              row["source_guest_target"], row["original_source_qword"])
    need(record == SOURCE, "unaltered source29 GLOB_DAT __curbrk and zero qword")
    prior = json.loads(read_regular(previous))
    need(prior["schema"] == PRIOR_SCHEMA
         and prior["source_original_libc_sha256"] == LIBC_SHA
         and prior["source_original_ldso_sha256"] == LDSO_SHA
         and prior["original_relocations_total"] == 147
         and prior["previously_independently_attested_native_writer_target_count"] == 91
         and prior["remaining_requires_separate_native_hardware_evidence"] == 56
         and prior["remaining_non_IFUNC_DT_RELA_indices"] == list(range(29,85))
         and prior["remaining_IFUNC_indices"] == []
         and prior["native_GNU_DT_RELA28_GLOBDAT_sym2868_getdate_err_REAL_FEX_ARM64_STORE_independently_proven"] is True
         and prior["full_GLOB_DAT_dynamic_symbol_scope_preemption_and_versioning_proven"] is False
         and prior["all_147_same_guest_native_execution_proven"] is False
         and prior["Android_Bionic_Wine_Proton_games_proven"] is False,
         "source-locked previous 91 writers and 56 distinct remaining")
    done = set(prior["previously_attested_original_source_indices"])
    need(len(done) == 91 and 29 not in done and 29 in prior["remaining_non_IFUNC_DT_RELA_indices"],
         "not counted previously and no duplicates")
    need(len(prior["original_147_relocation_source_records"]) == 147
         and prior["original_147_relocation_source_records"][29]["source_guest_target"] == SOURCE[7],
         "prior source index29 fixed target")
    proof = json.loads(read_regular(independent))
    need(proof["schema"] == PROOF_SCHEMA
         and proof["original_source_libc_sha256"] == LIBC_SHA
         and proof["original_source_ldso_sha256"] == LDSO_SHA
         and proof["original_source_indices"] == [29]
         and proof["prior_independently_certified_native_hardware_target_count"] == 91
         and proof["new_distinct_original_GNU_native_hardware_writer_targets"] == 1
         and proof["unique_original_libc_native_hardware_writer_target_count"] == 92
         and proof["two_separate_FEX_guest_original_GLOBDAT_hardware_write_processes"] is True
         and proof["original_GLOB_DAT_full_dynamic_symbol_scope_preemption_and_versioning_proven"] is False
         and proof["one_single_FEX_guest_process_for_all_92_writers_proven"] is False
         and proof["original_147_relocations_all_in_single_guest_proven"] is False
         and proof["Android_Bionic_Wine_Proton_games_proven"] is False,
         "separately independently approved two FEX native hardware events")
    rejected = proof["sixteen_fake_original_GLOBDAT_native_hardware_traces_rejected"]
    need(len(rejected) == 16 and len(set(rejected)) == 16,
         "16 independent forgery negatives are unique")
    evidence = proof["one_original_GNU_RELA29_GLOBDAT_Sym655_native_writer_receipt"]
    need(evidence["genuine_source_index"] == 29
         and evidence["original_table"] == "DT_RELA"
         and evidence["original_relocation_type"] == "R_X86_64_GLOB_DAT"
         and evidence["source_symbol_index"] == 655
         and evidence["source_symbol_name"] == "__curbrk"
         and evidence["original_source_signed_addend"] == 0
         and evidence["source_original_qword"] == "0x0"
         and evidence["original_guest_hardware_write_target"] == SOURCE[7]
         and evidence["observed_native_writer_qword"] == POINTER
         and evidence["observed_native_pointer_value"] == POINTER_DECIMAL
         and evidence["source_defined_ELF_address_candidate"] == POINTER
         and evidence["actual_two_guest_native_value_matches_original_ELF_candidate"] is True
         and evidence["native_real_AArch64_store"] == "stlr x13, [x4]"
         and evidence["native_source_value_register"] == "x13"
         and evidence["native_source_register_value"] == POINTER
         and evidence["native_target_address_register"] == "x4"
         and evidence["native_target_register_value"] == SOURCE[7]
         and evidence["original_x86_GNU_loader_JIT_entry"] == "0x80100fb8b"
         and evidence["original_GNU_x86_loader_store_opcode"] == "4c8908"
         and evidence["native_real_FEX_JIT_instruction_count"] == 2
         and evidence["source_guest_x86_to_ARM64_hardware_writer_proven"] is True
         and evidence["full_GLOB_DAT_symbol_scope_preemption_versioning_proven"] is False
         and evidence["original_all_147_same_guest_relocations_proven"] is False,
         "original x86 STLR source29 registers, native value and target")
    done.add(29)
    pending = [i for i in range(147) if i not in done]
    need(len(done) == 92 and pending == list(range(30,85)) and len(pending) == 55,
         "92 unique original source targets, 55 pending")
    for item in prior["original_147_relocation_source_records"]:
        index = item["source_index"]
        item["native_writer_ledger_reference"] = (
            "PREVIOUSLY_INDEPENDENTLY_ATTESTED_92_TARGET_LEDGER_REFERENCE"
            if index in done else "NOT_IN_92_INDIVIDUALLY_CERTIFIED_WRITER_TARGETS"
        )
        item["new_runtime_native_hardware_proof_generated_by_this_batch"] = False
    for group in prior["source_cohort_release_groups"]:
        members = set(group["original_indices"])
        group["previously_independently_certified_target_count"] = len(members & done)
        group["remaining_separate_native_target_evidence_count"] = len(members - done)
    prior.update({
        "schema": RESULT_SCHEMA,
        "independent_existing_ledger_proof_anchor":
            "https://github.com/RM11Cor/RM11-WinCore/actions/runs/43033586098",
        "previously_independently_attested_native_writer_target_count": 92,
        "previously_attested_original_source_indices": sorted(done),
        "remaining_requires_separate_native_hardware_evidence": 55,
        "remaining_IFUNC_indices": [],
        "remaining_non_IFUNC_DT_RELA_indices": pending,
        PROOF_KEY: True,
        "full_GLOB_DAT_dynamic_symbol_scope_preemption_and_versioning_proven": False,
        "new_native_hardware_attestations_in_this_source_inventory": 0,
        "new_hardware_writer_attestations_from_this_batch": 0,
        "new_GNU_CALL_RET_stack_READ_attestations_from_this_batch": 0,
        "all_147_same_guest_native_execution_proven": False,
        "Android_Bionic_Wine_Proton_games_proven": False,
    })
    need(sum(group["previously_independently_certified_target_count"]
             for group in prior["source_cohort_release_groups"]) == 92
         and sum(group["remaining_separate_native_target_evidence_count"]
                 for group in prior["source_cohort_release_groups"]) == 55,
         "source cohorts independently reconcile exactly 147")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(prior, indent=2) + "\n")
    print("KERNIX_G0_ORIGINAL_GNU_147_SOURCE_LEDGER92_55_PENDING_AFTER_INDEPENDENT_FEX_92_ONLY")
    return prior

if __name__ == "__main__":
    need(len(sys.argv) == 5, "usage ORIGINAL_TRIAD LEDGER91_GENUINE PROOF92_INDEPENDENT OUTPUT92")
    run(*map(Path, sys.argv[1:]))
