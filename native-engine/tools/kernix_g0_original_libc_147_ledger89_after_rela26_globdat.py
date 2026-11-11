#!/usr/bin/env python3
"""Fail-closed ledger89: original GNU libc GLOB_DAT26 sym1250 __ctype32_toupper original defined data symbol.

Aggregate 88 existing, individually authenticated GNU libc FEX ARM64 writers
and ONE separately authenticated real original source26 target. Do NOT imply
same-process loader closure, runtime symbol preemption, Android or games.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path
from kernix_g0_original_libc_147_ledger88_after_rela25_globdat import (
    run as prior88_run, require,
)
from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA, LDSO_SHA, decode_original_libc,
)

SOURCE = (26, "DT_RELA", 26, 6, 1250, "0x202e28", 0, "0x804202e28", "0x0")
SCHEMA = "kernix.g0.original-gnu-dt-rela26-globdat-sym1250-real-native-arm64-fex-independent-writer.v1"
RESULT_SCHEMA = "kernix.g0.original-gnu-libc-147-relocation-cohort-native-writer-ledger89.v1"

def run(*all_inputs: Path) -> dict:
    require(len(all_inputs) == 36, "35 authenticated prior inputs plus unique GLOB_DAT26 receipt")
    prev = prior88_run(*all_inputs[:-1])
    require(prev["schema"] ==
            "kernix.g0.original-gnu-libc-147-relocation-cohort-native-writer-ledger88.v1"
            and prev["source_original_libc_sha256"] == LIBC_SHA
            and prev["source_original_ldso_sha256"] == LDSO_SHA
            and prev["previously_independently_attested_native_writer_target_count"] == 88
            and prev["remaining_requires_separate_native_hardware_evidence"] == 59
            and prev["remaining_non_IFUNC_DT_RELA_indices"] == list(range(26, 85))
            and prev["remaining_IFUNC_indices"] == []
            and prev["native_GNU_DT_RELA25_GLOBDAT_sym1570_stdout_REAL_FEX_ARM64_STORE_independently_proven"] is True
            and prev["full_GLOB_DAT_dynamic_symbol_scope_preemption_and_versioning_proven"] is False
            and prev["all_147_same_guest_native_execution_proven"] is False
            and prev["Android_Bionic_Wine_Proton_games_proven"] is False,
            "strict 88 genuine prior hardware targets and explicit negative claims")
    proof_path = all_inputs[-1]
    require(proof_path.is_file() and not proof_path.is_symlink(),
            "source26 independent proof must be an authentic regular file")
    proof = json.loads(proof_path.read_text())
    require(proof["schema"] == SCHEMA
            and proof["original_source_libc_sha256"] == LIBC_SHA
            and proof["original_source_ldso_sha256"] == LDSO_SHA
            and proof["original_source_indices"] == [26]
            and proof["prior_independently_certified_native_hardware_target_count"] == 88
            and proof["new_distinct_original_GNU_native_hardware_writer_targets"] == 1
            and proof["unique_original_libc_native_hardware_writer_target_count"] == 89
            and proof["two_separate_FEX_guest_original_GLOBDAT_hardware_write_processes"] is True
            and proof["original_GLOB_DAT_full_dynamic_symbol_scope_preemption_and_versioning_proven"] is False
            and proof["one_single_FEX_guest_process_for_all_89_writers_proven"] is False
            and proof["original_147_relocations_all_in_single_guest_proven"] is False
            and proof["Android_Bionic_Wine_Proton_games_proven"] is False,
            "immutable-source independently authenticated 89th writer and negatives")
    fakes = proof["sixteen_fake_original_GLOBDAT_native_hardware_traces_rejected"]
    require(len(fakes) == 16 and len(set(fakes)) == 16,
            "all sixteen independently falsified hardware traces rejected")
    source = decode_original_libc(
        (all_inputs[0] / "lib/x86_64-linux-gnu/libc.so.6").read_bytes()
    )[26]
    record = (source["index"], source["table"], source["table_index"],
              source["r_type"], source["r_sym"], source["r_offset"],
              source["r_addend"], source["source_guest_target"],
              source["original_source_qword"])
    require(record == SOURCE,
            "original SHA-locked GNU DT_RELA26 GLOB_DAT sym1250 source record")
    w = proof["one_original_GNU_RELA26_GLOBDAT_Sym1250_native_writer_receipt"]
    require(
        w["genuine_source_index"] == 26
        and w["original_table"] == "DT_RELA"
        and w["original_relocation_type"] == "R_X86_64_GLOB_DAT"
        and w["source_symbol_index"] == 1250
        and w["source_symbol_name"] == "__ctype32_toupper"
        and w["original_source_signed_addend"] == 0
        and w["source_original_qword"] == "0x0"
        and w["original_guest_hardware_write_target"] == SOURCE[7]
        and w["observed_native_writer_qword"] == "0x804203640"
        and w["observed_native_pointer_value"] == 34428958272
        and w["source_defined_ELF_address_candidate"] == "0x804203640"
        and w["actual_two_guest_native_value_matches_original_ELF_candidate"] is True
        and w["native_real_AArch64_store"] == "stlr x13, [x4]"
        and w["native_source_value_register"] == "x13"
        and w["native_source_register_value"] == "0x804203640"
        and w["native_target_address_register"] == "x4"
        and w["native_target_register_value"] == SOURCE[7]
        and w["original_x86_GNU_loader_JIT_entry"] == "0x80100fb8b"
        and w["original_GNU_x86_loader_store_opcode"] == "4c8908"
        and w["native_real_FEX_JIT_instruction_count"] == 2
        and w["source_guest_x86_to_ARM64_hardware_writer_proven"] is True
        and w["full_GLOB_DAT_symbol_scope_preemption_versioning_proven"] is False
        and w["original_all_147_same_guest_relocations_proven"] is False,
        "same original x86 guest source-to-ARM64 STLR actual new pointer qword")
    prior = set(prev["previously_attested_original_source_indices"])
    require(len(prior) == 88 and 26 not in prior
            and 26 in prev["remaining_non_IFUNC_DT_RELA_indices"],
            "original source26 unique, never previously credited")
    done = prior | {26}
    require(len(done) == 89 and done <= set(range(147)),
            "89 distinct originally indexed target slots without double counting")
    for row in prev["original_147_relocation_source_records"]:
        index = row["source_index"]
        row["native_writer_ledger_reference"] = (
            "PREVIOUSLY_INDEPENDENTLY_ATTESTED_89_TARGET_LEDGER_REFERENCE"
            if index in done else "NOT_IN_89_INDIVIDUALLY_CERTIFIED_WRITER_TARGETS"
        )
        row["new_runtime_native_hardware_proof_generated_by_this_batch"] = False
    for group in prev["source_cohort_release_groups"]:
        members = set(group["original_indices"])
        group["previously_independently_certified_target_count"] = len(members & done)
        group["remaining_separate_native_target_evidence_count"] = len(members - done)
    pending = [i for i in range(147) if i not in done]
    require(pending == list(range(27,85)) and len(pending) == 58,
            "exact GNU DT_RELA27..84 remain pending source hardware evidence")
    prev.update({
        "schema": RESULT_SCHEMA,
        "independent_existing_ledger_proof_anchor":
            "https://github.com/RM11Cor/RM11-WinCore/actions/runs/43025220000",
        "previously_independently_attested_native_writer_target_count": 89,
        "previously_attested_original_source_indices": sorted(done),
        "remaining_requires_separate_native_hardware_evidence": 58,
        "remaining_IFUNC_indices": [],
        "remaining_non_IFUNC_DT_RELA_indices": pending,
        "native_GNU_DT_RELA26_GLOBDAT_sym1250___ctype32_toupper_REAL_FEX_ARM64_STORE_independently_proven": True,
        "source_defined_in_original_GNU_libc_BSS_variable_and_native_FEX_written_address_verified": True,
        "full_GLOB_DAT_dynamic_symbol_scope_preemption_and_versioning_proven": False,
        "new_native_hardware_attestations_in_this_source_inventory": 0,
        "new_hardware_writer_attestations_from_this_batch": 0,
        "new_GNU_CALL_RET_stack_READ_attestations_from_this_batch": 0,
        "all_147_same_guest_native_execution_proven": False,
        "Android_Bionic_Wine_Proton_games_proven": False,
    })
    require(len(prev["original_147_relocation_source_records"]) == 147
            and sum(x["previously_independently_certified_target_count"] for x in prev["source_cohort_release_groups"]) == 89
            and sum(x["remaining_separate_native_target_evidence_count"] for x in prev["source_cohort_release_groups"]) == 58,
            "89 certified plus 58 remaining equals 147 unique original GNU records")
    return prev

if __name__ == "__main__":
    require(len(sys.argv) == 38, "usage 35 original GNU proof paths plus RELA26 proof and output")
    data = run(*map(Path, sys.argv[1:37]))
    output = Path(sys.argv[37])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2) + "\n")
    print("KERNIX_G0_ORIGINAL_GNU_147_SOURCE_LEDGER89_58_NONIFUNC_REMAIN_AFTER_TRUE_FEX_INDEPENDENT_ONLY")
