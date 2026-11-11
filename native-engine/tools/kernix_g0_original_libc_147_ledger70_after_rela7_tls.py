#!/usr/bin/env python3
"""Fail-closed source ledger70: original GNU libc DT_RELA7 TLS native writer.

This aggregates *previously* independently attested evidence only. It does not
claim same-process closure, full TLS semantics, Android/Bionic or game support.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from kernix_g0_original_libc_147_ledger69_after_rela6_tls import (
    run as prior69_run, require,
)
from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA, LDSO_SHA, decode_original_libc,
)

NEW = frozenset((7,))

def run(root: Path, prior124: Path, four125: Path, four129: Path,
        four133: Path, four137: Path, four141: Path, two145: Path,
        ifunc85: Path, rela0: Path, rela1: Path, rela2: Path,
        rela3: Path, rela4: Path, rela5: Path, rela6: Path, rela7: Path) -> dict:
    prev = prior69_run(
        root, prior124, four125, four129, four133,
        four137, four141, two145, ifunc85, rela0, rela1, rela2, rela3, rela4, rela5, rela6,
    )
    require(
        prev["schema"] ==
        "kernix.g0.original-gnu-libc-147-relocation-cohort-native-writer-ledger69.v1"
        and prev["previously_independently_attested_native_writer_target_count"] == 69
        and prev["remaining_requires_separate_native_hardware_evidence"] == 78
        and prev["remaining_non_IFUNC_DT_RELA_indices"] == list(range(7, 85))
        and prev["remaining_IFUNC_indices"] == []
        and prev["native_GNU_DT_RELA2_TLS_TPOFF64_sym0_addend48_REAL_FEX_ARM64_STORE_independently_proven"] is True
        and prev["native_GNU_DT_RELA3_TLS_TPOFF64_sym0_addend88_REAL_FEX_ARM64_STORE_independently_proven"] is True
        and prev["native_GNU_DT_RELA4_TLS_TPOFF64_sym0_addend72_REAL_FEX_ARM64_STORE_independently_proven"] is True
        and prev["native_GNU_DT_RELA5_TLS_TPOFF64_sym0_addend80_REAL_FEX_ARM64_STORE_independently_proven"] is True
        and prev["native_GNU_DT_RELA6_TLS_TPOFF64_sym0_addend100_REAL_FEX_ARM64_STORE_independently_proven"] is True
        and prev["full_TLS_runtime_module_layout_symbol_preemption_versioning_proven"] is False
        and prev["all_147_same_guest_native_execution_proven"] is False
        and prev["Android_Bionic_Wine_Proton_games_proven"] is False,
        "strict previous 69 target source ledger and all prior negatives",
    )
    require(rela7.is_file() and not rela7.is_symlink(),
            "independent TLS source writer receipt must be regular file")
    d = json.loads(rela7.read_text())
    require(
        d["schema"] ==
        "kernix.g0.original-gnu-dt-rela7-tpoff64-real-native-arm64-fex-independent-writer.v1"
        and d["original_source_libc_sha256"] == LIBC_SHA
        and d["original_source_ldso_sha256"] == LDSO_SHA
        and d["original_source_indices"] == [7]
        and d["prior_independently_certified_native_hardware_target_count"] == 69
        and d["new_distinct_original_GNU_native_hardware_writer_targets"] == 1
        and d["unique_original_libc_native_hardware_writer_target_count"] == 70
        and d["two_separate_FEX_guest_original_TLS_hardware_write_processes"] is True
        and d["one_single_FEX_guest_process_for_all_70_writers_proven"] is False
        and d["original_undefined_symbol_zero_TLS_model_and_runtime_module_offset_fully_proven"] is False
        and d["original_147_relocations_all_in_single_guest_proven"] is False
        and d["original_GNU_CALL_RET_stack_READ_for_this_TPOFF64_writer_proven"] is False
        and d["Android_Bionic_Wine_Proton_games_proven"] is False,
        "original SHA-pinned independent real native RELA7 writer only",
    )
    negatives = d["sixteen_fake_original_TLS_native_hardware_traces_rejected"]
    require(len(negatives) == 16 and len(set(negatives)) == 16,
            "16 independent negative log controls rejected")
    src = decode_original_libc(
        (root / "lib/x86_64-linux-gnu/libc.so.6").read_bytes()
    )[7]
    require(
        (src["index"], src["table"], src["table_index"], src["r_type"],
         src["r_sym"], src["r_offset"], src["r_addend"],
         src["source_guest_target"], src["original_source_qword"]) ==
        (7, "DT_RELA", 7, 18, 0, "0x202db0", 120, "0x804202db0", "0x0"),
        "unaltered original GNU DT_RELA7 x86 TLS source relocation",
    )
    w = d["one_original_GNU_RELA7_TLS_TPOFF64_native_writer_receipt"]
    require(
        w["genuine_source_index"] == 7
        and w["original_table"] == "DT_RELA"
        and w["original_relocation_type"] == "R_X86_64_TPOFF64"
        and w["source_symbol_index"] == 0
        and w["original_source_signed_addend"] == 120
        and w["original_guest_hardware_write_target"] == src["source_guest_target"]
        and w["source_original_qword"] == "0x0"
        and w["observed_native_writer_qword"] == "0xfffffffffffffff0"
        and w["observed_native_signed_value"] == -16
        and w["native_real_AArch64_store"] == "stlr x4, [x10]"
        and w["native_source_value_register"] == "x4"
        and w["native_source_register_value"] == "0xfffffffffffffff0"
        and w["original_x86_GNU_loader_JIT_entry"] == "0x801010014"
        and w["original_GNU_x86_loader_store_opcode"] == "488906"
        and w["native_real_FEX_JIT_instruction_count"] == 2
        and w["source_guest_x86_to_ARM64_hardware_writer_proven"] is True
        and w["original_TLS_module_offset_and_all_TP_semantics_proven"] is False
        and w["original_all_147_same_guest_relocations_proven"] is False,
        "source-authenticated -16 original ARM64 native target write",
    )
    prior = set(prev["previously_attested_original_source_indices"])
    require(len(prior) == 69 and 7 not in prior
            and 7 in set(prev["remaining_non_IFUNC_DT_RELA_indices"]),
            "new target not a previous native writer or reused source index")
    final = prior | NEW
    require(len(final) == 70 and final <= set(range(147)),
            "exact 70 unique GNU relocation indices")
    for row in prev["original_147_relocation_source_records"]:
        idx = row["source_index"]
        row["native_writer_ledger_reference"] = (
            "PREVIOUSLY_INDEPENDENTLY_ATTESTED_70_TARGET_LEDGER_REFERENCE"
            if idx in final else "NOT_IN_70_INDIVIDUALLY_CERTIFIED_WRITER_TARGETS"
        )
        row["new_runtime_native_hardware_proof_generated_by_this_batch"] = False
    for group in prev["source_cohort_release_groups"]:
        members = set(group["original_indices"])
        group["previously_independently_certified_target_count"] = len(members & final)
        group["remaining_separate_native_target_evidence_count"] = len(members - final)
    pending = [i for i in range(147) if i not in final]
    require(pending == list(range(8, 85)) and len(pending) == 77,
            "exact next non-IFUNC source indices 8..84 awaiting native writers")
    prev.update({
        "schema": "kernix.g0.original-gnu-libc-147-relocation-cohort-native-writer-ledger70.v1",
        "independent_existing_ledger_proof_anchor":
            "https://github.com/RM11Cor/RM11-WinCore/actions/runs/42928720903",
        "previously_independently_attested_native_writer_target_count": 70,
        "previously_attested_original_source_indices": sorted(final),
        "remaining_requires_separate_native_hardware_evidence": 77,
        "remaining_IFUNC_indices": [],
        "remaining_non_IFUNC_DT_RELA_indices": pending,
        "native_GNU_DT_RELA7_TLS_TPOFF64_sym0_addend120_REAL_FEX_ARM64_STORE_independently_proven": True,
        "full_TLS_runtime_module_layout_symbol_preemption_versioning_proven": False,
        "new_native_hardware_attestations_in_this_source_inventory": 0,
        "new_hardware_writer_attestations_from_this_batch": 0,
        "new_GNU_CALL_RET_stack_READ_attestations_from_this_batch": 0,
        "all_147_same_guest_native_execution_proven": False,
        "Android_Bionic_Wine_Proton_games_proven": False,
    })
    require(
        len(prev["original_147_relocation_source_records"]) == 147
        and sum(g["previously_independently_certified_target_count"]
                for g in prev["source_cohort_release_groups"]) == 70
        and sum(g["remaining_separate_native_target_evidence_count"]
                for g in prev["source_cohort_release_groups"]) == 77,
        "70 certified + 77 unproven equals all 147 original source records",
    )
    return prev

if __name__ == "__main__":
    require(len(sys.argv) == 19,
            "usage original-triad prior124 four125 four129 four133 four137 "
            "four141 two145 IFUNC85 R64-RELA0 TLS-RELA1 TLS-RELA2 TLS-RELA3 TLS-RELA4 TLS-RELA5 TLS-RELA6 TLS-RELA7 output")
    data = run(*map(Path, sys.argv[1:18]))
    output = Path(sys.argv[18])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2) + "\n")
    print("KERNIX_G0_ORIGINAL_GNU_147_SOURCE_LEDGER70_77_NONIFUNC_REMAIN_AFTER_TRUE_FEX_INDEPENDENT_ONLY")
