#!/usr/bin/env python3
"""SHA-locked original GNU libc 147-relocation batch coverage inventory.

One SOURCE inspection for all 147 real ELF relocation records. An independently
attested IFUNC124 receipt is the bounded existing 39-target evidence checkpoint.
This tool DOES NOT execute FEX or manufacture hardware write/RET proofs.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA, LDSO_SHA, classify, decode_original_libc,
)

BIAS = 0x804000000
OUTPUT = "original-libc-147-source-batch-coverage-and-native-gates-NO-NEW-PROOF.json"
TYPES = {
    1: "R_X86_64_64",
    6: "R_X86_64_GLOB_DAT",
    7: "R_X86_64_JUMP_SLOT",
    18: "R_X86_64_TPOFF64",
    37: "R_X86_64_IRELATIVE",
}
SOURCE_GROUPS = {
    ("DT_RELA", 1): 8,
    ("DT_RELA", 18): 16,
    ("DT_RELA", 6): 61,
    ("DT_RELA", 37): 1,
    ("DT_JMPREL", 7): 16,
    ("DT_JMPREL", 37): 45,
}
CERTIFIED_SYMBOLIC = frozenset(range(86, 102))
CERTIFIED_IFUNC = frozenset(range(102, 125))
CERTIFIED_INDICES = CERTIFIED_SYMBOLIC | CERTIFIED_IFUNC
PENDING_OTHER_RELA = frozenset(range(85))  # non-IFUNC DT_RELA 0..84
PENDING_IFUNC = frozenset([85, *range(125, 147)])


def require(ok: bool, label: str) -> None:
    if not ok:
        raise AssertionError("FAIL-CLOSED original libc batch coverage: " + label)


def source_invariants(rows: list[dict], original: list[dict]) -> None:
    require(len(rows) == len(original) == 147, "exact 147 source record count")
    require([r["index"] for r in rows] == list(range(147)), "ordered exact original indices")
    require(len({r["r_offset"] for r in rows}) == 147,
            "147 distinct original GNU source offsets")
    require(len({r["source_guest_target"] for r in rows}) == 147,
            "147 distinct source guest targets")
    require(Counter((r["table"], r["r_type"]) for r in rows) == Counter(SOURCE_GROUPS),
            "all six true GNU source type/table cohorts")
    require(all(r["r_type"] == 37 and r["r_sym"] == 0
                for r in (rows[85], *rows[102:])), "complete genuine IFUNC source index set")
    require(all(r["r_type"] == 7 and r["r_sym"] > 0 for r in rows[86:102]),
            "original 16 symbolic JUMP_SLOT source indices")
    for row, expected in zip(rows, original):
        require(all(row[k] == expected[k] for k in
                    ("index", "table", "table_index", "r_offset", "r_type",
                     "r_sym", "r_addend", "source_guest_target", "original_source_qword")),
                "original SHA-pinned ELF record fields at index " + str(expected["index"]))


def run_negative_controls(rows: list[dict]) -> list[str]:
    changes = [
        ("dropped", lambda a: a.pop(125)),
        ("reordered", lambda a: a.__setitem__(124, a[125])),
        ("duplicate_target", lambda a: a[125].__setitem__("r_offset", a[124]["r_offset"])),
        ("mutate_type", lambda a: a[125].__setitem__("r_type", 7)),
        ("mutate_source_old_qword", lambda a: a[125].__setitem__("original_source_qword", "0x1")),
        ("mutate_resolver_addend", lambda a: a[125].__setitem__("r_addend", a[124]["r_addend"])),
        ("mutate_symbolic_type", lambda a: a[101].__setitem__("r_type", 37)),
        ("mutate_DT_RELA_type", lambda a: a[85].__setitem__("r_type", 6)),
        ("mutate_table", lambda a: a[125].__setitem__("table", "DT_RELA")),
        ("mutate_table_ordinal", lambda a: a[125].__setitem__("table_index", 0)),
        ("mutate_target_address", lambda a: a[125].__setitem__("source_guest_target", "0x0")),
        ("mutate_source_symbol", lambda a: a[125].__setitem__("r_sym", 1)),
    ]
    rejected = []
    for name, change in changes:
        mutated = copy.deepcopy(rows)
        change(mutated)
        try:
            source_invariants(mutated, rows)
        except AssertionError:
            rejected.append(name)
            print("KERNIX_G0_BATCH_SOURCE_MUTATION_REJECTED", name)
        else:
            raise AssertionError("FAIL-OPEN original source batch accepted " + name)
    require(len(rejected) == 12, "12 adversarial original ELF cohort mutation controls")
    return rejected


def build(libc: bytes, ldso: bytes, proof: dict) -> dict:
    require(len(libc) == 2118168 and hashlib.sha256(libc).hexdigest() == LIBC_SHA,
            "original GNU libc source SHA/size")
    require(len(ldso) == 235408 and hashlib.sha256(ldso).hexdigest() == LDSO_SHA,
            "original GNU interpreter source SHA/size")
    rows = decode_original_libc(libc)
    source_invariants(rows, rows)
    classified = classify(rows)
    require(classified["original_total_RELA_and_JMPREL"] == 147,
            "classification exact original relocation count")
    require(classified["original_source_IRELATIVE_count"] == 46,
            "46 original IFUNC")
    require(classified["original_other_RELA_count"] == 85,
            "85 non-IFUNC DT_RELA")
    require(proof["original_source_IFUNC_index"] == 124,
            "independently attested latest return-chain index")
    require(proof["source_original_libc_sha256"] == LIBC_SHA
            and proof["source_original_ldso_sha256"] == LDSO_SHA,
            "independently attested ELF must equal all-record source")
    require(proof["source_original_target"] == rows[124]["source_guest_target"],
            "independent target 124 matches original x86 source index")
    require(proof["native_source_original_IFUNC124_distinct_writer_ledger_count"] == 39,
            "current separately certified native writer ledger 39")
    require(proof["genuine_original_linux_FEX_ARM64_ONE_process_IFUNC124_CALL_resolver_JIT_C3_RET_native_hardware_read_and_writer_proven"] is True,
            "independent genuine FEX ARM64 IFUNC124 full execution")
    require(proof["ten_genuine_native_hardware_log_corruptions_independently_rejected"] is True,
            "independent original native tamper controls")
    require(proof["new_unique_relocation_count_due_to_RET_proof"] == 0,
            "return provenance never adds a second writer")
    require(proof["all_147_original_libc_RELA_JMPREL_writers_one_process_proven"] is False,
            "entire original libc guest loader not yet independently closed")
    require(proof["Android_Bionic_Wine_Proton_games_proven"] is False,
            "Linux-only evidence must not claim Android games")

    ifunc = [r for r in rows if r["r_type"] == 37]
    require([r["index"] for r in ifunc] == [85, *range(102, 147)],
            "all original DT_RELA and JMPREL IFUNC indices")
    by_resolver = defaultdict(list)
    for row in ifunc:
        by_resolver[row["r_addend"]].append(row["index"])
    aliased = [group for group in by_resolver.values() if len(group) > 1]
    require(len(by_resolver) == 42 and sorted(map(len, aliased)) == [2, 2, 2, 2],
            "42 unique resolver entries and four actual 2-index aliases")
    require(CERTIFIED_INDICES == (CERTIFIED_SYMBOLIC | CERTIFIED_IFUNC)
            and len(CERTIFIED_INDICES) == 39, "39 unique independently reported target indices")
    require(len(PENDING_OTHER_RELA | PENDING_IFUNC) == 108,
            "108 remaining candidate source rows")
    require(not (CERTIFIED_INDICES & (PENDING_OTHER_RELA | PENDING_IFUNC)),
            "never double-count certified and pending")

    records = []
    for row in rows:
        idx, typ = row["index"], row["r_type"]
        record = {
            "source_index": idx,
            "source_table": row["table"],
            "source_table_ordinal": row["table_index"],
            "source_relocation_type": TYPES[typ],
            "original_source_guest_target": row["source_guest_target"],
            "original_source_file_old_qword": row["original_source_qword"],
            "native_writer_ledger_reference": (
                "PREVIOUSLY_INDEPENDENTLY_ATTESTED_39_TARGET_LEDGER_REFERENCE"
                if idx in CERTIFIED_INDICES else "NOT_IN_39_INDIVIDUALLY_CERTIFIED_WRITER_TARGETS"
            ),
            "new_runtime_native_hardware_proof_generated_by_this_batch": False,
        }
        if typ == 37:
            record["original_source_resolver"] = hex(BIAS + row["r_addend"])
            record["original_resolver_alias_indices"] = by_resolver[row["r_addend"]]
        records.append(record)

    cohort_rows = []
    for (table, typ), expected_n in SOURCE_GROUPS.items():
        group = [r["source_index"] for r in records
                 if r["source_table"] == table
                 and r["source_relocation_type"] == TYPES[typ]]
        require(len(group) == expected_n, "complete cohort " + table + TYPES[typ])
        cohort_rows.append({
            "table": table, "type": TYPES[typ], "source_record_count": expected_n,
            "original_indices": group,
            "previously_independently_certified_target_count":
                len(set(group) & CERTIFIED_INDICES),
            "remaining_separate_native_target_evidence_count":
                len(set(group) - CERTIFIED_INDICES),
            "source_cohort_proven_not_native_execution": True,
        })
    negatives = run_negative_controls(rows)
    return {
        "schema": "kernix.g0.original-gnu-libc-147-relocation-cohort-handoff.v1",
        "source_original_libc_sha256": LIBC_SHA,
        "source_original_ldso_sha256": LDSO_SHA,
        "original_relocations_total": 147,
        "original_DT_RELA_source_count": 86,
        "original_DT_JMPREL_source_count": 61,
        "original_IFUNC_source_target_count": 46,
        "original_distinct_IFUNC_resolver_count": 42,
        "original_repeated_resolver_index_groups": sorted(map(sorted, aliased)),
        "independent_existing_ledger_proof_anchor":
            "https://github.com/RM11Cor/RM11-WinCore/actions/runs/42827886594",
        "previously_independently_attested_native_writer_target_count": 39,
        "previously_attested_original_source_indices": sorted(CERTIFIED_INDICES),
        "remaining_requires_separate_native_hardware_evidence": 108,
        "remaining_non_IFUNC_DT_RELA_indices": sorted(PENDING_OTHER_RELA),
        "remaining_IFUNC_indices": sorted(PENDING_IFUNC),
        "source_cohort_release_groups": cohort_rows,
        "original_147_relocation_source_records": records,
        "adversarial_source_mutations_rejected": negatives,
        "new_hardware_writer_attestations_from_this_batch": 0,
        "new_GNU_CALL_RET_stack_READ_attestations_from_this_batch": 0,
        "new_Android_Bionic_Wine_Proton_game_exec_attestations": 0,
        "all_147_same_guest_native_execution_proven": False,
        "Android_Bionic_Wine_Proton_games_proven": False,
        "release_gates": [
            "Do NOT infer hardware execution from source grouping or common resolver addend",
            "For remaining IFUNC, trigger each original source resolver/target in same Linux FEX guest then independently check one-process native hardware chronology",
            "For 85 other DT_RELA entries, test 64/TPOFF64/GLOB_DAT semantics by type-group native captures and independent per-target provenance",
            "Verify no missing targets and actual final guest RELRO/ABI state after grouping; do not double-count replayed target",
            "A separate actual Android/Bionic on-device guest-loader and 16KiB-page gate is required before Wine or game claims",
        ],
    }


def main(root: Path, receipt: Path, output: Path) -> None:
    libc = root / "lib/x86_64-linux-gnu/libc.so.6"
    ldso = root / "lib64/ld-linux-x86-64.so.2"
    require(libc.is_file() and ldso.is_file(), "original source guest triad")
    require(not libc.is_symlink() and not ldso.is_symlink(),
            "original guest no source file symlinks")
    require(receipt.is_file() and not receipt.is_symlink(),
            "original full independent native receipt file")
    result = build(libc.read_bytes(), ldso.read_bytes(), json.loads(receipt.read_text()))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n")
    print("KERNIX_G0_ORIGINAL_147_RELOCATION_SOURCE_BATCH_GROUPS_PASS")
    for group in result["source_cohort_release_groups"]:
        print("KERNIX_G0_SOURCE_COHORT", group["table"], group["type"],
              "total", group["source_record_count"],
              "previous_certified", group["previously_independently_certified_target_count"],
              "remaining", group["remaining_separate_native_target_evidence_count"])
    print("KERNIX_G0_COHORT_SUMMARY_PREVIOUS_WRITERS=39 REMAINING_NEED_NATIVE=108"
          " NEGATIVES=12 NO_NEW_HARDWARE_PROOF")


if __name__ == "__main__":
    require(len(sys.argv) == 4, "usage triad-root full-IFUNC124-independent-proof output")
    main(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
