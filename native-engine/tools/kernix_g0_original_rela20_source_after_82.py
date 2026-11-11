#!/usr/bin/env python3
"""Source-only bounded inventory of original GNU libc DT_RELA index 20.

Must never report native FEX writer evidence, native execution, complete TLS
semantics, same-guest 147 closure, Android/Bionic, or Windows game operation.
"""
from __future__ import annotations
import hashlib
import json
import sys
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA, LDSO_SHA, decode_original_libc,
)

def require(x, why):
    if not x:
        raise AssertionError("GNU source DT_RELA20 FAIL-CLOSED: " + why)

def regular(path: Path):
    require(path.is_file() and not path.is_symlink(), "immutable input file " + str(path))
    return path.read_bytes()

def run(triad: Path, prior82: Path, output: Path):
    libc = regular(triad / "lib/x86_64-linux-gnu/libc.so.6")
    ldso = regular(triad / "lib64/ld-linux-x86-64.so.2")
    require(hashlib.sha256(libc).hexdigest() == LIBC_SHA,
            "source original x86-64 libc immutable SHA")
    require(hashlib.sha256(ldso).hexdigest() == LDSO_SHA,
            "source original x86-64 GNU ldso immutable SHA")
    records = decode_original_libc(libc)
    require(len(records) == 147, "exact original GNU 147 ELF source entries")
    ledger = json.loads(regular(prior82 /
        "original-libc-147-source-batch-native-proof-ledger82-NO-NEW-HW-RUN.json"))
    require(
        ledger["schema"] == "kernix.g0.original-gnu-libc-147-relocation-cohort-native-writer-ledger82.v1"
        and ledger["source_original_libc_sha256"] == LIBC_SHA
        and ledger["source_original_ldso_sha256"] == LDSO_SHA
        and ledger["original_relocations_total"] == 147
        and ledger["previously_independently_attested_native_writer_target_count"] == 82
        and ledger["remaining_requires_separate_native_hardware_evidence"] == 65
        and ledger["remaining_non_IFUNC_DT_RELA_indices"] == list(range(20, 85))
        and ledger["remaining_IFUNC_indices"] == []
        and 20 not in ledger["previously_attested_original_source_indices"]
        and ledger["all_147_same_guest_native_execution_proven"] is False
        and ledger["Android_Bionic_Wine_Proton_games_proven"] is False,
        "exact unique prior 82 native source ledger; index20 not certified",
    )
    r = records[20]
    require(
        r["index"] == 20 and r["table"] == "DT_RELA"
        and r["table_index"] == 20
        and isinstance(r["r_type"], int)
        and isinstance(r["r_sym"], int)
        and isinstance(r["r_addend"], int)
        and isinstance(r["r_offset"], str)
        and isinstance(r["source_guest_target"], str),
        "actual source index 20 relocation fields, no guessed type or offset",
    )
    rows = [x for x in ledger["original_147_relocation_source_records"]
            if x["source_index"] == 20]
    require(len(rows) == 1
            and rows[0]["native_writer_ledger_reference"] ==
            "NOT_IN_82_INDIVIDUALLY_CERTIFIED_WRITER_TARGETS",
            "original index20 unique and still awaiting native hardware proof")
    result = {
        "schema": "kernix.g0.original-gnu-dt-rela20-source-only-after-ledger82.v1",
        "original_source_libc_sha256": LIBC_SHA,
        "original_source_ldso_sha256": LDSO_SHA,
        "original_source_index": 20,
        "original_table": r["table"],
        "original_table_ordinal": r["table_index"],
        "original_relocation_type_id": r["r_type"],
        "original_symbol_index": r["r_sym"],
        "original_signed_addend": r["r_addend"],
        "original_source_relocation_offset": r["r_offset"],
        "original_guest_target": r["source_guest_target"],
        "original_source_initial_qword": r["original_source_qword"],
        "prior_independently_attested_native_writers": 82,
        "remaining_requires_native_hardware_proof": 65,
        "source_only_no_native_writer_proven": True,
        "new_native_attestations": 0,
        "full_TLS_module_and_thread_pointer_semantics_proven": False,
        "all_147_same_guest_native_execution_proven": False,
        "Android_Bionic_Wine_Proton_games_proven": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n")
    print("KERNIX_G0_SOURCE_ORIGINAL_RELA20_NO_NATIVE_PROOF")
    print(json.dumps(result, sort_keys=True))
    return result

if __name__ == "__main__":
    require(len(sys.argv) == 4, "usage original-triad ledger82 source-output")
    run(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
