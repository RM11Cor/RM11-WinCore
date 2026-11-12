#!/usr/bin/env python3
"""G0-L40-C #85 ORIGINAL GNU IRELATIVE resolver SOURCE classification only.

Original x86-64 ELF r_addend chooses a candidate guest IFUNC resolver entry.
A zero before/after relocation slot does NOT demonstrate resolver execution,
a zero return, a write, a completed GNU loader, or an Android game.
No actual FEX native execution is performed by this script.
"""
from __future__ import annotations
import copy
import hashlib
import json
import struct
import sys
from pathlib import Path
from kernix_g0_l40_c_original_mixed_rela_jmprel80_119_source_plan import (
    run as source_run, SCHEMA as MIXED_SCHEMA,
)
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import LIBC_BIAS
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA

SCHEMA = "kernix.g0.l40c.source-gnu-original-irelative85-resolver-elf-exec-range-no-runtime-proof.v1"
OUT = "KERNIX-G0-C-Original-IRELATIVE85-Source-Resolver-Entry-NO-FEX-EXECUTION.json"

def need(test, why):
    if not test:
        raise AssertionError("KERNIX_G0_C_IRELATIVE85_SOURCE_FAIL_CLOSED: " + why)

def real_bytes(path: Path, limit: int):
    need(path.is_file() and not path.is_symlink(), "genuine regular file " + str(path))
    data = path.read_bytes()
    need(0 < len(data) <= limit, "bounded original ELF source " + str(path))
    return data

def resolver_location(libc: bytes, addend: int):
    need(libc[:6] == b"\x7fELF\x02\x01"
         and struct.unpack_from("<H", libc, 16)[0] == 3
         and struct.unpack_from("<H", libc, 18)[0] == 62,
         "SHA pinned original GNU x86-64 ET_DYN ELF64")
    phoff = struct.unpack_from("<Q", libc, 32)[0]
    phsize, n = struct.unpack_from("<HH", libc, 54)
    need(phsize == 56 and 0 < n <= 128 and phoff + n * phsize <= len(libc),
         "bounded original ELF program headers")
    matching = []
    for i in range(n):
        p_type, flags, offset, va, _, filesz, memsz, _ = struct.unpack_from(
            "<IIQQQQQQ", libc, phoff + i * phsize
        )
        if (p_type == 1 and flags & 1 and 0 <= addend - va
                and addend - va + 16 <= filesz
                and addend - va < memsz):
            at = offset + addend - va
            if at + 16 <= len(libc):
                matching.append({"source_offset": at, "segment_vaddr": va,
                                 "flags": flags, "segment_file_offset": offset})
    need(len(matching) == 1,
         "exactly one actual original executable PT_LOAD contains IFUNC resolver addend")
    return matching[0]

def validate(record: dict, row: dict):
    need(record["source_index"] == 85
         and record["source_table"] == "DT_RELA"
         and record["source_table_ordinal"] == 85
         and record["relocation"] == "R_X86_64_IRELATIVE"
         and record["symbol_index"] == 0
         and record["original_slot_file_qword"] == "0x0"
         and record["signed_original_elf_r_addend"] == row["signed_addend"]
         and record["candidate_resolver_guest_RIP"] == hex(LIBC_BIAS + row["signed_addend"])
         and record["original_slot_guest_address"] == row["original_guest_target"]
         and len(bytes.fromhex(record["resolver_entry_first_16_original_source_bytes_hex"])) == 16,
         "original zero qword, DT_RELA #85 and SHA source resolver address")
    for key in (
        "native_original_resolver_entry_trap_proven",
        "native_original_resolver_return_or_zero_result_proven",
        "zero_to_zero_actual_native_slot_store_proven",
        "stage_C_forty_original_native_writers_one_FEX_pid_proven",
        "full_original_GNU_loader_closure_proven",
        "Android_Bionic_Wine_Proton_games_proven",
    ):
        need(record[key] is False, "source-only not native execution: " + key)

def negative_controls(record: dict, row: dict):
    cases = [
        ("wrong_index", "source_index", 86),
        ("wrong_table", "source_table", "DT_JMPREL"),
        ("wrong_ordinal", "source_table_ordinal", 84),
        ("wrong_relocation", "relocation", "R_X86_64_JUMP_SLOT"),
        ("forged_symbol", "symbol_index", 1),
        ("forged_initial", "original_slot_file_qword", "0x1"),
        ("forged_addend", "signed_original_elf_r_addend", row["signed_addend"] + 1),
        ("forged_entry", "candidate_resolver_guest_RIP", "0x1"),
        ("forged_target", "original_slot_guest_address", "0x2"),
        ("fake_resolver_proof", "native_original_resolver_entry_trap_proven", True),
        ("fake_zero_store", "zero_to_zero_actual_native_slot_store_proven", True),
        ("fake_game_claim", "Android_Bionic_Wine_Proton_games_proven", True),
    ]
    need(len(cases) == 12, "twelve fail-closed original GNU source checks")
    rejected = []
    for name, key, bad in cases:
        mutant = copy.deepcopy(record)
        need(mutant[key] != bad, "adversarial mutation must change source evidence")
        mutant[key] = bad
        try:
            validate(mutant, row)
        except (AssertionError, KeyError, ValueError, TypeError):
            rejected.append(name)
        else:
            raise AssertionError("FORGED_GNU_IFUNC85_SOURCE_ACCEPTED " + name)
    need(len(rejected) == len(cases), "all forged IRELATIVE85 source records rejected")
    return rejected

def run(triad: Path, ledger: Path, out: Path):
    original = source_run(triad, ledger, out / "regenerated")
    need(original["schema"] == MIXED_SCHEMA
         and original["original_source_indices"] == list(range(80, 120))
         and original["new_same_guest_native_writers_proven"] == 0,
         "actual original 40 mixed GNU relocation source only")
    row = original["all_forty_source_records"][5]
    need(row["index"] == 85 and row["original_table"] == "DT_RELA"
         and row["original_table_ordinal"] == 85
         and row["relocation_type_number"] == 37
         and row["relocation_type"] == "R_X86_64_IRELATIVE"
         and row["symbol_index"] == 0 and row["original_source_file_qword"] == "0x0"
         and type(row["signed_addend"]) is int and row["signed_addend"] >= 0,
         "actual SHA original IRELATIVE85 ELF entry, not assumed resolver")
    libc = real_bytes(triad / "lib/x86_64-linux-gnu/libc.so.6", 2_500_000)
    need(hashlib.sha256(libc).hexdigest() == LIBC_SHA,
         "original GNU libc SHA unchanged")
    seg = resolver_location(libc, row["signed_addend"])
    start = seg["source_offset"]
    value = {
        "schema": SCHEMA,
        "original_libc_sha256": LIBC_SHA,
        "source_index": 85, "source_table": "DT_RELA", "source_table_ordinal": 85,
        "relocation": "R_X86_64_IRELATIVE",
        "symbol_index": 0, "original_slot_file_qword": "0x0",
        "signed_original_elf_r_addend": row["signed_addend"],
        "candidate_resolver_guest_RIP": hex(LIBC_BIAS + row["signed_addend"]),
        "original_slot_guest_address": row["original_guest_target"],
        "resolver_entry_source_file_offset": hex(start),
        "resolver_entry_first_16_original_source_bytes_hex": libc[start:start+16].hex(),
        "original_resolver_executable_ELF_PT_LOAD": seg,
        "native_original_resolver_entry_trap_proven": False,
        "native_original_resolver_return_or_zero_result_proven": False,
        "zero_to_zero_actual_native_slot_store_proven": False,
        "stage_C_forty_original_native_writers_one_FEX_pid_proven": False,
        "full_original_GNU_loader_closure_proven": False,
        "Android_Bionic_Wine_Proton_games_proven": False,
    }
    validate(value, row)
    value["twelve_forged_IFUNC85_source_claims_rejected"] = negative_controls(value, row)
    out.mkdir(parents=True, exist_ok=True)
    (out / OUT).write_text(json.dumps(value, indent=2) + "\n")
    print("KERNIX_C_GNU_ORIGINAL_IRELATIVE85_RESOLVER_ENTRY_SOURCE_SHA_PASS",
          value["candidate_resolver_guest_RIP"],
          "12_FORGED_SOURCE_CLAIMS_REJECTED_NO_NATIVE_EXECUTION")
    return value

if __name__ == "__main__":
    need(len(sys.argv) == 4, "usage original_GNU_triad canonical147_ledger out")
    run(*map(Path, sys.argv[1:]))
