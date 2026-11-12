#!/usr/bin/env python3
"""Synthetic-only verifier unit tests. NOT a native ARM64 FEX run."""
import json

from kernix_g0_l40_c_first_four_original_writers_independent_gate import (
    audit, negative_controls, PREFIX, NAMES,
)
from kernix_g0_l40_c_original_globdat80_83_real_fex_four_writers_plan import SCHEMA as PLAN_SCHEMA

def mark(kind, record):
    return PREFIX + kind + " " + json.dumps(record, sort_keys=True)

def fixture():
    pid = 4444
    rows = [
        {"index": i, "target": hex(0x5000 + (i - 80) * 8),
         "candidate": hex(0x6000 + (i - 80) * 8),
         "relocation_type": "R_X86_64_GLOB_DAT"}
        for i in (80, 81, 82, 83)
    ]
    source = {
        "schema": PLAN_SCHEMA, "source_indices": [80, 81, 82, 83],
        "four_genuine_original_ELF_GLOB_DAT_source_tuples": rows,
    }
    lines = ["SYNTHETIC_FIXTURE_ONLY_NO_REAL_HARDWARE_TEST"]
    for row in rows:
        lines.append(mark(NAMES[0], {
            "index": row["index"], "pid": pid,
            "target": row["target"], "value": "0x0",
        }))
    lines.append(mark(NAMES[1], {
        "pid": pid, "indices": [80, 81, 82, 83],
    }))
    for row in rows:
        lines.append(mark(NAMES[2], {
            "index": row["index"], "pid": pid,
            "pc": "0xffff00000010", "x4": row["target"],
            "x13": row["candidate"], "x28": "0xffff00001000",
            "target": row["target"], "value": row["candidate"],
            "instruction": "0xffff0000000c: stlr x13, [x4]",
            "source_x86_3bytes": "4c8908",
            "FEX_guest_entry": "0x80100fb8b",
            "FEX_guest_size": 3, "FEX_native_ops": 2,
        }))
    lines.append(mark(NAMES[3], {
        "pid": pid, "indices": [80, 81, 82, 83],
        "targets": [x["target"] for x in rows],
        "values": [x["candidate"] for x in rows],
        "all_147_same_guest_proven": False,
        "Android_Bionic_Wine_Proton_games_proven": False,
    }))
    return "\n".join(lines) + "\n", source

def must_reject(log, source):
    try:
        audit(log, source)
    except (AssertionError, KeyError, ValueError, TypeError):
        return
    raise AssertionError("SYNTHETIC_FORGED_GDB_TRACE_ACCEPTED")

def main():
    log, source = fixture()
    result = audit(log, source)
    assert result["pid"] == 4444
    denied = negative_controls(log, source)
    assert len(denied) == 28
    lines = log.splitlines()
    # Independent adversarial chronology/count/scope checks in addition to 28 mutations.
    must_reject("\n".join(lines[:-1]) + "\n", source)  # missing final
    must_reject(log + lines[-1] + "\n", source)          # duplicated final
    must_reject(log.replace("SYNTHETIC_FIXTURE_ONLY", "KERNIX_G0_L40_C_REJECT_FAKE"), source)
    must_reject(log.replace('"FEX_native_ops": 2', '"FEX_native_ops": 3', 1), source)
    must_reject(log.replace('"all_147_same_guest_proven": false',
                            '"all_147_same_guest_proven": true'), source)
    print("KERNIX_G0_C_FIRST4_GATE_SYNTHETIC_UNIT_PASS_28_MUTATIONS_AND_5_ADVERSARIAL_ONLY")
    print("NO_NATIVE_PROOF_NO_RELOCATION_COUNT_INCREASE_NO_ANDROID_OR_GAME_EXECUTION")

if __name__ == "__main__":
    main()
