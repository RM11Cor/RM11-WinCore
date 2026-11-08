#!/usr/bin/env python3
"""Independent two-slot GNU ldso x86 guest writer RIP receipt replay (G0 only).

Requires authentic, separately emitted, SHA-locked ARM64 FEX runtime receipts
from native x86 writer RIP validators for source main GLOB_DAT and JUMP_SLOT.
The x86 instruction may have the SAME original GNU ldso guest RIP in two
different runtime processes while writing distinct original main addresses.
That is NOT eight writers, RELRO, mprotect or Windows game compatibility.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

FEX = "02e24ca5c01ed0c864466ed573db347336f70170"
WRITER_RIP = "0x80100fb8b"
EXPECTED = {
    "strong": {
        "schema": "kernix.g0.strong-globdat-exact-guest-rip.v1",
        "target": "0x800003fd8",
        "value": "0x80402a200",
        "symbol": "__libc_start_main",
        "type": "GLOB_DAT",
    },
    "puts": {
        "schema": "kernix.g0.puts-jumpslot-exact-guest-rip.v1",
        "target": "0x800003fd0",
        "value": "0x804087bc0",
        "symbol": "puts",
        "type": "JUMP_SLOT",
    },
}

class Refuse(ValueError):
    pass

def require(ok, reason):
    if not ok:
        raise Refuse(reason)

def review(raw: dict, key: str) -> dict:
    desc = EXPECTED[key]
    require(isinstance(raw, dict) and raw.get("schema") == desc["schema"],
            "wrong original guest writer evidence receipt schema: " + key)
    require(raw.get("original_FEX_source_commit") == FEX,
            "wrong original FEX pinned revision for " + key)
    require(raw.get("original_guest_writer_RIP") == WRITER_RIP
            and raw.get("original_guest_writer_RIP_proven") is True
            and raw.get("exact_original_guest_writer_RIP_proven") is True,
            "exact original GNU ld-linux guest RIP unproven for " + key)
    require(raw.get("source_x86_instruction") == "mov QWORD PTR [rax],r9",
            "wrong original x86 writer opcode: " + key)
    require(raw.get("source_RAX_arm64_x") == 4 and raw.get("source_R9_arm64_x") == 13,
            "wrong pinned FEX original guest GPR source mapping: " + key)
    require(raw.get("live_x4") == desc["target"] and raw.get("live_x13") == desc["value"],
            "wrong original main source destination or resolved symbol value: " + key)
    require(raw.get("FEX_source_rip_pairs") == [[4,0],[8,0]],
            "wrong original JIT x86-to-AArch64 source RIP offset mapping: " + key)
    for f in ("original_main_all_relocations_proven", "original_main_RELRO_sealed",
              "Android_Bionic_or_phone_executed", "Wine_Proton_or_gameplay_proven"):
        require(raw.get(f) is False, "false guest/linker/game claim: " + f)
    return {
        "source_symbol": desc["symbol"],
        "source_relocation_type": desc["type"],
        "original_main_guest_destination": desc["target"],
        "resolved_source_value": desc["value"],
        "original_ldso_x86_writer_RIP": WRITER_RIP,
        "guest_opcode": "mov QWORD PTR [rax],r9",
        "native_jit_store_opcode": "stlr x13,[x4]",
        "exact_guest_RIP_and_source_register_witness": True,
    }

def classify(strong: dict, puts: dict) -> dict:
    a, b = review(strong, "strong"), review(puts, "puts")
    require(a["original_main_guest_destination"] != b["original_main_guest_destination"],
            "one source original main slot counted twice")
    require(a["source_relocation_type"] != b["source_relocation_type"],
            "two independent dynamic relocation types not demonstrated")
    return {
        "schema": "kernix.g0.original-main-two-source-exact-x86-writers-crossrun.v1",
        "original_FEX_upstream_source_commit": FEX,
        "distinct_original_source_main_RELRO_targets_exact_x86_writer_proven": 2,
        "separate_real_native_FEX_guest_processes": True,
        "same_original_GNU_ldso_x86_write_instruction_reused": WRITER_RIP,
        "slots": [a, b],
        "original_main_eight_guest_x86_writer_instructions_proven": False,
        "early_fixture_relative0_x86_ldso_writer_proven": False,
        "authentic_original_main_mprotect10_success": False,
        "main_PT_GNU_RELRO_sealed": False,
        "Android_Bionic_Wine_Proton_games_proven": False,
    }

def negative_tests(strong: dict, puts: dict) -> int:
    cases = [
        ("bad strong source SHA revision", "strong", lambda x: x.update(original_FEX_source_commit="0"*40)),
        ("bad weak source SHA revision", "puts", lambda x: x.update(original_FEX_source_commit="0"*40)),
        ("misassigned original strong symbol", "strong", lambda x: x.update(live_x4="0x800003fd0")),
        ("misassigned puts symbol", "puts", lambda x: x.update(live_x4="0x800003fd8")),
        ("wrong strong libc export", "strong", lambda x: x.update(live_x13="0x0")),
        ("wrong puts libc export", "puts", lambda x: x.update(live_x13="0x0")),
        ("fabricated x86 RIP", "strong", lambda x: x.update(original_guest_writer_RIP="0x80100fb8c")),
        ("fabricated x86 opcode", "puts", lambda x: x.update(source_x86_instruction="mov QWORD PTR [rax],r8")),
        ("wrong FEX register ownership", "strong", lambda x: x.update(source_RAX_arm64_x=5)),
        ("fake x86-host RIP map", "puts", lambda x: x.update(FEX_source_rip_pairs=[[4,0],[8,1]])),
        ("fake main RELRO", "puts", lambda x: x.update(original_main_RELRO_sealed=True)),
        ("fake game", "strong", lambda x: x.update(Wine_Proton_or_gameplay_proven=True)),
        ("fake eight-main relocations", "puts", lambda x: x.update(original_main_all_relocations_proven=True)),
        ("unproven exact guest RIP", "strong", lambda x: x.update(exact_original_guest_writer_RIP_proven=False)),
    ]
    for i, (description, which, change) in enumerate(cases, 1):
        a, b = copy.deepcopy(strong), copy.deepcopy(puts)
        change(a if which == "strong" else b)
        try:
            classify(a, b)
        except (Refuse, KeyError, TypeError, ValueError):
            print(f"KERNIX_G0_TWO_EXACT_SOURCE_GUEST_WRITER_NEGATIVE_{i:02d}_REJECTED {description}")
        else:
            raise Refuse("false original x86 RIP evidence accepted: " + description)
    return len(cases)

def main(argv):
    if len(argv) != 4 or argv[1] != "selftest":
        print("usage: gate.py selftest STRONG_GLOBDAT_JSON PUTS_JUMPSLOT_JSON", file=sys.stderr)
        return 2
    strong, puts = (json.loads(Path(x).read_text()) for x in argv[2:])
    report = classify(strong, puts)
    require(negative_tests(strong, puts) == 14, "missing mandatory false-proof controls")
    print(json.dumps(report,indent=2,sort_keys=True))
    print("KERNIX_G0_TWO_EXACT_SOURCE_X86_WRITERS_PROVEN_DIFFERENT_MAIN_RELRO_TARGETS_NO_FULL_LDSO_RELRO_OR_GAMES")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except (Refuse, KeyError, TypeError, ValueError) as err:
        print("KERNIX_G0_TWO_MAIN_GUEST_RIP_CROSSRUN_FAIL_CLOSED: " + str(err), file=sys.stderr)
        raise SystemExit(1)
