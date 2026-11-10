#!/usr/bin/env python3
"""G0 original GNU x86 libc IFUNC85: source-only DT_RELA zero-qword candidate.

Unlike IFUNC102..146 this is DT_RELA ordinal 85, initially ZERO, and is
not a DT_JMPREL write. Never infer its watch can arm after the JMPREL closure;
native order/arm timing must be independently established before a proof.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA, LDSO_SHA, decode_original_libc, classify,
)
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import (
    GUEST_MAIN, LIBC_BIAS, LDSO_BIAS, CALL, CALLER_RETURN, STORE,
)

IDX = 85
PREFIX = "original-libc-IFUNC85-DT_RELA-zero-source-only-NO-NATIVE-PROOF"


def require(yes: bool, label: str) -> None:
    if not yes:
        raise AssertionError("FAIL-CLOSED original GNU IFUNC85 source: " + label)


def run(triad: Path, old_proof: Path, repo: Path, out: Path) -> dict:
    libcpath = triad / "lib/x86_64-linux-gnu/libc.so.6"
    ldsopath = triad / "lib64/ld-linux-x86-64.so.2"
    require(libcpath.is_file() and ldsopath.is_file()
            and not libcpath.is_symlink() and not ldsopath.is_symlink(),
            "immutable original GNU source files")
    libc, ldso = libcpath.read_bytes(), ldsopath.read_bytes()
    require(len(libc) == 2118168 and hashlib.sha256(libc).hexdigest() == LIBC_SHA,
            "original GNU x86 libc SHA256")
    require(len(ldso) == 235408 and hashlib.sha256(ldso).hexdigest() == LDSO_SHA,
            "original GNU x86 ldso SHA256")
    for address, op in ((CALL, bytes.fromhex("ffd0")),
                        (CALLER_RETURN, bytes.fromhex("4883c318")),
                        (STORE, bytes.fromhex("498906"))):
        off = source_offset(ldso, address - LDSO_BIAS, len(op), 5)
        require(ldso[off:off + len(op)] == op, "unaltered original x86 loader CALL/STORE bytes")
    rows = decode_original_libc(libc)
    typ = classify(rows)
    require(len(rows) == 147 and typ["original_DT_RELA_count"] == 86
            and typ["original_DT_JMPREL_count"] == 61,
            "original full GNU RELA and JMPREL immutable table")
    require(typ["original_DT_RELA_type_counts"]["R_X86_64_IRELATIVE"] == 1,
            "exactly one original DT_RELA IRELATIVE")
    r = rows[IDX]
    require(r["index"] == IDX and r["table"] == "DT_RELA"
            and r["table_index"] == IDX and r["r_type"] == 37 and r["r_sym"] == 0,
            "genuine unique DT_RELA IFUNC85 not JMPREL")
    require(r["original_source_qword"] == "0x0",
            "the original target is ZERO, unlike JMPREL targets")
    require([x["index"] for x in rows if x["r_type"] == 37] ==
            [85, *range(102,147)], "all original 46 IFUNC source indices")
    require(len({x["r_offset"] for x in rows}) == 147,
            "no source target alias or double-counting")

    require(old_proof.is_file() and not old_proof.is_symlink(),
            "previous 61 original independent target writer proof file")
    prev = json.loads(old_proof.read_text())
    require(prev["original_source_libc_sha256"] == LIBC_SHA
            and prev["original_source_ldso_sha256"] == LDSO_SHA,
            "previous immutable original source hashes")
    require(prev["original_source_indices"] == [145,146]
            and prev["prior_independently_certified_native_hardware_target_count"] == 59
            and prev["new_distinct_original_GNU_native_hardware_writer_targets"] == 2
            and prev["unique_original_libc_native_hardware_writer_target_count"] == 61,
            "two new independent IFUNC145-146 hardware receipts and prior 59")
    require(prev["two_separate_FEX_guest_processes_share_one_FEX_build"] is True
            and prev["one_single_FEX_guest_process_for_both_writes_proven"] is False,
            "never mislabel two guest processes as one")
    require(len(prev["two_independent_native_hardware_writer_receipts"]) == 2
            and sum(map(len, prev["twenty_native_hardware_tamper_cases_rejected"].values())) == 20,
            "two independent original writer witnesses with 20 negative controls")
    require(prev["original_IFUNC145_146_CALL_C3_RET_native_stack_HW_READ_proven"] is False
            and prev["all_147_original_libc_RELA_JMPREL_writers_same_process_proven"] is False
            and prev["Android_Bionic_Wine_Proton_games_proven"] is False,
            "do not fabricate full loader or Android game success")

    target = LIBC_BIAS + int(r["r_offset"], 16)
    resolver = LIBC_BIAS + int(r["r_addend"])
    target_off = source_offset(libc, int(r["r_offset"],16), 8, 6, nonexec=True)
    resolver_off = source_offset(libc, int(r["r_addend"]), 8, 5)
    require(int.from_bytes(libc[target_off:target_off+8], "little") == 0,
            "actual immutable ELF target location must be zero")
    aliases = [x["index"] for x in rows if x["r_type"] == 37
               and x["r_addend"] == r["r_addend"]]
    require(85 in aliases, "actual IFUNC85 resolver alias provenance")
    require(target not in {int(x["source_guest_target"],16) for x in rows if x["index"] != IDX},
            "unique target against all other 146 source relocations")

    host = repo / GUEST_MAIN
    require(host.is_file() and not host.is_symlink(), "genuine FEX guest main source")
    marks = [i for i,line in enumerate(host.read_text().splitlines(),1)
             if line.strip() == "++RealOriginalLdsoLibcCloses;"]
    require(len(marks) == 1, "unique previous native writer closure marker")
    # Candidate only: source old qword is zero and DT_RELA may run BEFORE this marker.
    # The runtime must independently establish the zero qword at watch arm time,
    # or choose an earlier source-locked FEX breakpoint. DO NOT call this a hit.
    gdb = (
        "set pagination off\nset confirm off\nset breakpoint pending on\n"
        "handle SIGBUS nostop noprint pass\nhandle SIGCHLD nostop noprint pass\n"
        f"break {GUEST_MAIN}:{marks[0]}\n"
        "commands\nsilent\n"
        f'printf "KERNIX_G0_IFUNC85_DT_RELA_CANDIDATE_PREWATCH target={hex(target)} '
        f'original_zero=1 NOT_NATIVE_PROOF=1\\n"\n'
        f"x/gx {hex(target)}\n"
        f"watch -location *(unsigned long long *){hex(target)}\n"
        "condition 2 $pc >= 0xffff00000000 && $x28 >= 0xffff00000000\n"
        "continue\nend\nrun\n"
        f'printf "KERNIX_G0_IFUNC85_DT_RELA_RAW_UNVERIFIED_HIT target={hex(target)} '
        'pc=0x%lx x19=0x%lx RAW_NOT_INDEPENDENT=1\\n",$pc,$x19\n'
        f"x/gx {hex(target)}\n"
        "x/i $pc-4\n"
        f'printf "KERNIX_G0_IFUNC85_DT_RELA_NO_NATIVE_ATTESTATION=1\\n"\n'
        "quit\n"
    )
    require(gdb.count(f"watch -location *(unsigned long long *){hex(target)}") == 1,
            "source watch is exact only once")
    require("awatch -location" not in gdb and "rwatch -location" not in gdb,
            "native source candidate is WRITE only")

    obj = {
        "schema": "kernix.g0.original-gnu-libc-ifunc85-dt-rela-zero-source-only.v1",
        "original_source_libc_sha256": LIBC_SHA,
        "original_source_ldso_sha256": LDSO_SHA,
        "original_relocation_index": 85,
        "original_table": "DT_RELA",
        "original_table_ordinal": 85,
        "relocation_type": "R_X86_64_IRELATIVE",
        "original_guest_resolver": hex(resolver),
        "original_source_resolver_elf_offset": hex(resolver_off),
        "original_guest_target": hex(target),
        "original_source_target_elf_offset": hex(target_off),
        "original_unmodified_target_qword": "0x0",
        "original_resolver_alias_indices": aliases,
        "previously_independently_certified_native_writers": 61,
        "new_native_writer_attestations": 0,
        "source_only_not_native_hardware_proof": True,
        "prior_independent_proof_run": 42854380835,
        "prewatch_may_be_after_DT_RELA_write": True,
        "same_guest_CALL_C3_RET_stack_READ_proven": False,
        "all_147_same_guest_relocations_proven": False,
        "Android_Bionic_Wine_Proton_games_proven": False,
        "native_next_gate": "verify arm-before-write and original zero-to-write under real ARM64 FEX; no observed write assumed",
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / (PREFIX + ".json")).write_text(json.dumps(obj, indent=2) + "\n")
    (out / (PREFIX + ".gdb")).write_text(gdb)
    print("KERNIX_G0_GNU_IFUNC85_DISTINCT_DT_RELA_ZERO_QWORD_SOURCE_ONLY_PASSED_KEEP_NATIVE_61_OF_147")
    return obj


if __name__ == "__main__":
    require(len(sys.argv) == 5, "usage: original-source-triad-root previous-independent-proof repo-root out-dir")
    run(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]))
