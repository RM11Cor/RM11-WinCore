#!/usr/bin/env python3
"""Plan four NEW source-distinct IFUNC141..144 original GNU relocation target watches.

One immutable original x86 libc source scan and one independently certified
IFUNC137-140 four native writer receipts prerequisite. Four separate GDB watch files are SOURCE ONLY:
never claim a new live FEX writer, original resolver return or Android support.
"""
from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA, LDSO_SHA, decode_original_libc, classify,
)
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import (
    GUEST_MAIN, LIBC_BIAS, LDSO_BIAS, CALL, CALLER_RETURN, STORE,
)

START, END = 141, 145
CERTIFIED_PREVIOUS_COUNT = 55
PREFIX = "original-libc-IFUNC141-144-source-batch-NOT-NATIVE-HARDWARE-PROOF"


def require(ok: bool, label: str) -> None:
    if not ok:
        raise AssertionError("FAIL-CLOSED original GNU IFUNC141-144 source batch: " + label)


def original_bytes(root: Path) -> tuple[bytes, bytes]:
    libp = root / "lib/x86_64-linux-gnu/libc.so.6"
    ldp = root / "lib64/ld-linux-x86-64.so.2"
    require(libp.is_file() and ldp.is_file() and not libp.is_symlink()
            and not ldp.is_symlink(), "original triad libc/ldso paths")
    libc, ldso = libp.read_bytes(), ldp.read_bytes()
    require(len(libc) == 2118168 and hashlib.sha256(libc).hexdigest() == LIBC_SHA,
            "original GNU libc SHA256/size")
    require(len(ldso) == 235408 and hashlib.sha256(ldso).hexdigest() == LDSO_SHA,
            "original GNU ldso SHA256/size")
    for guest, op in ((CALL, bytes.fromhex("ffd0")),
                      (CALLER_RETURN, bytes.fromhex("4883c318")),
                      (STORE, bytes.fromhex("498906"))):
        require(ldso[source_offset(ldso, guest-LDSO_BIAS, len(op), 5):
                     source_offset(ldso, guest-LDSO_BIAS, len(op), 5)+len(op)] == op,
                "original x86 GNU ldso CALL/caller-return/STORE bytes")
    return libc, ldso


def gdb_writer_only(index: int, target: int, resolver: int, old: int,
                    break_at: str) -> str:
    # This script cannot certify anything until an actual FEX Linux ARM64
    # hardware trace is run AND checked with independent negative controls.
    script = (
        "set pagination off\nset confirm off\nset breakpoint pending on\n"
        "set output-radix 16\nhandle SIGBUS nostop noprint pass\n"
        "handle SIGCHLD nostop noprint pass\n"
        f"break {break_at}\n"
        "commands\nsilent\n"
        f'printf "KERNIX_G0_BATCH_IFUNC{index}_SOURCE_ONLY_WATCH_ARMED '
        f'index={index} resolver={hex(resolver)} target={hex(target)} '
        f'old={hex(old)} NOT_EXECUTED=1\\n"\n'
        f"x/gx {hex(target)}\n"
        f"watch -location *(unsigned long long *){hex(target)}\n"
        "condition 2 $pc >= 0xffff00000000 && $x28 >= 0xffff00000000\n"
        "continue\nend\nrun\n"
        f'printf "KERNIX_G0_BATCH_IFUNC{index}_RAW_TARGET_HARDWARE_HIT '
        f'target={hex(target)} pc=0x%lx guest_x4=0x%lx '
        f'guest_x19=0x%lx guest_x28=0x%lx RAW_NOT_INDEPENDENT=1\\n",'
        '$pc,$x4,$x19,$x28\n'
        f"x/gx {hex(target)}\n"
        "x/i $pc-4\n"
        "set $hdr=*(unsigned long long *)$x28\n"
        "set $off=*(unsigned int *)$hdr\n"
        "set $tail=$hdr+$off\n"
        "set $entry=*(unsigned long long *)($tail+8)\n"
        "set $size=*(unsigned long long *)($tail+16)\n"
        "set $cnt=*(unsigned int *)($tail+24)\n"
        f'printf "KERNIX_G0_BATCH_IFUNC{index}_SOURCE_GNU_JIT '
        'guest_entry=0x%lx source_size=0x%lx native_count=%u\\n",'
        '$entry,$size,$cnt\n'
        "x/8bx $entry\n"
        f"x/8bx {hex(STORE)}\n"
        f"x/8bx {hex(resolver)}\n"
        f'printf "KERNIX_G0_BATCH_IFUNC{index}_RAW_WRITER_ONLY_NO_ATTESTATION=1\\n"\n'
        "quit\n"
    )
    require(script.count(f"watch -location *(unsigned long long *){hex(target)}") == 1,
            "one watch for exact new original source target")
    require("awatch -location" not in script and "rwatch -location" not in script,
            "writer-only native watchpoints")
    return script


def run(root: Path, previous_path: Path, repo: Path, out: Path) -> dict:
    libc, ldso = original_bytes(root)
    rows = decode_original_libc(libc)
    require(classify(rows)["original_total_RELA_and_JMPREL"] == 147,
            "original 147 relocation data source")
    ifunc = [r for r in rows if r["r_type"] == 37]
    require(len(ifunc) == 46 and [r["index"] for r in ifunc] == [85, *range(102,147)],
            "complete original 46 IFUNC source indices")
    require(len({r["r_addend"] for r in ifunc}) == 42,
            "real original 42 distinct IFUNC resolvers")
    require(previous_path.is_file() and not previous_path.is_symlink(),
            "previous four independent original GNU IFUNC137-140 hardware receipts")
    prior = json.loads(previous_path.read_text())
    require(prior["original_source_libc_sha256"] == LIBC_SHA
            and prior["original_source_ldso_sha256"] == LDSO_SHA,
            "prior independent batch original ELF SHA256")
    require(prior["original_source_indices"] == [137, 138, 139, 140],
            "previous four genuine native target indices")
    require(prior["prior_independently_certified_native_hardware_target_count"] == 51
            and prior["new_distinct_original_GNU_native_hardware_writer_targets"] == 4
            and prior["unique_original_libc_native_hardware_writer_target_count"] == 55,
            "previous 55 individually independently attested original writers")
    require(prior["four_separate_FEX_guest_processes_share_one_FEX_build"] is True
            and prior["one_single_FEX_guest_process_for_all_four_writes_proven"] is False,
            "never claim prior four sources were one guest process")
    require(prior["original_IFUNC137_140_CALL_C3_RET_native_stack_HW_READ_proven"] is False
            and prior["all_147_original_libc_RELA_JMPREL_writers_same_process_proven"] is False
            and prior["Android_Bionic_Wine_Proton_games_proven"] is False,
            "no unsupported guest return/Android claims")
    require(len(prior["four_independent_native_hardware_writer_receipts"]) == 4
            and sum(len(v) for v in prior["forty_native_hardware_tamper_cases_rejected"].values()) == 40,
            "previous genuine four writer receipts and forty anti-forgery cases")
    host = (repo / GUEST_MAIN)
    require(host.is_file() and not host.is_symlink(), "original native FEX source host")
    markers = [i for i, line in enumerate(host.read_text().splitlines(), 1)
               if line.strip() == "++RealOriginalLdsoLibcCloses;"]
    require(len(markers) == 1, "single bounded source original libc closure marker")
    break_at = f"{GUEST_MAIN}:{markers[0]}"
    assert len(rows) == 147
    records = []
    for index in range(START, END):
        r = rows[index]
        require(r["index"] == index and r["r_type"] == 37 and r["r_sym"] == 0
                and r["table"] == "DT_JMPREL" and r["table_index"] == index - 86,
                "original GNU source IFUNC index/table/type "+str(index))
        resolver = LIBC_BIAS + r["r_addend"]
        target = LIBC_BIAS + int(r["r_offset"], 16)
        old = int(r["original_source_qword"], 16)
        require(old != 0 and target == int(r["source_guest_target"], 16),
                "original guest target/qword parity "+str(index))
        require(target not in {int(prev["source_guest_target"], 16)
                               for prev in rows[:index]},
                "no duplicate prior target "+str(index))
        resolver_off = source_offset(libc, r["r_addend"], 8, 5)
        target_off = source_offset(libc, int(r["r_offset"], 16), 8, 6,
                                   nonexec=True)
        require(int.from_bytes(libc[target_off:target_off+8], "little") == old,
                "ELF original target initial value "+str(index))
        aliases = [q["index"] for q in ifunc if q["r_addend"] == r["r_addend"]]
        require(index in aliases and len(aliases) in (1, 2),
                "actual original source IFUNC resolver aliases "+str(index))
        gdb = gdb_writer_only(index, target, resolver, old, break_at)
        label = f"original-libc-IFUNC{index}-source-only-distinct-native-write-plan"
        (out / f"{label}.gdb").write_text(gdb)
        receipt = {
            "schema":"kernix.g0.original-gnu-libc-ifunc-batched-source-writer-watch.v1",
            "original_source_libc_sha256":LIBC_SHA,
            "original_source_ldso_sha256":LDSO_SHA,
            "original_relocation_index":index,
            "original_table":r["table"],
            "original_table_ordinal":r["table_index"],
            "relocation_type":"R_X86_64_IRELATIVE",
            "original_guest_resolver":hex(resolver),
            "original_source_resolver_elf_offset":hex(resolver_off),
            "original_guest_target":hex(target),
            "original_source_target_elf_offset":hex(target_off),
            "original_unmodified_target_qword":hex(old),
            "original_resolver_alias_indices":aliases,
            "previous_unique_native_writers_independently_certified":55,
            "this_batch_new_native_writer_receipts":0,
            "this_batch_native_guest_RET_hardware_READ_proven":False,
            "source_plan_only_not_real_native_FEX_execution":True,
            "Android_Bionic_Wine_Proton_games_proven":False,
        }
        (out / f"{label}.json").write_text(json.dumps(receipt,indent=2)+"\n")
        records.append(receipt)
        print("KERNIX_G0_ORIGINAL_IFUNC_BATCH_SOURCE_ONLY",index,
              "resolver",hex(resolver),"target",hex(target),
              "old",hex(old),"aliases",aliases)
    require(len(records) == 4 and len({x["original_guest_target"] for x in records}) == 4,
            "four distinct genuine source targets")
    out_record = {
        "schema":"kernix.g0.original-ifunc141-144-source-batch-no-native-proof.v1",
        "original_source_libc_sha256":LIBC_SHA,
        "original_source_ldso_sha256":LDSO_SHA,
        "previous_original_four_native_IFUNC137_140_writer_proof_run":42844416071,
        "certified_prior_native_writer_ledger":55,
        "exact_original_source_indices":[141,142,143,144],
        "new_source_candidates":records,
        "source_candidates_derived_in_one_hash_verified_batch":4,
        "new_independently_native_writer_attested_targets":0,
        "new_same_guest_CALL_RET_stack_READ_attestations":0,
        "full_original_147_same_guest_relocations_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
        "batch_execution_note":
            "Four separate exact-source writer watches prepared in a single preflight. "
            "Native Linux FEX hardware writes and independent per-target receipts remain pending. "
            "Share FEX compilation in future group runtime; never share/fabricate target receipts.",
    }
    (out / (PREFIX+".json")).write_text(json.dumps(out_record, indent=2)+"\n")
    return out_record


if __name__ == "__main__":
    require(len(sys.argv) == 5, "usage triad-root previous-full-native-proof repo-root out-dir")
    destination = Path(sys.argv[4])
    destination.mkdir(parents=True, exist_ok=True)
    answer = run(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]),
                 destination)
    print("KERNIX_G0_IFUNC141_144_BULK_SOURCE_PREFLIGHT_4_DISTINCT_TARGETS_COMPLETE"
          "_KEEP_NATIVE_LEDGER_55_OF_147_NO_NEW_NATIVE_ATTESTATIONS")
