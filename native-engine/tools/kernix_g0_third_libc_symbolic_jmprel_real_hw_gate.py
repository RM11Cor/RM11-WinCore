#!/usr/bin/env python3
"""Third original libc symbolic JMPREL: strictly source-pinned FEX hardware gate.

Modes:
  prepare DIST -- generate read-only source-backed GDB write-only watch plan.
  attest  DIST -- accept only an actual later native hardware store in a fresh
                  original GNU Linux x86 guest under real FEX Linux ARM64.
Never equate an armed watchpoint, GDB exit 0, or a static ELF pointer with a
hardware writer. Android, Bionic, Wine, DXVK, and games are not tested here.
"""
from pathlib import Path
import hashlib
import json
import re
import sys

from kernix_g0_libc_rela_source_inventory_gate import make_inventory
from kernix_g0_next_libc_symbolic_live_writer_gate import (
    source_offset, unique, LIBC_SHA, LDSO_SHA, LIBC_BASE, LDSO_BASE
)

OLD_GDB = "original-libc-next-symbolic-jmprel-native-write-watch-plan.gdb"
NEW_GDB = "original-libc-third-symbolic-jmprel-native-write-watch-plan.gdb"
NEW_PLAN = "original-libc-third-symbolic-jmprel-native-write-watch-plan.json"
NEW_LOG = "original-libc-third-symbolic-jmprel-live-fex-hw.log"
NEW_PROOF = "original-libc-third-symbolic-jmprel-real-fex-hw-verified.json"


def inputs(dist):
    source = dist / "original-source-pinned-root"
    libc = (source / "lib/x86_64-linux-gnu/libc.so.6").read_bytes()
    ldso = (source / "lib64/ld-linux-x86-64.so.2").read_bytes()
    assert len(libc) == 2118168 and hashlib.sha256(libc).hexdigest() == LIBC_SHA
    assert len(ldso) == 235408 and hashlib.sha256(ldso).hexdigest() == LDSO_SHA
    inv = make_inventory(libc)
    saved = json.loads((dist / "original-libc-147-rela-jmprel-source-inventory.json").read_text())
    assert inv == saved
    first = json.loads((dist / "original-fex-libc-symbolic-jmprel-first-real-native-writer-proof.json").read_text())
    second = json.loads((dist / "original-libc-next-symbolic-jmprel-live-fex-hw-verified.json").read_text())
    assert first["one_original_libc_symbolic_JMPREL_real_hardware_store_proven"] is True
    assert first["selected_original_record_index"] == 86
    assert first["guest_original_target"] == "0x804202ba0"
    assert second["genuine_second_symbolic_source_hardware_store_proven"] is True
    assert second["source_record_index"] == 87
    assert second["source_original_guest_target"] == "0x804202bc0"
    assert second["source_original_qword"] == "0x28060"
    assert second["hardware_recorded_after_qword"] == "0x8040ae650"
    assert second["source_libc_sha256"] == LIBC_SHA
    assert second["source_original_gnu_ldso_sha256"] == LDSO_SHA
    candidates = inv["next_source_candidates"]
    assert len(candidates) >= 2 and [r["index"] for r in candidates[:2]] == [87, 88]
    candidate = candidates[1]
    assert candidate["table"] == "DT_JMPREL"
    assert candidate["r_type"] == 7 and candidate["r_sym"] > 0
    assert int(candidate["source_qword"], 16) != 0
    target = int(candidate["source_guest_target"], 16)
    old = int(candidate["source_qword"], 16)
    assert target == LIBC_BASE + int(candidate["r_offset"], 16) and target % 8 == 0
    assert int.from_bytes(libc[source_offset(libc, target-LIBC_BASE, 8, 6, nonexec=True):
                               source_offset(libc, target-LIBC_BASE, 8, 6, nonexec=True)+8], "little") == old
    return libc, ldso, candidate, first, second


def prepare(dist):
    libc, ldso, candidate, first, second = inputs(dist)
    prior = json.loads((dist / "original-libc-next-symbolic-jmprel-native-write-watch-plan.json").read_text())
    assert prior["next_candidate_original_source_index"] == 87
    assert prior["next_candidate_original_guest_target"] == "0x804202bc0"
    assert prior["next_candidate_original_source_qword"] == "0x28060"
    assert prior["GDB_native_hardware_watch_kind"] == "write_only_watchpoint"
    earlier = (dist / OLD_GDB).read_text()
    assert earlier.count("watch -location *(unsigned long long *)0x804202bc0") == 1
    assert earlier.count("index=87 target=0x804202bc0 original=0x28060") == 1
    assert earlier.count("x/gx 0x804202bc0") == 2
    assert "awatch -location" not in earlier
    assert earlier.count("KERNIX_G0_NEXT_JMPREL_REAL_NATIVE_HW_WRITE_STOP") == 1
    third_target = candidate["source_guest_target"]
    third_qword = candidate["source_qword"]
    new = earlier.replace("0x804202bc0", third_target)
    new = new.replace("index=87 ", "index=88 ")
    new = new.replace("original=0x28060 ", "original=" + third_qword + " ")
    assert "0x804202bc0" not in new
    assert "index=87 " not in new
    assert "original=0x28060 " not in new
    assert new.count("watch -location *(unsigned long long *)" + third_target) == 1
    assert new.count("index=88 target=" + third_target + " original=" + third_qword) == 1
    assert "awatch" not in new
    # Same exact source breakpoint, native CPU sanity checks and original
    # FEX JIT source capture as first two proven sessions.
    assert "++RealOriginalLdsoLibcCloses" not in new
    assert "NOT_YET_SOURCE_ATTESTED=1" in new
    (dist / NEW_GDB).write_text(new)
    report = {
        "schema": "kernix.g0.third-original-libc-symbolic-jmprel-source-hardware-watch-plan.v1",
        "source_libc_sha256": LIBC_SHA,
        "source_gnu_ldso_sha256": LDSO_SHA,
        "prior_real_first_writer_index": 86,
        "prior_real_second_writer_index": 87,
        "source_candidate_index": 88,
        "source_symbol_id": candidate["r_sym"],
        "source_guest_target": third_target,
        "source_original_qword": third_qword,
        "original_source_table": candidate["table"],
        "GDB_watch_kind": "write-only",
        "one_original_unchanged_guest_process_per_fresh_probe": True,
        "new_native_hw_write_proven": False,
        "next_source_guest_rip_proven": False,
        "remaining_144_rela_jmprel_writers_proven": False,
        "full_relocations_and_IFUNC_proven": False,
        "Android_Bionic_Wine_Proton_games_proven": False,
    }
    (dist / NEW_PLAN).write_text(json.dumps(report, indent=2) + "\n")
    print("KERNIX_G0_THIRD_LIBC_SYMBOLIC_SOURCE_EXACT_NATIVE_WATCH_ARMED_NOT_EXECUTED")


def attest(dist):
    libc, ldso, candidate, first, second = inputs(dist)
    plan = json.loads((dist / NEW_PLAN).read_text())
    assert plan["source_candidate_index"] == candidate["index"] == 88
    assert plan["source_guest_target"] == candidate["source_guest_target"]
    assert plan["source_original_qword"] == candidate["source_qword"]
    assert plan["new_native_hw_write_proven"] is False
    target = int(candidate["source_guest_target"], 16)
    before = int(candidate["source_qword"], 16)
    raw = (dist / NEW_LOG).read_text(errors="replace")
    arm = unique(
        r"^KERNIX_G0_NEXT_SOURCE_SYMBOLIC_JMPREL_NATIVE_WRITER_WATCH_ARMED "
        r"index=(\d+) target=(0x[0-9a-fA-F]+) original=(0x[0-9a-fA-F]+) NO_WRITER_YET=1$", raw)
    assert tuple(int(x, 16) for x in arm[1:]) == (target, before) and int(arm[0]) == 88
    hits = re.findall(
        r"^Hardware watchpoint 2: -location \*\(unsigned long long \*\)0x([0-9a-fA-F]+)$", raw, re.M)
    assert len(hits) == 2 and all(int(x, 16) == target for x in hits)
    old = int(unique(r"^Old value = (0x[0-9a-fA-F]+)$", raw), 16)
    new = int(unique(r"^New value = (0x[0-9a-fA-F]+)$", raw), 16)
    assert old == before and new != old and new != 0
    assert re.search(r"^0x%x:\s+0x%016x$" % (target, new), raw, re.M)
    assert raw.count("KERNIX_G0_LIBC_1214_ORIGINAL_RELOCATION_TARGETS_PRISTINE_AFTER_CLOSE3") == 1
    assert raw.index("KERNIX_G0_LIBC_1214_ORIGINAL_RELOCATION_TARGETS_PRISTINE_AFTER_CLOSE3") < raw.index(
        "KERNIX_G0_NEXT_SOURCE_SYMBOLIC_JMPREL_NATIVE_WRITER_WATCH_ARMED") < raw.index(
        "Old value = ") < raw.index("New value = ")
    hit = unique(
        r"^KERNIX_G0_NEXT_JMPREL_REAL_NATIVE_HW_WRITE_STOP "
        r"target=(0x[0-9a-fA-F]+) after_pc=(0x[0-9a-fA-F]+) "
        r"guest_rsp_x8=(0x[0-9a-fA-F]+) cpu_state_x28=(0x[0-9a-fA-F]+) "
        r"NOT_YET_SOURCE_ATTESTED=1$", raw)
    seen, pc, rsp, state = [int(x, 16) for x in hit]
    assert seen == target and pc >= 0xffff00000000
    assert 0x803000000 <= rsp < 0x803010000 and state >= 0xffff00000000
    stlr = re.findall(r"^\s*0x%x:\s+(stlr\s+x13,\s*\[x4\])\s*$" % (pc-4), raw, re.M)
    assert len(stlr) >= 2 and len(set(stlr)) == 1
    jit = unique(
        r"^KERNIX_G0_NEXT_JMPREL_NATIVE_STOP_FEX_JIT_GUEST_SOURCE "
        r"guest_entry=(0x[0-9a-fA-F]+) guest_size=(0x[0-9a-fA-F]+) "
        r"inst_count=(\d+) host_pc=(0x[0-9a-fA-F]+)$", raw)
    guest, guestsize, count, native_pc = int(jit[0],16), int(jit[1],16), int(jit[2]), int(jit[3],16)
    assert native_pc == pc and guestsize == 3 and count == 2
    source_va = guest - LDSO_BASE
    source_bytes = ldso[source_offset(ldso, source_va, 8, 5):
                        source_offset(ldso, source_va, 8, 5)+8]
    reported = unique(
        r"^0x%x:\s+((?:0x[0-9a-fA-F]{2}\s+){7}0x[0-9a-fA-F]{2})\s*$" % guest, raw)
    observed = bytes(int(z,16) for z in re.findall(r"0x[0-9a-fA-F]{2}", reported))
    assert observed == source_bytes and observed[:3] == bytes.fromhex("4c8908")
    # A symbolic JMPREL may resolve across ELF objects. In this exact
    # source run, record #88 points into authentic GNU ld-linux RX, whereas
    # the first two source-symbolic records pointed inside libc RX.
    # Check ORIGINAL pinned binary ELF PT_LOAD RX provenance, rather than
    # assuming that the relocated pointer must remain in libc.
    source_objects = []
    for name, blob, base in (
        ("original-libc.so.6", libc, LIBC_BASE),
        ("original-ld-linux-x86-64.so.2", ldso, LDSO_BASE),
    ):
        try:
            source_offset(blob, new - base, 1, 5)
        except AssertionError:
            continue
        source_objects.append(name)
    assert source_objects == ["original-ld-linux-x86-64.so.2"], (
        "third resolved pointer is not the SHA-pinned original GNU ldso RX PT_LOAD",
        hex(new), source_objects)

    def isvalid(b, a, op, store, addr):
        return (b == before and a == new and a != b
                and op == bytes.fromhex("4c8908")
                and re.fullmatch(r"stlr\s+x13,\s*\[x4\]", store) is not None
                and addr == target)
    assert isvalid(old, new, observed[:3], stlr[0], target)
    assert not isvalid(new, new, observed[:3], stlr[0], target)
    assert not isvalid(old, 0, observed[:3], stlr[0], target)
    assert not isvalid(old, new, b"\x4c\x89\x00", stlr[0], target)
    assert not isvalid(old, new, observed[:3], "ldr x13, [x4]", target)
    assert not isvalid(old, new, observed[:3], stlr[0], target+8)

    result = {
        "schema": "kernix.g0.third-original-libc-symbolic-jmprel-real-fex-arm64-hardware-write.v1",
        "source_original_libc_sha256": LIBC_SHA,
        "source_original_gnu_ldso_sha256": LDSO_SHA,
        "prior_two_native_symbolic_writers_independently_proven": True,
        "third_original_source_relocation_index": candidate["index"],
        "third_original_source_symbol_id": candidate["r_sym"],
        "third_original_source_guest_target": hex(target),
        "third_original_qword": hex(old),
        "third_real_native_hardware_after_qword": hex(new),
        "third_resolved_pointer_source_original_elf": source_objects[0],
        "third_result_inside_pinned_GNU_ldso_RX_PT_LOAD": True,
        "full_original_elf_symbol_lookup_algorithm_proven": False,
        "third_real_native_after_write_pc": hex(pc),
        "source_original_gnu_guest_store_RIP": hex(guest),
        "source_original_gnu_x86_writer_opcode": observed[:3].hex(),
        "real_native_ARM64_store_opcode": stlr[0],
        "third_symbolic_JMPREL_real_native_hardware_writer_proven": True,
        "cumulative_individually_source_attested_libc_symbolic_JMPREL": 3,
        "remaining_144_original_RELA_JMPREL_writers_proven": False,
        "source_IFUNC_46_real_resolvers_proven": False,
        "full_original_libc_relocations_closed": False,
        "original_guest_main_relocations_closed": False,
        "Android_Bionic_Wine_Proton_games_proven": False,
    }
    (dist / NEW_PROOF).write_text(json.dumps(result, indent=2) + "\n")
    print("KERNIX_G0_THIRD_ORIGINAL_LIBC_SYMBOLIC_JMPREL_REAL_FEX_ARM64_HW_STORE_PASS_NOT_FULL_GLIBC")


if __name__ == "__main__":
    assert len(sys.argv) == 3 and sys.argv[1] in ("prepare", "attest")
    if sys.argv[1] == "prepare":
        prepare(Path(sys.argv[2]))
    else:
        attest(Path(sys.argv[2]))
