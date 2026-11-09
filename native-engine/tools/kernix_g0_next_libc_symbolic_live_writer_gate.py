#!/usr/bin/env python3
"""Verify ONE newly executed original libc JMPREL hardware write in genuine Linux ARM64 FEX.

This gate is intentionally strict: GDB exits, a stop, or a changed qword alone are
not sufficient. Exact original ELF source, native hardware stop and executable
GNU loader x86 writer bytes must all independently agree. No Android/PE claims.
"""
import hashlib
import json
import re
import struct
import sys
from pathlib import Path


LIBC_SHA = "7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906"
LDSO_SHA = "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"
LDSO_BASE = 0x801000000
LIBC_BASE = 0x804000000


def unique(pattern, log):
    hits = re.findall(pattern, log, re.M)
    assert len(hits) == 1, ("expected one genuine hardware proof", pattern, len(hits))
    return hits[0]


def source_offset(blob, addr, size, required_flags, *, nonexec=False):
    assert blob[:6] == b"\x7fELF\x02\x01"
    assert struct.unpack_from("<H", blob, 18)[0] == 62
    po = struct.unpack_from("<Q", blob, 32)[0]
    ents, count = struct.unpack_from("<HH", blob, 54)
    assert ents == 56 and 0 < count <= 128
    assert po + ents * count <= len(blob)
    entries = [struct.unpack_from("<IIQQQQQQ", blob, po + i * ents)
               for i in range(count)]
    matches = [p for p in entries if p[0] == 1 and (p[1] & required_flags) == required_flags
               and (not nonexec or not p[1] & 1)
               and p[3] <= addr and addr + size <= p[3] + p[5]
               and p[2] + p[5] <= len(blob)]
    assert len(matches) == 1, ("original PT_LOAD mismatch", hex(addr))
    return matches[0][2] + addr - matches[0][3]


def attest(dist, raw_override=None):
    source = dist / "original-source-pinned-root"
    libc = (source / "lib/x86_64-linux-gnu/libc.so.6").read_bytes()
    ldso = (source / "lib64/ld-linux-x86-64.so.2").read_bytes()
    assert len(libc) == 2118168 and hashlib.sha256(libc).hexdigest() == LIBC_SHA
    assert len(ldso) == 235408 and hashlib.sha256(ldso).hexdigest() == LDSO_SHA
    plan = json.loads((dist / "original-libc-next-symbolic-jmprel-native-write-watch-plan.json").read_text())
    inventory = json.loads((dist / "original-libc-147-rela-jmprel-source-inventory.json").read_text())
    prev = json.loads((dist / "original-fex-libc-symbolic-jmprel-first-real-native-writer-proof.json").read_text())
    assert plan["source_libc_sha256"] == inventory["libc_source_sha256"] == LIBC_SHA
    assert prev["one_original_libc_symbolic_JMPREL_real_hardware_store_proven"] is True
    assert prev["selected_original_record_index"] == 86
    assert plan["verified_first_source_jmprel_index"] == 86
    idx = plan["next_candidate_original_source_index"]
    assert 86 < idx < 147
    rows = inventory["next_source_candidates"]
    assert rows and rows[0]["index"] == idx and idx in inventory["next_source_candidate_indices"]
    row = rows[0]
    assert row["table"] == "DT_JMPREL" and row["r_type"] == 7 and row["r_sym"] > 0
    old = int(row["source_qword"], 16)
    target = int(row["source_guest_target"], 16)
    assert old != 0 and old == int(plan["next_candidate_original_source_qword"], 16)
    assert target == int(plan["next_candidate_original_guest_target"], 16)
    assert target == LIBC_BASE + int(row["r_offset"], 16) and target % 8 == 0
    qword_off = source_offset(libc, target - LIBC_BASE, 8, 6, nonexec=True)
    assert struct.unpack_from("<Q", libc, qword_off)[0] == old
    assert plan["GDB_native_hardware_watch_kind"] == "write_only_watchpoint"
    assert plan["next_native_hardware_store_has_executed"] is False
    log = (dist / "original-libc-next-symbolic-jmprel-live-fex-hw.log").read_text(
        errors="replace") if raw_override is None else raw_override

    armed = unique(
        r"^KERNIX_G0_NEXT_SOURCE_SYMBOLIC_JMPREL_NATIVE_WRITER_WATCH_ARMED "
        r"index=(\d+) target=(0x[0-9a-fA-F]+) original=(0x[0-9a-fA-F]+) NO_WRITER_YET=1$", log)
    assert (int(armed[0]), int(armed[1],16), int(armed[2],16)) == (idx, target, old)
    assert log.count("KERNIX_G0_LIBC_1214_ORIGINAL_RELOCATION_TARGETS_PRISTINE_AFTER_CLOSE3") == 1
    # Native GDB hardware write-only watchpoint registration and true firing.
    native_watch = re.findall(
        r"^Hardware watchpoint 2: -location \*\(unsigned long long \*\)0x([0-9a-fA-F]+)$",
        log, re.M)
    assert len(native_watch) == 2 and all(int(x,16) == target for x in native_watch)
    actual_old = int(unique(r"^Old value = (0x[0-9a-fA-F]+)$", log), 16)
    after = int(unique(r"^New value = (0x[0-9a-fA-F]+)$", log), 16)
    assert actual_old == old and after != old and after != 0
    assert log.index("KERNIX_G0_LIBC_1214_ORIGINAL_RELOCATION_TARGETS_PRISTINE_AFTER_CLOSE3") < log.index(
        "KERNIX_G0_NEXT_SOURCE_SYMBOLIC_JMPREL_NATIVE_WRITER_WATCH_ARMED") < log.index(
        "Old value = ") < log.index("New value = ")

    hit = unique(
        r"^KERNIX_G0_NEXT_JMPREL_REAL_NATIVE_HW_WRITE_STOP "
        r"target=(0x[0-9a-fA-F]+) after_pc=(0x[0-9a-fA-F]+) "
        r"guest_rsp_x8=(0x[0-9a-fA-F]+) cpu_state_x28=(0x[0-9a-fA-F]+) NOT_YET_SOURCE_ATTESTED=1$", log)
    seen_target, pc, rsp, state = (int(v,16) for v in hit)
    assert seen_target == target and pc >= 0xffff00000000
    assert 0x803000000 <= rsp < 0x803010000 and state >= 0xffff00000000
    # AArch64 real JIT native 64-bit store, rather than a mere read.
    inst = re.findall(r"^\s*0x%x:\s+(stlr\s+x\d+,\s*\[x\d+\])\s*$" % (pc-4), log, re.M)
    assert len(inst) >= 1
    assert len(set(inst)) == 1
    assert re.search(r"^0x%x:\s+0x%016x$" % (target, after), log, re.M)
    jit = unique(
        r"^KERNIX_G0_NEXT_JMPREL_NATIVE_STOP_FEX_JIT_GUEST_SOURCE "
        r"guest_entry=(0x[0-9a-fA-F]+) guest_size=(0x[0-9a-fA-F]+) "
        r"inst_count=(\d+) host_pc=(0x[0-9a-fA-F]+)$", log)
    guest, guest_size, count, pc2 = int(jit[0],16), int(jit[1],16), int(jit[2]), int(jit[3],16)
    assert pc2 == pc and 0 < guest_size <= 4096 and 0 < count <= 4096
    assert LDSO_BASE <= guest < LDSO_BASE + len(ldso) + 0x1000
    src_off = source_offset(ldso, guest - LDSO_BASE, 8, 5)
    original_bytes = ldso[src_off:src_off+8]
    byte_line = unique(
        r"^0x%x:\s+((?:0x[0-9a-fA-F]{2}\s+){7}0x[0-9a-fA-F]{2})\s*$" % guest, log)
    observed_bytes = bytes(int(z,16) for z in re.findall(r"0x[0-9a-fA-F]{2}", byte_line))
    assert observed_bytes == original_bytes
    # Source GNU loader must actually represent the store instruction
    # 4c 89 08 (MOV QWORD PTR [RAX], R9), as in the first real writer.
    # Do not guess a different writer's semantics based on a JIT PC alone.
    assert observed_bytes[:3] == bytes.fromhex("4c8908")
    assert guest_size == 3
    def accepted(b,a,opcode,store,to):
        return b == old and a == after and a != b and opcode == bytes.fromhex("4c8908") \
               and store == inst[0] and store.startswith("stlr ") and to == target
    assert accepted(old,after,observed_bytes[:3],inst[0],target)
    assert not accepted(after,after,observed_bytes[:3],inst[0],target)
    assert not accepted(old,0,observed_bytes[:3],inst[0],target)
    assert not accepted(old,after,b"\x4c\x89\x00",inst[0],target)
    assert not accepted(old,after,observed_bytes[:3],inst[0].replace("stlr","ldr"),target)
    assert not accepted(old,after,observed_bytes[:3],inst[0],target+8)

    return {
      "schema": "kernix.g0.second-source-libc-symbolic-JMPREL-real-FEX-arm64-hardware-write.v1",
      "source_libc_sha256": LIBC_SHA,
      "source_original_gnu_ldso_sha256": LDSO_SHA,
      "source_record_index": idx,
      "source_record_kind": row["r_type"],
      "source_symbol_id": row["r_sym"],
      "source_original_guest_target": hex(target),
      "source_original_qword": hex(old),
      "hardware_recorded_after_qword": hex(after),
      "actual_native_after_write_pc": hex(pc),
      "actual_native_writer_opcode": inst[0],
      "original_guest_source_jit_rip": hex(guest),
      "original_guest_source_x86_writer_bytes": observed_bytes[:3].hex(),
      "exact_original_GNU_JIT_RX_bytes_verified": True,
      "genuine_second_symbolic_source_hardware_store_proven": True,
      "libc_total_symbolic_JMPREL_writer_records_proven": 2,
      "remaining_145_rela_jmprel_writers_proven": False,
      "full_libc_symbol_resolution_proven": False,
      "original_libc_IFUNC_resolver_execution_proven": False,
      "full_147_RELA_JMPREL_relocations_closed": False,
      "original_main_relocations_closed": False,
      "Android_Bionic_Wine_Proton_games_proven": False
    }


def main(dist):
    report = attest(dist)
    out = dist / "original-libc-next-symbolic-jmprel-live-fex-hw-verified.json"
    out.write_text(json.dumps(report,indent=2)+"\n")
    print("KERNIX_G0_SECOND_LIBC_SOURCE_SYMBOLIC_JMPREL_REAL_FEX_ARM64_HARDWARE_WRITE_PASS_NOT_FULL_RELOCATIONS")


if __name__ == "__main__":
    assert len(sys.argv)==2
    main(Path(sys.argv[1]))
