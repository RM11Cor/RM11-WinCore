#!/usr/bin/env python3
"""Attest one real native FEX libc JMPREL store; never infer total symbol/IFUNC closure."""
from pathlib import Path
import hashlib
import json
import re
import struct
import sys


def phdrs(elf):
    start = struct.unpack_from("<Q", elf, 32)[0]
    ents, count = struct.unpack_from("<HH", elf, 54)
    assert ents == 56 and 0 < count <= 128
    assert start + 56 * count <= len(elf)
    return [struct.unpack_from("<IIQQQQQQ", elf, start + 56 * i)
            for i in range(count)]


def file_offset(ph, elf, va, size, flags, *, nx=False):
    hits = [p for p in ph if p[0] == 1 and p[3] <= va
            and va + size <= p[3] + p[5]
            and p[2] + p[5] <= len(elf)
            and p[1] & flags == flags
            and (not nx or not p[1] & 1)]
    assert len(hits) == 1, ("original source PT_LOAD mismatch", hex(va))
    return hits[0][2] + va - hits[0][3]


def exactly_one(pattern, raw):
    values = re.findall(pattern, raw, re.M)
    assert len(values) == 1, (pattern, len(values))
    return values[0]


def attest(dist: Path, *, raw_override=None):
    raw = (dist / "original-fex-libc-symbolic-rela-access-hw.log").read_text(
        errors="replace") if raw_override is None else raw_override
    src = json.loads(
        (dist / "original-fex-libc-symbolic-rela-access-hw.source.json").read_text())
    prior = json.loads(
        (dist / "original-fex-libc-symbolic-rela-access-hw.json").read_text())
    libc = (dist / "original-source-pinned-root/lib/x86_64-linux-gnu/libc.so.6").read_bytes()
    ldso = (dist / "original-source-pinned-root/lib64/ld-linux-x86-64.so.2").read_bytes()
    libc_hash = "7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906"
    ldso_hash = "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"
    assert len(libc) == 2118168 and hashlib.sha256(libc).hexdigest() == libc_hash
    assert hashlib.sha256(ldso).hexdigest() == ldso_hash
    assert src["original_libc_sha256"] == libc_hash
    assert (src["source_original_rela_total"], src["source_original_jmprel_total"],
            src["source_original_ifunc_total"], src["source_original_symbolic_total"]) == (
            86, 61, 46, 101)
    assert prior["actual_native_arm64_hw_read_or_write_access_observed"] is True
    assert prior["source_rela_symbolic_native_write_proven"] is False
    selected = src["selected"]
    target = int(selected["guest_target"], 16)
    assert target == 0x804000000 + selected["addr"]
    assert selected["kind"] == 7 and selected["plt"] is True
    assert selected["symbol"] > 0 and selected["source"] != 0
    cp, lp = phdrs(libc), phdrs(ldso)

    # Independently decode original JMPREL source record, not the diagnostic's
    # summary: first 86 are DT_RELA, next 61 are DT_JMPREL.
    dyn = [p for p in cp if p[0] == 2]
    assert len(dyn) == 1
    tags = {}
    for off in range(dyn[0][2], dyn[0][2] + dyn[0][5], 16):
        t, v = struct.unpack_from("<qQ", libc, off)
        if t == 0:
            break
        if t in (2, 23):
            assert t not in tags
            tags[t] = v
    assert tags[2] == 61 * 24
    idx = selected["index"] - 86
    assert 0 <= idx < 61
    jmprel_off = file_offset(cp, libc, tags[23], tags[2], 4)
    addr, info, addend = struct.unpack_from("<QQq", libc, jmprel_off + idx * 24)
    assert (addr, info & 0xffffffff, info >> 32, addend) == (
        selected["addr"], selected["kind"], selected["symbol"],
        selected["addend"])
    src_off = file_offset(cp, libc, addr, 8, 6, nx=True)
    assert struct.unpack_from("<Q", libc, src_off)[0] == selected["source"]

    watch = re.findall(
        r"^Hardware access \(read/write\) watchpoint 2: "
        r"-location \*\(unsigned long long \*\)0x([0-9a-fA-F]+)$",
        raw, re.M)
    assert len(watch) == 2 and all(int(w, 16) == target for w in watch)
    before = int(exactly_one(r"^Old value = (0x[0-9a-fA-F]+)$", raw), 16)
    after = int(exactly_one(r"^New value = (0x[0-9a-fA-F]+)$", raw), 16)
    assert before == selected["source"] and after != before and after != 0
    # Read the resulting pointer only as source-address provenance.
    # This does NOT prove the entire linker symbol-resolution algorithm.
    resolved_va = after - 0x804000000
    file_offset(cp, libc, resolved_va, 1, 5)
    hit = exactly_one(
        r"^KERNIX_G0_LIBC_RELA_SYMBOLIC_FIRST_NATIVE_HW_ACCESS_STOP "
        r"target=(0x[0-9a-fA-F]+) host_pc=(0x[0-9a-fA-F]+) "
        r"live_rsp_x8=(0x[0-9a-fA-F]+) cpu_state_x28=(0x[0-9a-fA-F]+) no_store_claim=1$",
        raw)
    hit_target, host_pc, rsp, cpustate = (int(x, 16) for x in hit)
    assert hit_target == target and host_pc >= 0xffff00000000
    assert 0x803000000 <= rsp < 0x803010000
    assert cpustate >= 0xffff00000000
    # GDB awatch can fire on reads. An actual Old->New delta plus the
    # immediately preceding native stlr are the independent WRITE witnesses.
    assert re.search(
        rf"^\s*0x{host_pc-4:x}:\s+stlr\s+x13,\s*\[x4\]\s*$", raw, re.M)
    assert re.search(r"^0x%x:\s+0x%016x$" % (target, after), raw, re.M)
    guest, size, count, native = exactly_one(
        r"^KERNIX_G0_LIBC_RELA_SYMBOLIC_REAL_FEX_JIT_ACCESS_SOURCE "
        r"guest_entry=(0x[0-9a-fA-F]+) guest_size=(0x[0-9a-fA-F]+) "
        r"inst_count=(\d+) host_pc=(0x[0-9a-fA-F]+)$", raw)
    guest = int(guest, 16)
    assert int(native, 16) == host_pc and int(size, 16) == 3
    assert int(count) == 2
    guest_off = file_offset(lp, ldso, guest - 0x801000000, 3, 5)
    source_bytes = ldso[guest_off:guest_off + 3]
    assert source_bytes == bytes.fromhex("4c 89 08")  # mov qword ptr [rax],r9
    assert re.search(r"^0x%x:\s+0x4c\s+0x89\s+0x08\s" % guest, raw, re.M)
    assert raw.index("KERNIX_G0_LIBC_1214_ORIGINAL_RELOCATION_TARGETS_PRISTINE_AFTER_CLOSE3") < raw.index(
        "Old value = ") < raw.index("New value = ") < raw.index(
        "KERNIX_G0_LIBC_RELA_SYMBOLIC_REAL_FEX_JIT_ACCESS_SOURCE")

    def accept(b, a, op, native_store, dest):
        return (b == selected["source"] and a == after and a != b
                and op == bytes.fromhex("4c 89 08")
                and native_store == "stlr x13, [x4]" and dest == target)

    assert accept(before, after, source_bytes, "stlr x13, [x4]", target)
    assert not accept(after, after, source_bytes, "stlr x13, [x4]", target)
    assert not accept(before, 0, source_bytes, "stlr x13, [x4]", target)
    assert not accept(before, after, b"\x4c\x89\x00", "stlr x13, [x4]", target)
    assert not accept(before, after, source_bytes, "ldr x13, [x4]", target)
    assert not accept(before, after, source_bytes, "stlr x13, [x4]", target + 8)

    output = {
        "schema": "kernix.g0.first-libc-symbolic-jmprel-native-hardware-store.v1",
        "original_libc_sha256": libc_hash,
        "original_gnu_ldso_sha256": ldso_hash,
        "original_rela_jmprel_source_records": 147,
        "selected_original_record_index": selected["index"],
        "selected_original_relocation_type": selected["kind"],
        "selected_original_symbol_index": selected["symbol"],
        "guest_original_target": hex(target),
        "original_qword": hex(before),
        "real_hardware_after_store_qword": hex(after),
        "after_value_inside_source_libc_rx_ptload": True,
        "real_native_after_store_pc": hex(host_pc),
        "real_native_store_instruction": "stlr x13, [x4]",
        "original_gnu_x86_guest_source_writer_rip": hex(guest),
        "original_x86_store_opcode": source_bytes.hex(),
        "original_x86_store_semantics": "MOV QWORD PTR [RAX], R9",
        "one_original_libc_symbolic_JMPREL_real_hardware_store_proven": True,
        "live_guest_RAX_R9_independently_proven": False,
        "all_symbol_resolution_proven": False,
        "remaining_146_libc_rela_jmprel_writers_proven": False,
        "libc_IFUNC_resolver_paths_proven": False,
        "all_libc_relocation_closure_proven": False,
        "Android_Bionic_Wine_Proton_games_proven": False,
        "five_value_opcode_negative_controls_rejected": True,
        "six_replayed_real_log_mutations_rejected": True
    }
    return output


def replay_log_negative_suite(dist: Path):
    """Mutate the genuine captured log in memory; never rewrite CI evidence."""
    raw = (dist / "original-fex-libc-symbolic-rela-access-hw.log").read_text(errors="replace")
    cases = []
    def change_one(name, pattern, replacement):
        tampered, count = re.subn(pattern, replacement, raw, count=1, flags=re.M)
        assert count == 1 and tampered != raw, ("cannot generate control", name)
        cases.append((name, tampered))

    change_one("old_qword_changed", r"^Old value = 0x[0-9a-fA-F]+$",
               "Old value = 0x1")
    change_one("new_qword_erased", r"^New value = 0x[0-9a-fA-F]+$",
               "New value = 0x0")
    change_one("native_store_replaced_by_load",
               r"^([ \t]*0x[0-9a-fA-F]+:[ \t]+)stlr[ \t]+x13,[ \t]*\[x4\]$",
               r"\1ldr x13, [x4]")
    change_one("source_guest_x86_opcode_corrupted",
               r"^(0x80100fb8b:[ \t]+0x4c[ \t]+0x89[ \t]+)0x08",
               r"\g<1>0x00")
    change_one("hardware_watchpoint_removed",
               r"^Hardware access \(read/write\) watchpoint 2: -location \*\(unsigned long long \*\)0x[0-9a-fA-F]+$",
               "Hardware watchpoint suppressed")
    change_one("guest_relocation_target_changed",
               r"^(KERNIX_G0_LIBC_RELA_SYMBOLIC_FIRST_NATIVE_HW_ACCESS_STOP target=)0x[0-9a-fA-F]+",
               r"\g<1>0x1")
    assert len(cases) == 6
    for name, corrupted in cases:
        try:
            attest(dist, raw_override=corrupted)
        except AssertionError:
            continue
        raise AssertionError("FAIL OPEN: corrupted genuine log accepted: " + name)
    return [name for name, _ in cases]


if __name__ == "__main__":
    assert len(sys.argv) == 2
    dist = Path(sys.argv[1])
    proof = attest(dist)
    names = replay_log_negative_suite(dist)
    assert len(names) == 6
    proof["replayed_log_negative_case_names"] = names
    (dist / "original-fex-libc-symbolic-jmprel-first-real-native-writer-proof.json").write_text(
        json.dumps(proof, indent=2) + "\n")
    print("KERNIX_G0_ORIGINAL_LIBC_FIRST_SYMBOLIC_JMPREL_REAL_NATIVE_HARDWARE_WRITE_SOURCE_MOV_STLR_PASS_NOT_FULL_RELA_IFUNC")
