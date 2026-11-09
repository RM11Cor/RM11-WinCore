#!/usr/bin/env python3
"""Last original libc JUMP_SLOT #101: SHA-pinned real ARM64 FEX hardware writer.

Accept only a genuine write-only watchpoint, old/new original-source qword,
true AArch64 store, original GNU x86 writer and one source-backed RX result.
This is NOT Android, full dynamic symbol resolution or full libc closure.
"""
import hashlib
import json
import re
import sys
from pathlib import Path
from kernix_g0_libc_rela_source_inventory_gate import make_inventory
from kernix_g0_next_libc_symbolic_live_writer_gate import (
    LIBC_SHA, LDSO_SHA, LIBC_BASE, LDSO_BASE, source_offset, unique
)

PLAN = "original-libc-last-jumpslot-101-source-watch-plan.json"
LOG = "original-libc-last-jumpslot-101-real-fex-hw.log"
OUTPUT = "original-libc-last-jumpslot-101-real-fex-hw-verified.json"
INDEX = 101
TARGET = 0x804202d70
BEFORE = 0x283c0
SOURCE_WRITER = bytes.fromhex("4c8908")


def attest(dist: Path, *, raw_override=None):
    root = dist / "original-source-pinned-root"
    libc_path = root / "lib/x86_64-linux-gnu/libc.so.6"
    ldso_path = root / "lib64/ld-linux-x86-64.so.2"
    assert libc_path.is_file() and not libc_path.is_symlink()
    assert ldso_path.is_file() and not ldso_path.is_symlink()
    libc, ldso = libc_path.read_bytes(), ldso_path.read_bytes()
    assert len(libc) == 2118168 and hashlib.sha256(libc).hexdigest() == LIBC_SHA
    assert len(ldso) == 235408 and hashlib.sha256(ldso).hexdigest() == LDSO_SHA
    inventory = make_inventory(libc)
    assert inventory == json.loads(
        (dist / "original-libc-147-rela-jmprel-source-inventory.json").read_text())
    first = json.loads(
        (dist / "original-fex-libc-symbolic-jmprel-first-real-native-writer-proof.json").read_text())
    second = json.loads(
        (dist / "original-libc-next-symbolic-jmprel-live-fex-hw-verified.json").read_text())
    third = json.loads(
        (dist / "original-libc-third-symbolic-jmprel-real-fex-hw-verified.json").read_text())
    assert (first["one_original_libc_symbolic_JMPREL_real_hardware_store_proven"],
            first["selected_original_record_index"],
            first["guest_original_target"]) == (True, 86, "0x804202ba0")
    assert (second["genuine_second_symbolic_source_hardware_store_proven"],
            second["source_record_index"],
            second["source_original_guest_target"],
            second["source_libc_sha256"]) == (True, 87, "0x804202bc0", LIBC_SHA)
    assert third["third_symbolic_JMPREL_real_native_hardware_writer_proven"] is True
    assert third["third_original_source_relocation_index"] == 88
    assert third["third_original_source_guest_target"] == "0x804202c08"
    assert third["third_real_native_hardware_after_qword"] == "0x80100cf60"
    assert third["third_resolved_pointer_source_original_elf"] == "original-ld-linux-x86-64.so.2"
    assert third["third_result_inside_pinned_GNU_ldso_RX_PT_LOAD"] is True
    assert third["six_actual_native_log_tamper_controls_rejected"] is True
    assert third["source_original_libc_sha256"] == LIBC_SHA
    assert third["source_original_gnu_ldso_sha256"] == LDSO_SHA
    assert third["cumulative_individually_source_attested_libc_symbolic_JMPREL"] == 3
    fourth = json.loads(
        (dist / "original-libc-fourth-symbolic-jmprel-real-fex-hw-verified.json").read_text())
    assert fourth["fourth_symbolic_JMPREL_real_native_hardware_store_proven"] is True
    assert fourth["fourth_source_index"] == 89
    assert fourth["fourth_source_guest_target"] == "0x804202c40"
    assert fourth["fourth_original_qword"] == "0x28160"
    assert fourth["fourth_after_native_hardware_store_qword"] == "0x801014840"
    assert fourth["fourth_result_pinned_source_ELF_RX"] == "ld-linux"
    assert fourth["six_actual_native_log_negative_mutations_rejected"] is True
    assert len(fourth["negative_names"]) == 6
    assert fourth["individual_symbolic_JMPREL_hardware_writers_proven"] == 4
    assert fourth["source_original_libc_sha256"] == LIBC_SHA
    assert fourth["source_original_gnu_ldso_sha256"] == LDSO_SHA

    # No extension of the simple JUMP_SLOT writer gate into IRELATIVE/IFUNC.
    from kernix_g0_original_libc_relocation_type_transition_gate import classify, decode_original_libc
    typed = classify(decode_original_libc(libc))
    assert typed == json.loads(
        (dist / "original-libc-147-rela-jmprel-typed-source-next-stage-plan.json").read_text())
    assert typed["genuine_source_JUMP_SLOT_indices"] == list(range(86,102))
    assert typed["last_JUMP_SLOT_live_FEX_hardware_writer_proven"] is False
    assert typed["last_unproven_source_JUMP_SLOT"] == {
        "index":101, "symbol":19,
        "guest_target":"0x804202d70","original_qword":"0x283c0"}
    assert typed["original_source_IRELATIVE_count"] == 46
    assert typed["original_other_RELA_count"] == 85

    fifth = json.loads(
        (dist / "original-libc-fifth-symbolic-jmprel-real-fex-hw-verified.json").read_text())
    assert fifth["fifth_symbolic_JMPREL_real_native_hardware_store_proven"] is True
    assert fifth["fifth_source_index"] == 90
    assert fifth["fifth_original_qword"] == "0x28170"
    assert fifth["source_original_libc_sha256"] == LIBC_SHA
    assert fifth["source_original_gnu_ldso_sha256"] == LDSO_SHA
    assert fifth["six_actual_native_log_negative_mutations_rejected"] is True
    assert fifth["individual_symbolic_JMPREL_hardware_writers_proven"] == 5
    prior_two = json.loads(
        (dist / "original-libc-symbolic-jmprel-91-92-same-native-guest-verified.json").read_text())
    assert prior_two["libc_sha256"] == LIBC_SHA and prior_two["ldso_sha256"] == LDSO_SHA
    assert prior_two["indices"] == [91,92]
    assert prior_two["two_individual_real_native_hardware_writes_in_ONE_FEX_guest_proven"] is True
    assert prior_two["total_individually_real_native_attested_original_libc_JMPREL"] == 7
    assert prior_two["six_actual_same_process_hw_batch_log_mutations_rejected"] is True
    prior_four = json.loads(
        (dist / "original-libc-symbolic-jmprel-93-96-same-native-guest-verified.json").read_text())
    assert prior_four["indices"] == [93,94,95,96]
    assert prior_four["libc_sha256"] == LIBC_SHA and prior_four["ldso_sha256"] == LDSO_SHA
    assert prior_four["four_individual_real_native_hardware_writes_in_ONE_FEX_guest_proven"] is True
    assert prior_four["total_individually_real_native_attested_original_libc_JMPREL"] == 11
    assert prior_four["twelve_actual_same_process_hw_batch_log_mutations_rejected"] is True
    prior_fifteen = json.loads(
        (dist / "original-libc-symbolic-jmprel-97-100-same-native-guest-verified.json").read_text())
    assert prior_fifteen["indices"] == [97,98,99,100]
    assert prior_fifteen["source_original_writer_indices_prior"] == list(range(86,97))
    assert prior_fifteen["libc_sha256"] == LIBC_SHA and prior_fifteen["ldso_sha256"] == LDSO_SHA
    assert prior_fifteen["four_individual_real_native_hardware_writes_in_ONE_FEX_guest_proven"] is True
    assert prior_fifteen["total_individually_real_native_attested_original_libc_JMPREL"] == 15
    assert prior_fifteen["twelve_actual_same_process_hw_batch_log_mutations_rejected"] is True
    assert len(prior_fifteen["negative_case_names"]) == 12
    assert [w["after_real_hardware_write_qword"] for w in prior_fifteen["writers"]] == [
        "0x801015c20","0x801001480","0x8010142e0","0x8010042f0"]

    row = inventory["next_source_candidates"][14]
    assert (row["index"], row["table"], row["r_type"]) == (INDEX, "DT_JMPREL", 7)
    assert row["r_sym"] == 19 and int(row["source_guest_target"], 16) == TARGET
    assert int(row["source_qword"], 16) == BEFORE
    assert TARGET == LIBC_BASE + int(row["r_offset"], 16)
    slot = source_offset(libc, TARGET-LIBC_BASE, 8, 6, nonexec=True)
    assert int.from_bytes(libc[slot:slot+8], "little") == BEFORE
    plan = json.loads((dist / PLAN).read_text())
    assert plan["prior_real_FEX_native_JUMP_SLOT_writer_indices"] == list(range(86,101))
    assert plan["last_source_index"] == INDEX
    assert plan["last_source_r_type"] == 7 and plan["last_source_symbol"] == 19
    assert int(plan["last_source_guest_target"], 16) == TARGET
    assert int(plan["last_source_qword"], 16) == BEFORE
    assert plan["source_libc_sha256"] == LIBC_SHA
    assert plan["source_ldso_sha256"] == LDSO_SHA
    assert plan["native_watchpoint_mode"] == "write-only"
    assert plan["last_source_writer_real_native_hardware_proven"] is False
    assert plan["all_16_original_JUMP_SLOT_writers_proven"] is False

    raw = ((dist / LOG).read_text(errors="replace")
           if raw_override is None else raw_override)
    armed = unique(
        r"^KERNIX_G0_NEXT_SOURCE_SYMBOLIC_JMPREL_NATIVE_WRITER_WATCH_ARMED "
        r"index=(\d+) target=(0x[0-9a-fA-F]+) original=(0x[0-9a-fA-F]+) NO_WRITER_YET=1$", raw)
    assert (int(armed[0]), int(armed[1],16), int(armed[2],16)) == (INDEX, TARGET, BEFORE)
    watches = re.findall(
        r"^Hardware watchpoint 2: -location \*\(unsigned long long \*\)0x([0-9a-fA-F]+)$",
        raw, re.M)
    assert len(watches) == 2 and all(int(v,16) == TARGET for v in watches)
    old = int(unique(r"^Old value = (0x[0-9a-fA-F]+)$", raw), 16)
    after = int(unique(r"^New value = (0x[0-9a-fA-F]+)$", raw), 16)
    assert old == BEFORE and after != BEFORE and after != 0
    assert re.search(r"^0x%x:\s+0x%016x$" % (TARGET, after), raw, re.M)
    pristine = "KERNIX_G0_LIBC_1214_ORIGINAL_RELOCATION_TARGETS_PRISTINE_AFTER_CLOSE3"
    arm = "KERNIX_G0_NEXT_SOURCE_SYMBOLIC_JMPREL_NATIVE_WRITER_WATCH_ARMED"
    assert raw.count(pristine) == 1
    assert raw.index(pristine) < raw.index(arm) < raw.index("Old value = ") < raw.index("New value = ")
    hit = unique(
        r"^KERNIX_G0_NEXT_JMPREL_REAL_NATIVE_HW_WRITE_STOP "
        r"target=(0x[0-9a-fA-F]+) after_pc=(0x[0-9a-fA-F]+) "
        r"guest_rsp_x8=(0x[0-9a-fA-F]+) cpu_state_x28=(0x[0-9a-fA-F]+) "
        r"NOT_YET_SOURCE_ATTESTED=1$", raw)
    addr, pc, rsp, state = [int(v,16) for v in hit]
    assert addr == TARGET and pc >= 0xffff00000000
    assert 0x803000000 <= rsp < 0x803010000 and state >= 0xffff00000000
    stores = re.findall(r"^\s*0x%x:\s+(stlr\s+x13,\s*\[x4\])\s*$" % (pc-4), raw, re.M)
    assert len(stores) >= 2 and len(set(stores)) == 1
    jit = unique(
        r"^KERNIX_G0_NEXT_JMPREL_NATIVE_STOP_FEX_JIT_GUEST_SOURCE "
        r"guest_entry=(0x[0-9a-fA-F]+) guest_size=(0x[0-9a-fA-F]+) "
        r"inst_count=(\d+) host_pc=(0x[0-9a-fA-F]+)$", raw)
    guest, length, count, hostpc = [int(v,16) for v in (jit[0],jit[1])] + [int(jit[2]),int(jit[3],16)]
    assert hostpc == pc and length == 3 and count == 2
    at = source_offset(ldso, guest-LDSO_BASE, 8, 5)
    original = ldso[at:at+8]
    printed = unique(
        r"^0x%x:\s+((?:0x[0-9a-fA-F]{2}\s+){7}0x[0-9a-fA-F]{2})\s*$" % guest, raw)
    source_jit = bytes(int(v,16) for v in re.findall(r"0x[0-9a-fA-F]{2}", printed))
    assert source_jit == original and source_jit[:3] == SOURCE_WRITER

    # Valid targets can point to original libc or original GNU ldso.
    # Must match exactly one immutable PT_LOAD RX source: never guess the
    # outcome or infer complete dynamic symbol lookup from this pointer.
    located = []
    for name, elf, bias in [
        ("libc", libc, LIBC_BASE),
        ("ld-linux", ldso, LDSO_BASE),
    ]:
        try:
            source_offset(elf, after-bias, 1, 5)
        except AssertionError:
            continue
        located.append(name)
    assert len(located) == 1 and located[0] in ("libc", "ld-linux"), (
        "value not in one exact-original-ELF RX segment", hex(after), located)

    def valid(b,a,op,instr,target):
        return (b == BEFORE and a == after and a != b and
                op == SOURCE_WRITER and
                re.fullmatch(r"stlr\s+x13,\s*\[x4\]",instr) is not None
                and target == TARGET)
    assert valid(old,after,source_jit[:3],stores[0],TARGET)
    assert not valid(after,after,source_jit[:3],stores[0],TARGET)
    assert not valid(old,0,source_jit[:3],stores[0],TARGET)
    assert not valid(old,after,b"\x4c\x89\x00",stores[0],TARGET)
    assert not valid(old,after,source_jit[:3],"ldr x13, [x4]",TARGET)
    assert not valid(old,after,source_jit[:3],stores[0],TARGET+8)
    return {
        "schema": "kernix.g0.last-16th-JUMP_SLOT-original-libc-real-arm64-FEX-hardware-write.v1",
        "source_original_libc_sha256": LIBC_SHA,
        "source_original_gnu_ldso_sha256": LDSO_SHA,
        "prior_fifteen_individual_real_native_writers_verified": True,
        "prior_97_to_100_hardware_write_values": [w["after_real_hardware_write_qword"] for w in prior_fifteen["writers"]],
        "last_JUMP_SLOT_source_index": INDEX,
        "last_JUMP_SLOT_source_symbol": row["r_sym"],
        "last_JUMP_SLOT_guest_target": hex(TARGET),
        "last_JUMP_SLOT_original_qword": hex(old),
        "last_JUMP_SLOT_real_native_hardware_after_qword": hex(after),
        "last_JUMP_SLOT_result_pinned_source_ELF_RX": located[0],
        "real_native_ARM64_after_write_pc": hex(pc),
        "real_native_ARM64_store_instruction": stores[0],
        "original_GNU_x86_guest_source_RIP": hex(guest),
        "original_GNU_x86_store_opcode": source_jit[:3].hex(),
        "last_JUMP_SLOT_real_ARM64_hardware_store_proven": True,
        "all_16_JUMP_SLOT_individual_native_hardware_writers_proven_count": 16,
        "remaining_131_RELA_JMPREL_writers_proven": False,
        "all_46_IFUNC_resolvers_proven": False
        ,"85_other_RELA_writer_semantics_proven": False
        ,"one_guest_all_147_RELA_JMPREL_closed": False,
        "all_libc_relocations_closed": False,
        "original_main_ELF_relocation_RELRO_closed": False,
        "Android_Bionic_Wine_Proton_games_proven": False,
    }


def negative_controls(dist: Path):
    raw = (dist / LOG).read_text(errors="replace")
    alterations = []
    def one(name, pattern, replacement):
        changed, count = re.subn(pattern, replacement, raw, count=1, flags=re.M)
        assert count == 1 and changed != raw, ("control generation failed",name,count)
        alterations.append((name,changed))
    one("old_qword_forged",r"^Old value = 0x[0-9a-fA-F]+$","Old value = 0x1")
    one("new_qword_forged",r"^New value = 0x[0-9a-fA-F]+$","New value = 0x1")
    one("native_watch_stop_target_forged",
        r"^(KERNIX_G0_NEXT_JMPREL_REAL_NATIVE_HW_WRITE_STOP target=)0x[0-9a-fA-F]+",
        r"\g<1>0x1")
    one("source_GNU_x86_byte_forged",r"^(0x80100fb8b:[ \t]+)0x4c",r"\g<1>0x00")
    pat=r"^([ \t]*0x[0-9a-fA-F]+:[ \t]+)stlr[ \t]+x13,[ \t]*\[x4\]$"
    changed,n=re.subn(pat,r"\g<1>ldr x13, [x4]",raw,flags=re.M)
    assert n>=2 and not re.search(pat,changed,re.M)
    alterations.append(("all_native_stores_forged_as_reads",changed))
    pat=r"^Hardware watchpoint 2: -location \*\(unsigned long long \*\)0x[0-9a-fA-F]+$"
    changed,n=re.subn(pat,"Hardware watchpoint disabled",raw,flags=re.M)
    assert n==2 and not re.search(pat,changed,re.M)
    alterations.append(("both_hw_watchpoint_records_removed",changed))
    assert len(alterations)==6
    for name,corrupted in alterations:
        try:
            attest(dist,raw_override=corrupted)
        except AssertionError:
            continue
        raise AssertionError("FAIL OPEN: accepted corrupted last JUMP_SLOT original FEX GDB log "+name)
    return [name for name,_ in alterations]


def main(dist: Path):
    obj=attest(dist)
    names=negative_controls(dist)
    assert len(names)==6
    obj["six_actual_native_log_negative_mutations_rejected"]=True
    obj["negative_names"]=names
    (dist/OUTPUT).write_text(json.dumps(obj,indent=2)+"\n")
    print("KERNIX_G0_ALL_16_ORIGINAL_LIBC_JUMP_SLOT_INDIVIDUAL_ARM64_FEX_NATIVE_HW_WRITERS_PASS_NOT_FULL_LIBC")


if __name__ == "__main__":
    assert len(sys.argv)==2
    main(Path(sys.argv[1]))
