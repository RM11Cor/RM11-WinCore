#!/usr/bin/env python3
"""Fail-closed evidence gate: four distinct real AArch64 hardware writes in ONE FEX guest.

Accept only both independent hardware-watchpoint stop callbacks, original
source ELF targets + qwords + exact GNU x86 guest source bytes, and native
AArch64 store register attribution. A GDB plan or one watchpoint is NOT PASS.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

from kernix_g0_libc_rela_source_inventory_gate import make_inventory
from kernix_g0_next_libc_symbolic_live_writer_gate import (
    LIBC_SHA, LDSO_SHA, LIBC_BASE, LDSO_BASE, source_offset
)
from kernix_g0_libc_jmprel_four_target_97_100_batch import PLAN, GDB, TARGETS

LOG = "original-libc-symbolic-jmprel-97-100-same-native-guest-live-fex-hw.log"
PROOF = "original-libc-symbolic-jmprel-97-100-same-native-guest-verified.json"
LINE_RE = (
    r"^KERNIX_G0_BATCH_REAL_GDB_HW_WRITE "
    r"index=(\d+) target=(0x[0-9a-fA-F]+) original=(0x[0-9a-fA-F]+) "
    r"after=(0x[0-9a-fA-F]+) pc=(0x[0-9a-fA-F]+) "
    r"x4=(0x[0-9a-fA-F]+) x13=(0x[0-9a-fA-F]+) "
    r"x8=(0x[0-9a-fA-F]+) x28=(0x[0-9a-fA-F]+) "
    r"guest=(0x[0-9a-fA-F]+) size=(0x[0-9a-fA-F]+) "
    r"insn_count=(\d+) original_guest_bytes8=([0-9a-fA-F]{16}) "
    r"native_store=(\S+)$"
)


def attest(dist: Path, *, log_override=None):
    root = dist / "original-source-pinned-root"
    libc_path = root / "lib/x86_64-linux-gnu/libc.so.6"
    ldso_path = root / "lib64/ld-linux-x86-64.so.2"
    assert libc_path.is_file() and not libc_path.is_symlink()
    assert ldso_path.is_file() and not ldso_path.is_symlink()
    libc, ldso = libc_path.read_bytes(), ldso_path.read_bytes()
    assert len(libc) == 2118168 and hashlib.sha256(libc).hexdigest() == LIBC_SHA
    assert len(ldso) == 235408 and hashlib.sha256(ldso).hexdigest() == LDSO_SHA

    inv = make_inventory(libc)
    assert inv == json.loads(
        (dist / "original-libc-147-rela-jmprel-source-inventory.json").read_text())
    records = inv["next_source_candidates"]
    assert [v["index"] for v in records[:14]] == list(range(87,101))
    source_rows = records[10:14]
    for (index, target, old, sym), row in zip(TARGETS, source_rows):
        assert (row["index"], row["r_type"], row["r_sym"], row["table"]) == (
            index, 7, sym, "DT_JMPREL")
        assert target == int(row["source_guest_target"], 16)
        assert old == int(row["source_qword"], 16)
        assert int(row["r_offset"],16) + LIBC_BASE == target
        slot = source_offset(libc, target-LIBC_BASE, 8, 6, nonexec=True)
        assert int.from_bytes(libc[slot:slot+8], "little") == old
    plan = json.loads((dist / PLAN).read_text())
    assert plan["original_libc_sha256"] == LIBC_SHA
    assert plan["original_ldso_sha256"] == LDSO_SHA
    assert plan["prior_eleven_writer_indices_source_attested"] == list(range(86,97))
    assert plan["hardware_watchpoint_mode"] == "write-only"
    assert plan["watchpoint_count"] == 4
    assert plan["same_original_FEX_guest_process_requested"] is True
    assert plan["actual_native_source_guest_execution_performed"] is False
    assert plan["all_four_original_hardware_writers_proven"] is False
    assert plan["new_source_original_symbolic_jmprel_records"] == [
        {"index":i, "original_guest_target":hex(t),
         "original_source_qword":hex(v), "source_symbol":sym}
        for i,t,v,sym in TARGETS]
    # Independent source evidence chain: the earlier four-target batch
    # is real native FEX hardware, not merely a generated source plan.
    last = json.loads(
        (dist / "original-libc-symbolic-jmprel-93-96-same-native-guest-verified.json").read_text())
    assert last["four_individual_real_native_hardware_writes_in_ONE_FEX_guest_proven"] is True
    assert last["indices"] == [93,94,95,96]
    assert last["total_individually_real_native_attested_original_libc_JMPREL"] == 11
    assert last["libc_sha256"] == LIBC_SHA and last["ldso_sha256"] == LDSO_SHA
    assert last["twelve_actual_same_process_hw_batch_log_mutations_rejected"] is True
    assert len(last["writers"]) == 4 and len(last["negative_case_names"]) == 12

    script = (dist / GDB).read_text()
    assert script.count("wp_class=gdb.WP_WRITE") == 1
    assert "gdb.WP_ACCESS" not in script and "awatch " not in script
    assert script.count("KernixBatchStop(r)") == 1

    raw = ((dist / LOG).read_text(errors="replace")
           if log_override is None else log_override)
    pristine = "KERNIX_G0_BATCH_FOUR_ORIGINAL_SOURCE_QWORDS_PRISTINE "
    armed = "KERNIX_G0_BATCH_FOUR_WRITE_ONLY_NATIVE_WATCHES_ARMED "
    complete = "KERNIX_G0_BATCH_FOUR_DISTINCT_GENUINE_HW_WRITE_STOPS "
    done = "KERNIX_G0_BATCH_GDB_FOUR_TARGETS_STOP_COMPLETE_NO_SOURCE_ATTESTATION_YET"
    assert raw.count(pristine) == raw.count(armed) == raw.count(complete) == raw.count(done) == 1
    assert not any(x in raw for x in (
        "KERNIX_G0_BATCH_DUPLICATE_HW_WATCH_INDEX_",
        "KERNIX_G0_BATCH_GDB_STOP_CAPTURE_ERROR",
        "KERNIX_G0_BATCH_WATCH_SETUP_ERROR",
        "KERNIX_G0_BATCH_GDB_INCOMPLETE_FAIL"))
    assert raw.index(pristine) < raw.index(armed) < raw.index(complete) < raw.index(done)
    assert re.search(
        r"^KERNIX_G0_BATCH_FOUR_ORIGINAL_SOURCE_QWORDS_PRISTINE "
        r"indices=97,98,99,100 boundary=close3 no_writer_yet=1$", raw, re.M)
    assert re.search(
        r"^KERNIX_G0_BATCH_FOUR_WRITE_ONLY_NATIVE_WATCHES_ARMED "
        r"indices=97,98,99,100 no_writer_yet=1$", raw, re.M)
    assert re.search(
        r"^KERNIX_G0_BATCH_FOUR_DISTINCT_GENUINE_HW_WRITE_STOPS "
        r"observed_indices=97,98,99,100 no_full_libc_closure=1$", raw, re.M)
    registrations = re.findall(
        r"^Hardware watchpoint (\d+):\s+(.+)$", raw, re.M)
    # Exactly 4 distinct hardware registrations, plus GDB's one final-stop echo.
    # This matches the confirmed behavior of two-watch GDB, but must be
    # independently verified for four on the original Linux ARM64 host.
    assert [int(number) for number,_ in registrations] == [2,3,4,5,5], (
        "four real registrations and final fourth-target GDB stop echo", registrations)
    assert registrations[3][1] == registrations[4][1]
    for (_,target,_,_),(_,line) in zip(TARGETS, registrations[:4]):
        assert "0x%x" % target in line and "watchpoint" not in line.lower()
    for number in (2,3,4,5):
        assert raw.index("Hardware watchpoint %d:" % number) < raw.index(armed)
    assert raw.index(complete) < raw.rindex("Hardware watchpoint 5:")
    assert re.search(r"(?m)^Old value = 0x283a0$", raw)
    last_new = re.findall(r"(?m)^New value = (0x[0-9a-fA-F]+)$",raw)
    assert len(last_new) == 1 and int(last_new[0],16) != 0x283a0

    # One original loader close3 boundary and one process.
    assert raw.count("KERNIX_G0_LIBC_1214_ORIGINAL_RELOCATION_TARGETS_PRISTINE_AFTER_CLOSE3") == 1

    matches = list(re.finditer(LINE_RE, raw, re.M))
    assert len(matches) == 4, ("four actual separate native hardware callbacks required", len(matches))
    assert raw.index(armed) < matches[0].start() < matches[1].start() < matches[2].start() < matches[3].start() < raw.index(complete)
    observed = {}
    for match in matches:
        (idx_s, t_s, b_s, a_s, pc_s, x4_s, x13_s, x8_s, x28_s,
         guest_s, size_s, cnt_s, source_hex, native_str) = match.groups()
        idx = int(idx_s)
        assert idx in (97,98,99,100) and idx not in observed
        expected = next(z for z in TARGETS if z[0] == idx)
        _, target, before, sym = expected
        after, pc, x4, x13, x8, x28, guest, size, count = [
            int(v,16) for v in (a_s, pc_s, x4_s, x13_s, x8_s,
                                x28_s, guest_s, size_s)] + [int(cnt_s)]
        assert (int(t_s,16), int(b_s,16)) == (target,before)
        assert after != before and after != 0
        assert pc >= 0xffff00000000 and pc % 4 == 0
        assert x4 == target and x13 == after
        assert 0x803000000 <= x8 < 0x803010000
        assert x28 >= 0xffff00000000
        assert size == 3 and count == 2
        assert guest == 0x80100fb8b and LDSO_BASE <= guest < LDSO_BASE+len(ldso)
        file_off = source_offset(ldso,guest-LDSO_BASE,8,5)
        source = ldso[file_off:file_off+8]
        assert bytes.fromhex(source_hex) == source
        assert source[:3] == bytes.fromhex("4c8908")
        assert re.fullmatch(r"stlr_x13,?_?\[x4\]",native_str), (
            "native FEX source JIT store must be original ARM64 STLR x13,[x4]",
            native_str)
        # No symbol-completeness claim: only exact original immutable
        # source-backed ELF executable destination provenance.
        located=[]
        for name, elf, bias in (("libc",libc,LIBC_BASE),("ld-linux",ldso,LDSO_BASE)):
            try:source_offset(elf,after-bias,1,5)
            except AssertionError:continue
            located.append(name)
        assert len(located)==1,("resolved address outside/ambiguous original ELF RX",hex(after),located)
        observed[idx] = {
            "original_jmprel_index":idx,
            "original_symbol":sym,
            "original_guest_target":hex(target),
            "original_source_qword":hex(before),
            "after_real_hardware_write_qword":hex(after),
            "original_source_result_ELF_RX":located[0],
            "native_after_write_pc":hex(pc),
            "live_native_store_register_x4":hex(x4),
            "live_native_store_register_x13":hex(x13),
            "native_ARM64_store_opcode":native_str,
            "original_GNU_x86_JIT_guest_RIP":hex(guest),
            "original_GNU_x86_opcode":source[:3].hex(),
        }
    assert set(observed)=={97,98,99,100}
    assert int(last_new[0],16) == int(observed[100]["after_real_hardware_write_qword"],16)
    return {
        "schema":"kernix.g0.four-real-libc-symbolic-jmprel-writers-in-one-original-FEX-arm64-process.v2",
        "libc_sha256":LIBC_SHA,
        "ldso_sha256":LDSO_SHA,
        "source_original_writer_indices_prior": list(range(86,97)),
        "four_individual_real_native_hardware_writes_in_ONE_FEX_guest_proven":True,
        "indices":[97,98,99,100],
        "writers":[observed[97],observed[98],observed[99],observed[100]],
        "total_individually_real_native_attested_original_libc_JMPREL":15,
        "remaining_132_original_RELA_JMPREL_writers_proven":False,
        "one_process_full_147_relocation_closure_proven":False,
        "original_IFUNC_46_resolver_completion_proven":False,
        "original_guest_main_relocation_RELRO_closure_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }


def negative_controls(dist):
    """Twelve negative mutations of authentic 4-watch single-process GDB log."""
    raw=(dist/LOG).read_text(errors="replace")
    mutations=[]
    def one(name,pattern,replacement):
        changed,count=re.subn(pattern,replacement,raw,count=1,flags=re.M)
        assert count==1 and changed!=raw,("invalid negative control",name,count)
        mutations.append((name,changed))
    one("index_97_forged",r"^(KERNIX_G0_BATCH_REAL_GDB_HW_WRITE index=)93 ",r"\g<1>96 ")
    one("index_98_old_forged",
        r"^(KERNIX_G0_BATCH_REAL_GDB_HW_WRITE index=98 target=0x[0-9a-fA-F]+ original=)0x[0-9a-fA-F]+",
        r"\g<1>0x1")
    one("index_99_new_forged",
        r"^(KERNIX_G0_BATCH_REAL_GDB_HW_WRITE index=99 target=0x[0-9a-fA-F]+ original=0x[0-9a-fA-F]+ after=)0x[0-9a-fA-F]+",
        r"\g<1>0x1")
    one("index_100_original_x86_opcode_forged",
        r"^(KERNIX_G0_BATCH_REAL_GDB_HW_WRITE index=100 .+ original_guest_bytes8=)4c89",
        r"\g<1>0000")
    one("index_97_native_stlr_forged",
        r"^(KERNIX_G0_BATCH_REAL_GDB_HW_WRITE index=97 .+ native_store=)stlr",
        r"\g<1>ldr")
    one("index_98_native_target_register_forged",
        r"^(KERNIX_G0_BATCH_REAL_GDB_HW_WRITE index=98 .+ x4=)0x[0-9a-fA-F]+",
        r"\g<1>0x1")
    one("index_99_native_store_register_forged",
        r"^(KERNIX_G0_BATCH_REAL_GDB_HW_WRITE index=99 .+ x13=)0x[0-9a-fA-F]+",
        r"\g<1>0x1")
    one("index_100_genuine_watch_missing",
        r"^KERNIX_G0_BATCH_REAL_GDB_HW_WRITE index=100 .+$",
        "KERNIX_G0_MISSING_FOURTH_NATIVE_HARDWARE_WRITE")
    one("distinct_completion_forged",
        r"^KERNIX_G0_BATCH_FOUR_DISTINCT_GENUINE_HW_WRITE_STOPS ",
        "KERNIX_G0_FAKE_THREE_HW_STOPS ")
    one("batch_final_stop_forged",
        r"^KERNIX_G0_BATCH_GDB_FOUR_TARGETS_STOP_COMPLETE_NO_SOURCE_ATTESTATION_YET$",
        "KERNIX_G0_BATCH_GDB_INCOMPLETE_FAIL")
    one("final_native_old_forged",
        r"^Old value = 0x[0-9a-fA-F]+$", "Old value = 0x1")
    one("final_native_new_forged",
        r"^New value = 0x[0-9a-fA-F]+$", "New value = 0x1")
    assert len(mutations)==12
    for name,corrupt in mutations:
        try:attest(dist,log_override=corrupt)
        except AssertionError:continue
        raise AssertionError("FAIL OPEN four-watch FEX evidence accepted mutation "+name)
    return [name for name,_ in mutations]


def main(dist):
    proof=attest(dist)
    controls=negative_controls(dist)
    assert len(controls)==12
    proof["twelve_actual_same_process_hw_batch_log_mutations_rejected"]=True
    proof["negative_case_names"]=controls
    (dist / PROOF).write_text(json.dumps(proof,indent=2)+"\n")
    print("KERNIX_G0_JMPREL_97_100_FOUR_REAL_HW_WRITERS_ONE_ORIGINAL_FEX_ARM64_GUEST_PASS_NOT_ALL_LIBC")


if __name__=="__main__":
    assert len(sys.argv)==2
    main(Path(sys.argv[1]))
