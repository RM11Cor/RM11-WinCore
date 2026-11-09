#!/usr/bin/env python3
"""Create exactly the FIFTH libc symbolic JMPREL write-only GDB source watch.

This is a SOURCE plan, not an executed guest or fifth hardware writer.
Requires four individually independently attested original native writers.
"""
import hashlib
import json
from pathlib import Path
import sys
from kernix_g0_libc_rela_source_inventory_gate import make_inventory

LDSO_SHA = "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"
PRIOR_GDB = "original-libc-fourth-symbolic-jmprel-native-write-watch-plan.gdb"
OUT_GDB = "original-libc-fifth-symbolic-jmprel-native-write-watch-plan.gdb"
OUT_JSON = "original-libc-fifth-symbolic-jmprel-source-watch-plan.json"


def prepare(dist):
    libc_p = dist / "original-source-pinned-root/lib/x86_64-linux-gnu/libc.so.6"
    ldso_p = dist / "original-source-pinned-root/lib64/ld-linux-x86-64.so.2"
    assert libc_p.is_file() and not libc_p.is_symlink()
    assert ldso_p.is_file() and not ldso_p.is_symlink()
    ld = ldso_p.read_bytes()
    assert len(ld) == 235408 and hashlib.sha256(ld).hexdigest() == LDSO_SHA
    inventory = make_inventory(libc_p.read_bytes())
    assert inventory == json.loads(
        (dist / "original-libc-147-rela-jmprel-source-inventory.json").read_text())

    first = json.loads(
        (dist / "original-fex-libc-symbolic-jmprel-first-real-native-writer-proof.json").read_text())
    second = json.loads(
        (dist / "original-libc-next-symbolic-jmprel-live-fex-hw-verified.json").read_text())
    third = json.loads(
        (dist / "original-libc-third-symbolic-jmprel-real-fex-hw-verified.json").read_text())
    fourth = json.loads(
        (dist / "original-libc-fourth-symbolic-jmprel-real-fex-hw-verified.json").read_text())
    assert first["one_original_libc_symbolic_JMPREL_real_hardware_store_proven"] is True
    assert first["selected_original_record_index"] == 86
    assert first["guest_original_target"] == "0x804202ba0"
    assert second["genuine_second_symbolic_source_hardware_store_proven"] is True
    assert second["source_record_index"] == 87
    assert second["source_original_guest_target"] == "0x804202bc0"
    assert second["source_libc_sha256"] == inventory["libc_source_sha256"]
    assert third["third_symbolic_JMPREL_real_native_hardware_writer_proven"] is True
    assert third["third_original_source_relocation_index"] == 88
    assert third["third_original_source_guest_target"] == "0x804202c08"
    assert third["six_actual_native_log_tamper_controls_rejected"] is True
    assert third["source_original_libc_sha256"] == inventory["libc_source_sha256"]
    assert third["source_original_gnu_ldso_sha256"] == LDSO_SHA
    assert fourth["fourth_symbolic_JMPREL_real_native_hardware_store_proven"] is True
    assert fourth["fourth_source_index"] == 89
    assert fourth["fourth_source_guest_target"] == "0x804202c40"
    assert fourth["fourth_original_qword"] == "0x28160"
    assert fourth["fourth_after_native_hardware_store_qword"] == "0x801014840"
    assert fourth["fourth_result_pinned_source_ELF_RX"] == "ld-linux"
    assert fourth["six_actual_native_log_negative_mutations_rejected"] is True
    assert len(fourth["negative_names"]) == 6
    assert fourth["individual_symbolic_JMPREL_hardware_writers_proven"] == 4
    assert fourth["source_original_libc_sha256"] == inventory["libc_source_sha256"]
    assert fourth["source_original_gnu_ldso_sha256"] == LDSO_SHA

    candidates = inventory["next_source_candidates"]
    assert [r["index"] for r in candidates[:4]] == [87, 88, 89, 90]
    selected = candidates[3]
    assert selected["index"] == 90 and selected["table"] == "DT_JMPREL"
    assert selected["r_type"] == 7 and selected["r_sym"] == 5
    assert selected["source_guest_target"] == "0x804202c48"
    assert selected["source_qword"] == "0x28170"
    assert int(selected["r_offset"], 16) + 0x804000000 == int(selected["source_guest_target"], 16)

    previous = (dist / PRIOR_GDB).read_text()
    assert previous.count("index=89 target=0x804202c40 original=0x28160") == 1
    assert previous.count("watch -location *(unsigned long long *)0x804202c40") == 1
    assert previous.count("x/gx 0x804202c40") == 2
    assert "awatch" not in previous and "NOT_YET_SOURCE_ATTESTED=1" in previous
    gdb = previous.replace("0x804202c40", selected["source_guest_target"])
    gdb = gdb.replace("index=89 ", "index=90 ")
    gdb = gdb.replace("original=0x28160 ", "original=" + selected["source_qword"] + " ")
    assert gdb.count(
        "index=90 target=0x804202c48 original=0x28170") == 1
    assert gdb.count("watch -location *(unsigned long long *)0x804202c48") == 1
    assert gdb.count("x/gx 0x804202c48") == 2
    assert "0x804202c40" not in gdb and "index=89 " not in gdb
    assert "awatch" not in gdb
    (dist / OUT_GDB).write_text(gdb)
    out = {
        "schema": "kernix.g0.fifth-original-libc-symbolic-jmprel-original-source-write-watch-plan.v1",
        "source_libc_sha256": inventory["libc_source_sha256"],
        "source_original_gnu_ldso_sha256": LDSO_SHA,
        "individually_source_proven_prior_writer_indices": [86, 87, 88, 89],
        "next_original_libc_jmprel_source_index": selected["index"],
        "next_original_libc_jmprel_type": selected["r_type"],
        "next_original_libc_jmprel_symbol": selected["r_sym"],
        "next_original_guest_target": selected["source_guest_target"],
        "next_original_source_qword": selected["source_qword"],
        "native_watchpoint_mode": "write-only",
        "source_guest_process_native_execution_performed": False,
        "fifth_native_hw_writer_proven": False,
        "remaining_143_writers_verified": False,
        "full_glibc_relocations_closed": False,
        "original_IFUNC_resolvers_completed": False,
        "Android_Bionic_Wine_Proton_games_proven": False,
    }
    (dist / OUT_JSON).write_text(json.dumps(out, indent=2) + "\n")
    print("KERNIX_G0_FIFTH_ORIGINAL_JMPREL_SOURCE_WATCHPLAN_INDEX90_PASS_NOT_EXECUTED")


if __name__ == "__main__":
    assert len(sys.argv) == 2
    prepare(Path(sys.argv[1]))
