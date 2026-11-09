#!/usr/bin/env python3
"""Source-only next libc JMPREL watchpoint after three *independently proven* writers.

No guest execution, no acceptance of a fourth hardware store, no Android claims.
The original SHA-pinned libc source dictates the next record and target.
"""
from pathlib import Path
import json
import sys
from kernix_g0_libc_rela_source_inventory_gate import make_inventory

LD_SHA = "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"
from hashlib import sha256

PREVIOUS_GDB = "original-libc-third-symbolic-jmprel-native-write-watch-plan.gdb"
NEW_GDB = "original-libc-fourth-symbolic-jmprel-native-write-watch-plan.gdb"
NEW_JSON = "original-libc-fourth-symbolic-jmprel-source-watch-plan.json"


def prepare(dist: Path):
    libcfile = dist / "original-source-pinned-root/lib/x86_64-linux-gnu/libc.so.6"
    ldfile = dist / "original-source-pinned-root/lib64/ld-linux-x86-64.so.2"
    assert libcfile.is_file() and not libcfile.is_symlink()
    assert ldfile.is_file() and not ldfile.is_symlink()
    ld = ldfile.read_bytes()
    assert len(ld) == 235408 and sha256(ld).hexdigest() == LD_SHA
    inv = make_inventory(libcfile.read_bytes())
    assert inv == json.loads((dist / "original-libc-147-rela-jmprel-source-inventory.json").read_text())
    first = json.loads((dist / "original-fex-libc-symbolic-jmprel-first-real-native-writer-proof.json").read_text())
    second = json.loads((dist / "original-libc-next-symbolic-jmprel-live-fex-hw-verified.json").read_text())
    third = json.loads((dist / "original-libc-third-symbolic-jmprel-real-fex-hw-verified.json").read_text())
    assert first["one_original_libc_symbolic_JMPREL_real_hardware_store_proven"] is True
    assert first["selected_original_record_index"] == 86
    assert first["guest_original_target"] == "0x804202ba0"
    assert second["genuine_second_symbolic_source_hardware_store_proven"] is True
    assert second["source_record_index"] == 87
    assert second["source_original_guest_target"] == "0x804202bc0"
    assert second["source_libc_sha256"] == inv["libc_source_sha256"]
    assert third["third_symbolic_JMPREL_real_native_hardware_writer_proven"] is True
    assert third["third_original_source_relocation_index"] == 88
    assert third["third_original_source_guest_target"] == "0x804202c08"
    assert third["third_real_native_hardware_after_qword"] == "0x80100cf60"
    assert third["third_resolved_pointer_source_original_elf"] == "original-ld-linux-x86-64.so.2"
    assert third["third_result_inside_pinned_GNU_ldso_RX_PT_LOAD"] is True
    assert third["six_actual_native_log_tamper_controls_rejected"] is True
    assert third["source_original_libc_sha256"] == inv["libc_source_sha256"]
    assert third["source_original_gnu_ldso_sha256"] == LD_SHA
    assert third["cumulative_individually_source_attested_libc_symbolic_JMPREL"] == 3
    rows = inv["next_source_candidates"]
    assert [x["index"] for x in rows[:3]] == [87, 88, 89]
    row = rows[2]
    assert row["index"] == 89 and row["table"] == "DT_JMPREL"
    assert row["r_type"] == 7 and row["r_sym"] > 0
    assert int(row["source_qword"], 16) != 0
    assert int(row["source_guest_target"],16) == 0x804000000 + int(row["r_offset"],16)
    before = row["source_qword"]
    target = row["source_guest_target"]

    third_gdb=(dist / PREVIOUS_GDB).read_text()
    assert third_gdb.count("index=88 target=0x804202c08 original=0x280f0") == 1
    assert third_gdb.count("watch -location *(unsigned long long *)0x804202c08") == 1
    assert third_gdb.count("x/gx 0x804202c08") == 2
    assert "awatch" not in third_gdb
    assert "NOT_YET_SOURCE_ATTESTED=1" in third_gdb
    new_gdb=third_gdb.replace("0x804202c08", target)
    new_gdb=new_gdb.replace("index=88 ", "index=89 ")
    new_gdb=new_gdb.replace("original=0x280f0 ", "original="+before+" ")
    assert new_gdb.count("index=89 target="+target+" original="+before)==1
    assert new_gdb.count("watch -location *(unsigned long long *)"+target)==1
    assert new_gdb.count("x/gx "+target)==2
    assert "0x804202c08" not in new_gdb and "index=88 " not in new_gdb
    assert "awatch" not in new_gdb
    assert "KERNIX_G0_LIBC" not in new_gdb  # do not simulate success logs
    (dist / NEW_GDB).write_text(new_gdb)
    report={
        "schema": "kernix.g0.fourth-original-libc-symbolic-jmprel-source-watch-only.v1",
        "source_libc_sha256": inv["libc_source_sha256"],
        "source_original_gnu_ldso_sha256": LD_SHA,
        "individually_source_proven_prior_writer_indices": [86,87,88],
        "next_original_libc_jmprel_source_index": row["index"],
        "next_original_libc_jmprel_type": row["r_type"],
        "next_original_libc_jmprel_symbol": row["r_sym"],
        "next_original_guest_target": target,
        "next_original_source_qword": before,
        "native_watchpoint_mode": "write-only",
        "source_guest_process_native_execution_performed": False,
        "fourth_native_hw_writer_proven": False,
        "remaining_144_writers_verified": False,
        "full_glibc_relocations_closed": False,
        "original_IFUNC_resolvers_completed": False,
        "Android_Bionic_Wine_Proton_games_proven": False,
    }
    (dist / NEW_JSON).write_text(json.dumps(report,indent=2)+"\n")
    print("KERNIX_G0_FOURTH_ORIGINAL_SYMBOLIC_JMPREL_SOURCE_WATCH_PLAN_PASS_NOT_EXECUTED")


if __name__ == "__main__":
    assert len(sys.argv)==2
    prepare(Path(sys.argv[1]))
