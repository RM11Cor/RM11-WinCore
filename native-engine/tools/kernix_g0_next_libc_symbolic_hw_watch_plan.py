#!/usr/bin/env python3
"""Generate a source-authenticated GDB native hardware watch plan for the NEXT
unproven libc symbolic JMPREL record. This tool does NOT run FEX or GDB.
"""
from pathlib import Path
import json
import re
import sys

from kernix_g0_libc_rela_source_inventory_gate import make_inventory

SOURCE_BREAK_FILE = (
    "native-engine/android-host/tests/"
    "kernix_g0_original_fex_full_ptload_source_executable_range_arm64.cpp"
)


def build_plan(dist: Path, checkout: Path):
    source_file = (dist / "original-source-pinned-root/lib/x86_64-linux-gnu/libc.so.6")
    source = make_inventory(source_file.read_bytes())
    recorded = json.loads(
        (dist / "original-libc-147-rela-jmprel-source-inventory.json").read_text())
    assert source == recorded, "saved inventory must exactly match source ELF"
    first_proof = json.loads(
        (dist / "original-fex-libc-symbolic-jmprel-first-real-native-writer-proof.json").read_text())
    assert first_proof["one_original_libc_symbolic_JMPREL_real_hardware_store_proven"] is True
    assert first_proof["original_libc_sha256"] == source["libc_source_sha256"]
    assert first_proof["selected_original_record_index"] == 86
    assert first_proof["guest_original_target"] == "0x804202ba0"
    assert first_proof["original_qword"] == "0x28020"
    assert first_proof["real_hardware_after_store_qword"] == "0x8040adf50"
    assert first_proof["remaining_146_libc_rela_jmprel_writers_proven"] is False
    assert first_proof["libc_IFUNC_resolver_paths_proven"] is False
    candidates = recorded["next_source_candidates"]
    assert len(candidates) == recorded["next_source_candidate_count"]
    assert [r["index"] for r in candidates] == recorded["next_source_candidate_indices"]
    assert len(candidates) > 0, "no safe second symbolic JMPREL candidate"
    candidate = candidates[0]
    assert candidate["table"] == "DT_JMPREL" and candidate["index"] > 86
    assert candidate["r_type"] == 7 and candidate["r_sym"] > 0
    original_value = int(candidate["source_qword"], 16)
    target = int(candidate["source_guest_target"], 16)
    source_va = int(candidate["r_offset"], 16)
    assert original_value != 0
    assert target == 0x804000000 + source_va and target % 8 == 0
    assert 0x1ff000 <= source_va < 0x211000

    anchor = "++RealOriginalLdsoLibcCloses;"
    lines = (checkout / SOURCE_BREAK_FILE).read_text().splitlines()
    line_numbers = [i for i, line in enumerate(lines, 1) if line.strip() == anchor]
    assert len(line_numbers) == 1
    # Native GDB watch (write-only), armed at the same genuine close(3)
    # pre-relocation boundary used in prior first writer diagnostics.
    # Hardware stop MUST later be checked independently, including original
    # immutable ELF RX bytes and decoded x86 guest register semantics.
    gdb = r"""set pagination off
set confirm off
set breakpoint pending on
set output-radix 16
handle SIGBUS nostop noprint pass
handle SIGCHLD nostop noprint pass
break __SOURCE__:__LINE__
commands
silent
printf "KERNIX_G0_NEXT_SOURCE_SYMBOLIC_JMPREL_NATIVE_WRITER_WATCH_ARMED index=__INDEX__ target=0x__TARGET__ original=0x__OLD__ NO_WRITER_YET=1\n"
x/gx 0x__TARGET__
watch -location *(unsigned long long *)0x__TARGET__
condition 2 $pc >= 0xffff00000000 && $x28 >= 0xffff00000000
continue
end
run
printf "KERNIX_G0_NEXT_JMPREL_REAL_NATIVE_HW_WRITE_STOP target=0x__TARGET__ after_pc=0x%lx guest_rsp_x8=0x%lx cpu_state_x28=0x%lx NOT_YET_SOURCE_ATTESTED=1\n", $pc, $x8, $x28
x/i $pc-4
x/10i $pc-20
x/gx 0x__TARGET__
set $h=*(unsigned long long *)$x28
set $offset=*(unsigned int *)$h
set $tail=$h+$offset
set $guest_entry=*(unsigned long long *)($tail+8)
set $guest_size=*(unsigned long long *)($tail+16)
set $count=*(unsigned int *)($tail+24)
printf "KERNIX_G0_NEXT_JMPREL_NATIVE_STOP_FEX_JIT_GUEST_SOURCE guest_entry=0x%lx guest_size=0x%lx inst_count=%u host_pc=0x%lx\n", $guest_entry, $guest_size, $count, $pc
x/8bx $guest_entry
printf "KERNIX_G0_NEXT_SYMBOLIC_DIAGNOSTIC_STOP_REQUIRES_INDEPENDENT_X86_NATIVE_SOURCE_VALIDATION\n"
quit
"""
    params = {
        "__SOURCE__": SOURCE_BREAK_FILE,
        "__LINE__": str(line_numbers[0]),
        "__INDEX__": str(candidate["index"]),
        "__TARGET__": f"{target:x}",
        "__OLD__": f"{original_value:x}",
    }
    for a, b in params.items():
        assert a in gdb
        gdb = gdb.replace(a, b)
    assert not re.search(r"__(SOURCE|LINE|INDEX|TARGET|OLD)__", gdb)
    assert gdb.count("watch -location *(unsigned long long *)0x") == 1
    assert "awatch" not in gdb and "watch -location" in gdb
    assert f"x/gx 0x{target:x}" in gdb
    assert "NOT_YET_SOURCE_ATTESTED=1" in gdb

    def accept(row, first):
        return (row["index"] > first and row["table"] == "DT_JMPREL"
                and row["r_type"] == 7 and row["r_sym"] > 0
                and int(row["source_qword"], 16) != 0
                and int(row["source_guest_target"], 16)
                == 0x804000000 + int(row["r_offset"], 16))
    assert accept(candidate, 86)
    assert not accept({**candidate, "index": 86}, 86)
    assert not accept({**candidate, "r_type": 37}, 86)
    assert not accept({**candidate, "r_sym": 0}, 86)
    assert not accept({**candidate, "source_qword": "0x0"}, 86)
    assert not accept({**candidate, "source_guest_target": "0x1"}, 86)

    record = {
        "schema": "kernix.g0.next-original-libc-symbolic-jmprel-watch-plan.v1",
        "source_libc_sha256": source["libc_source_sha256"],
        "verified_first_source_jmprel_index": 86,
        "next_candidate_original_source_index": candidate["index"],
        "next_candidate_original_type": candidate["r_type"],
        "next_candidate_original_symbol": candidate["r_sym"],
        "next_candidate_original_source_qword": candidate["source_qword"],
        "next_candidate_original_guest_target": candidate["source_guest_target"],
        "breakpoint_original_source_file": SOURCE_BREAK_FILE,
        "breakpoint_line": line_numbers[0],
        "GDB_native_hardware_watch_kind": "write_only_watchpoint",
        "prior_source_close3_pre_relocation_boundary_required": True,
        "five_mutated_candidate_controls_rejected": True,
        "next_native_hardware_store_has_executed": False,
        "next_original_guest_writer_x86_RIP_proven": False,
        "next_live_x86_guest_registers_proven": False,
        "all_libc_relocations_closed": False,
        "Android_Bionic_Wine_Proton_games_proven": False,
    }
    (dist / "original-libc-next-symbolic-jmprel-native-write-watch-plan.json").write_text(
        json.dumps(record, indent=2) + "\n")
    (dist / "original-libc-next-symbolic-jmprel-native-write-watch-plan.gdb").write_text(gdb)
    print("KERNIX_G0_ORIGINAL_LIBC_NEXT_SOURCE_JMPREL_WRITE_ONLY_HARDWARE_WATCH_PLAN_PASS_NO_NEW_GUEST_EXEC")


if __name__ == "__main__":
    assert len(sys.argv) == 3
    build_plan(Path(sys.argv[1]), Path(sys.argv[2]))
