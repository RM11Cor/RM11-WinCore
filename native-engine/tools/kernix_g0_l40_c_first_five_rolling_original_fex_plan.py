#!/usr/bin/env python3
"""Extend independently reproducible source80..83 ARM64 FEX GDB experiment
to true original GNU GLOB_DAT84 in the SAME inferior by rolling the watches.

The four original hardware watches are deleted after their actual traps,
then source84 watch is armed. This source plan alone proves NO new writer.
"""
from __future__ import annotations
import ast
import hashlib
import json
import re
import sys
from pathlib import Path
from kernix_g0_l40_c_original_globdat80_83_real_fex_four_writers_plan import (
    plan as four_plan, GDB as FOUR_GDB,
)
from kernix_g0_l40_c_original_mixed_rela_jmprel80_119_source_plan import (
    run as mixed_run,
)

SCHEMA = "kernix.g0.l40c.source-original-gnu-80-84-five-rolling-arm64-fex-one-pid-plan.v1"
OUT = "KERNIX-G0-C-Original-GLOB_DAT80-84-Five-Rolling-One-FEX-PID-SOURCE-ONLY.json"
GDB = "kernix-g0-c-gnu-original-globdat80-84-five-rolling-one-FEX-pid.gdb"

def need(ok, msg):
    if not ok:
        raise AssertionError("KERNIX_G0_C_FIVE_GLOB_DAT_SOURCE_FAIL_CLOSED: " + msg)

def plan(triad: Path, ledger: Path, repo: Path, out: Path):
    four = four_plan(triad, ledger, repo, out / "first-four")
    source = mixed_run(triad, ledger, out / "original-mixed")
    records = source["all_forty_source_records"]
    need([r["index"] for r in records[:5]] == [80, 81, 82, 83, 84],
         "true original GNU five source ordinals")
    r = records[4]
    need(r["index"] == 84 and r["original_table"] == "DT_RELA"
         and r["original_table_ordinal"] == 84
         and r["relocation_type"] == "R_X86_64_GLOB_DAT"
         and r["relocation_type_number"] == 6
         and r["original_source_file_qword"] == "0x0"
         and r["symbol_source_defined_candidate_if_non_TLS"] is not None,
         "exact SHA original fifth GNU GLOB_DAT must have defined non-TLS candidate")
    fifth = {
        "index": 84,
        "target": r["original_guest_target"],
        "candidate": r["symbol_source_defined_candidate_if_non_TLS"],
        "symbol": r["symbol_name"],
        "symbol_index": r["symbol_index"],
        "relocation_type": r["relocation_type"],
    }
    first = four["four_genuine_original_ELF_GLOB_DAT_source_tuples"]
    need(len({x["target"] for x in first + [fifth]}) == 5
         and int(fifth["candidate"], 16) > 0,
         "fifth nonzero real candidate and disjoint true ELF qword target")
    script = (out / "first-four" / FOUR_GDB).read_text()
    need(script.rstrip().endswith("quit") and script.count("\nquit\n") == 1
         and script.count("class OriginalWriter(gdb.Breakpoint)") == 1
         and script.count("wp_class=gdb.WP_WRITE") == 1,
         "reuse proven original GDB first-four watchpoint control flow")
    prefix = script[:script.rfind("\nquit\n")] + "\n"
    extra = r'''python
fifth=__FIFTH_ROW__
assert state["failure"] is None and state["armed"]
assert [x["index"] for x in state["hits"]]==[80,81,82,83]
assert gdb.selected_inferior().pid==state["startup_pid"]
assert qword(int(fifth["target"],16))==0,"authentic original source84 slot not pristine after four"
for bp in list(gdb.breakpoints() or []):
    if isinstance(bp,OriginalWriter):
        bp.delete()
rows.append(fifth)
OriginalWriter(fifth)
jmark("FIFTH_GLOB_DAT84_ARMED_AFTER_FOUR_IN_SAME_PID",
      pid=state["startup_pid"],index=84,target=fifth["target"],pristine="0x0",
      first_four_indices=[80,81,82,83],only_one_watch_armed_after_four=True)
end
continue
python
assert state["failure"] is None,"native source84 store missing or invalid: "+str(state["failure"])
assert [x["index"] for x in state["hits"]]==[80,81,82,83,84]
assert len({x["pid"] for x in state["hits"]})==1
assert gdb.selected_inferior().pid==state["startup_pid"]
jmark("FIVE_REAL_ORIGINAL_GLOB_DAT_80_84_WRITERS_SAME_ARM64_FEX_PID",
      pid=state["startup_pid"],indices=[x["index"] for x in state["hits"]],
      targets=[x["target"] for x in state["hits"]],
      values=[x["value"] for x in state["hits"]],
      source85_IRELATIVE_proven=False,
      all_40_stage_C_proven=False,
      all_147_same_guest_proven=False,
      Android_Bionic_Wine_Proton_games_proven=False)
end
quit
'''.replace("__FIFTH_ROW__", repr(fifth))
    combined = prefix + extra
    blocks = re.findall(r"(?:^|\n)python\n(.*?)\nend(?=\n|$)", combined, re.S)
    need(len(blocks) == 4 and combined.count("\nrun\n") == 1
         and combined.count("\ncontinue\n") == 1
         and combined.count("\nquit\n") == 1
         and combined.count("OriginalWriter(fifth)") == 1,
         "rolling four then fifth in same real Linux ARM64 FEX process")
    for block in blocks:
        ast.parse(block)
    out.mkdir(parents=True, exist_ok=True)
    (out / GDB).write_text(combined)
    data = {
        "schema": SCHEMA,
        "source_indices": [80,81,82,83,84],
        "first_four_rows": first,
        "fifth_original_GNU_GLOB_DAT_source_row": fifth,
        "native_gdb_rolling_script_sha256": hashlib.sha256(combined.encode()).hexdigest(),
        "require_same_true_Linux_ARM64_FEX_pid_across_five": True,
        "simultaneous_hardware_watches_at_most_four": True,
        "new_fifth_native_writer_proven_by_source_only": False,
        "stage_C_all_40_native_writers_proven": False,
        "IRELATIVE85_resolver_or_native_zero_write_proven": False,
        "full_original_GNU_loader_relocation_closure_proven": False,
        "Android_Bionic_Wine_Proton_games_proven": False,
    }
    (out / OUT).write_text(json.dumps(data, indent=2) + "\n")
    print("KERNIX_G0_C_SHA_ORIGINAL_80_84_FIVE_ONE_PID_ROLLING_WATCH_SOURCE_READY",
          fifth, "NO_NEW_NATIVE_WRITER_CLAIMS")
    return data

if __name__ == "__main__":
    need(len(sys.argv) == 5, "usage original_GNU_triad canonical147 ledger repo_root output")
    plan(*map(Path, sys.argv[1:]))
