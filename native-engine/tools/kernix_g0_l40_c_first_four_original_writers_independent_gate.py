#!/usr/bin/env python3
"""Independent stage-C 80..83 GNU GLOB_DAT hardware-writer audit.

A RAW successful ARM64 FEX/GDB job is not independent proof until its
unaltered log is matched against SHA-pinned original GNU ELF sources,
the original per-index relocation ledger, and the generated watch plan.
This gate never implies #84..119, IRELATIVE #85, RELRO closure, Wine,
Android, an APK or a playable game. No policy override is permitted.
"""
from __future__ import annotations
import hashlib
import json
import re
import sys
from pathlib import Path
from kernix_g0_l40_c_original_globdat80_83_real_fex_four_writers_plan import (
    plan as make_plan, SCHEMA as PLAN_SCHEMA, GDB as SCRIPT_NAME,
)

SCHEMA = "kernix.g0.l40c.independent-real-gnu-globdat80-83-one-fex-pid-writer-log-audit.v1"
RAW_SCHEMA = "kernix.g0.l40c.gnu-globdat80-83-four-real-native-writers-one-FEX-pid-raw.v1"
OUT = "KERNIX-G0-C-80-83-Independent-Real-Native-Writer-Audit-NOT-40.json"
LOG = "original80-83-one-FEX-pid.gdb.log"
RAW = "source80-83-one-FEX-RAW-ONLY.json"
NAMES = (
    "BEFORE",
    "FOUR_HARDWARE_WRITERS_ARMED_ONE_PID",
    "LIVE_HARDWARE_WRITER",
    "FOUR_REAL_ORIGINAL_GLOB_DAT_80_83_WRITERS_SAME_ARM64_FEX_PID",
)
COUNTS = (4, 1, 4, 1)
PREFIX = "KERNIX_G0_L40_C_"
PATTERN = re.compile(
    r"^KERNIX_G0_L40_C_([A-Z0-9_]+) (\{[^\r\n]*\})$", re.M
)

def need(ok, msg):
    if not ok:
        raise AssertionError("KERNIX_G0_C_FIRST4_INDEPENDENT_FAIL_CLOSED: " + msg)

def read(path: Path, limit=2_500_000):
    need(path.is_file() and not path.is_symlink(), "real regular file " + str(path))
    value = path.read_bytes()
    need(0 < len(value) <= limit, "bounded evidence input " + str(path))
    return value

def parse(log: str):
    events = {}
    for hit in PATTERN.finditer(log):
        kind = hit[1]
        need(kind in NAMES, "unknown or rejected original GDB event " + kind)
        events.setdefault(kind, []).append((hit.start(), json.loads(hit[2])))
    need(set(events) == set(NAMES), "four exact authentic GDB event kinds")
    for name, count in zip(NAMES, COUNTS):
        need(len(events[name]) == count, "real GDB event count for " + name)
    return events

def audit(log: str, source: dict):
    need(source["schema"] == PLAN_SCHEMA and source["source_indices"] == [80, 81, 82, 83],
         "original GNU first-four SHA-pinned source plan")
    rows = source["four_genuine_original_ELF_GLOB_DAT_source_tuples"]
    need(len(rows) == 4 and [r["index"] for r in rows] == [80, 81, 82, 83]
         and len({r["target"] for r in rows}) == 4
         and all(r["relocation_type"] == "R_X86_64_GLOB_DAT" for r in rows),
         "four original SHA/GNU distinct GLOB_DAT rows")
    need(PREFIX + "REJECT" not in log, "no GDB rejected native event")
    ev = parse(log)
    before = ev[NAMES[0]]
    armed = ev[NAMES[1]][0]
    writers = ev[NAMES[2]]
    final = ev[NAMES[3]][0]
    positions = [p for p, _ in before] + [armed[0]] + [p for p, _ in writers] + [final[0]]
    need(all(a < b for a, b in zip(positions, positions[1:])),
         "BEFORE four, ARM one, native writers four, FINAL one chronological provenance")
    pid = armed[1].get("pid")
    need(type(pid) is int and pid > 0
         and armed[1] == {"pid": pid, "indices": [80, 81, 82, 83]},
         "one authentic Linux ARM64 FEX inferior armed once for four writes")
    for i, row in enumerate(rows):
        expected_before = {"index": row["index"], "pid": pid,
                           "target": row["target"], "value": "0x0"}
        need(before[i][1] == expected_before,
             "original guest qword pristine BEFORE for source index " + str(row["index"]))
        hit = writers[i][1]
        need(set(hit) == {"index", "pid", "pc", "x4", "x13", "x28",
                           "target", "value", "instruction",
                           "source_x86_3bytes", "FEX_guest_entry",
                           "FEX_guest_size", "FEX_native_ops"},
             "exact native GDB hardware trace attributes")
        need(hit["index"] == row["index"] and type(hit["pid"]) is int
             and hit["pid"] == pid and hit["target"] == row["target"]
             and hit["value"] == row["candidate"]
             and hit["x4"] == row["target"] and hit["x13"] == row["candidate"]
             and int(hit["pc"], 16) >= 0xffff00000000
             and int(hit["x28"], 16) >= 0xffff00000000
             and re.search(r"\bstlr\s+x13,\s*\[x4\]", hit["instruction"])
             and hit["source_x86_3bytes"] == "4c8908"
             and hit["FEX_guest_entry"] == "0x80100fb8b"
             and type(hit["FEX_guest_size"]) is int and hit["FEX_guest_size"] == 3
             and type(hit["FEX_native_ops"]) is int and hit["FEX_native_ops"] == 2,
             "real ARM64 store and x86 JIT mapping to original symbol target "
             + str(row["index"]))
    need(final[1] == {
        "pid": pid,
        "indices": [80, 81, 82, 83],
        "targets": [r["target"] for r in rows],
        "values": [r["candidate"] for r in rows],
        "all_147_same_guest_proven": False,
        "Android_Bionic_Wine_Proton_games_proven": False,
    }, "exact same-FEX-inferior GDB final no false loader or game claims")
    return {
        "pid": pid,
        "before": [v for _, v in before],
        "native_writers": [v for _, v in writers],
        "final": final[1],
    }

def mutate(log: str, kind: str, nth: int, field: str, replacement):
    matches = [m for m in PATTERN.finditer(log) if m[1] == kind]
    need(len(matches) == COUNTS[NAMES.index(kind)] and nth < len(matches),
         "exact source event mutation scope")
    hit = matches[nth]
    record = json.loads(hit[2])
    need(field in record and record[field] != replacement,
         "mutation must materially modify a native source claim")
    record[field] = replacement
    line = PREFIX + kind + " " + json.dumps(record, sort_keys=True)
    return log[:hit.start()] + line + log[hit.end():]

def negative_controls(log: str, source: dict):
    cases = []
    for i in range(4):
        cases.extend([
            ("before_index_" + str(i), NAMES[0], i, "index", 500 + i),
            ("before_pid_" + str(i), NAMES[0], i, "pid", 999999),
            ("native_target_" + str(i), NAMES[2], i, "target", "0x1"),
            ("native_pid_" + str(i), NAMES[2], i, "pid", 999999),
            ("native_value_" + str(i), NAMES[2], i, "value", "0x0"),
            ("native_guest_bytes_" + str(i), NAMES[2], i, "source_x86_3bytes", "909090"),
        ])
    cases.extend([
        ("forged_armed_pid", NAMES[1], 0, "pid", 999999),
        ("forged_armed_indices", NAMES[1], 0, "indices", [80, 81, 82]),
        ("forged_final_pid", NAMES[3], 0, "pid", 999999),
        ("forged_final_loader_scope", NAMES[3], 0, "all_147_same_guest_proven", True),
    ])
    need(len(cases) == 28, "28 source/PID/JIT/write/scope negative controls")
    denied = []
    for name, kind, nth, field, value in cases:
        try:
            audit(mutate(log, kind, nth, field, value), source)
        except (AssertionError, KeyError, ValueError, TypeError):
            denied.append(name)
        else:
            raise AssertionError("FORGED_STAGE_C_NATIVE_GDB_LOG_WAS_ACCEPTED " + name)
    need(len(denied) == 28 and len(set(denied)) == 28,
         "all independently falsified real-source controls rejected")
    return denied

def run(triad: Path, ledger: Path, rawdir: Path, repo: Path, out: Path):
    source = make_plan(triad, ledger, repo, out / "regenerated")
    script = read(out / "regenerated" / SCRIPT_NAME, 130000)
    need(hashlib.sha256(script).hexdigest() ==
         source["original_fex_native_watchpoint_script_sha256"],
         "exact generated real native FEX GDB source script hash")
    raw = json.loads(read(rawdir / RAW))
    log = read(rawdir / LOG, 250000).decode(errors="replace")
    rc = int(read(rawdir / "gdb.exit", 60).decode().strip())
    need(raw["schema"] == RAW_SCHEMA
         and raw["source_indices"] == [80, 81, 82, 83]
         and raw["four_original_source_hardware_store_witnesses_one_real_FEX_pid_raw"] is True
         and raw["gdb_exit_code"] == rc == 0
         and raw["native_original_gdb_trace_sha256"] == hashlib.sha256(log.encode()).hexdigest()
         and raw["independently_attested_same_process_writer_count"] == 0
         and raw["stage_C_all_40_native_writers_one_pid_proven"] is False
         and raw["IRELATIVE85_resolver_or_zero_write_proven"] is False
         and raw["JUMP_SLOT_eager_or_lazy_symbol_binding_proven"] is False
         and raw["full_original_dynamic_loader_proven"] is False
         and raw["Android_Bionic_Wine_Proton_games_proven"] is False,
         "raw same-PID FEX record and source scope, no self-certification")
    result = audit(log, source)
    need(raw["same_real_arm64_FEX_inferior_pid"] == result["pid"]
         and raw["source_before_events"] == result["before"]
         and raw["source_native_writer_events"] == result["native_writers"],
         "raw JSON must exactly match unmodified original GDB native events")
    denied = negative_controls(log, source)
    data = {
        "schema": SCHEMA,
        "source_indices_independently_audited_in_one_FEX_pid": [80, 81, 82, 83],
        "native_ARM64_FEX_same_inferior_pid": result["pid"],
        "original_native_gdb_log_sha256": hashlib.sha256(log.encode()).hexdigest(),
        "original_GNU_four_writer_events_independently_audited": 4,
        "counterfeit_native_source_traces_rejected": denied,
        "stage_C_all_40_native_writers_one_pid_proven": False,
        "IRELATIVE85_resolver_or_zero_write_proven": False,
        "JUMP_SLOT_eager_or_lazy_symbol_binding_proven": False,
        "original_main_and_ldso_RELRO_closure_proven": False,
        "all_147_same_guest_native_execution_proven": False,
        "full_original_ELF_dynamic_loader_proven": False,
        "Android_Bionic_Wine_Proton_games_proven": False,
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / OUT).write_text(json.dumps(data, indent=2) + "\n")
    print("KERNIX_G0_C_FIRST_FOUR_NATIVE_GNU_GLOB_DAT_WRITERS_INDEPENDENT_AUDIT_PASS",
          "PID", result["pid"], "FORGERIES_REJECTED", len(denied),
          "NO_STAGE_C_COMPLETION_NO_FULL_LOADER", flush=True)
    return data

if __name__ == "__main__":
    need(len(sys.argv) == 6,
         "usage exact_original_GNU_triad canonical147 prior_FEX_raw repo_root output")
    run(*map(Path, sys.argv[1:]))
