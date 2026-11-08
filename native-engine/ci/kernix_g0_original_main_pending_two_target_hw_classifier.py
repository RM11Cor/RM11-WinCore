#!/usr/bin/env python3
"""Fail-closed authentic FEX ARM64 hardware probe for the NEXT two original main RELRO slots.

Only the original main ELF RELATIVE#0 and weak __gmon_start__ are in scope.
A frozen zero value is never a zero-to-zero write. Even a native JIT STLR
event is NOT a guest x86 writer RIP, completed relocation, RELRO seal or game.
"""
from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

SCHEMA = "kernix.g0.original-main-pending-relative0-gmon-source-fex-hardware-pair.v1"
MAIN_SHA = "9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412"
FEX_SHA = "02e24ca5c01ed0c864466ed573db347336f70170"
TARGET = {"relative0": 0x800003db8, "__gmon_start__": 0x800003fe8}
OLD = {"relative0": 0x1160, "__gmon_start__": 0}
NEW = {"relative0": 0x800001160, "__gmon_start__": 0}
HEX = re.compile(r"0x[0-9a-f]+")
# x/i $pc-4: only the immediately preceding genuine STLR may be counted.
STLR = re.compile(r"^(?:=>\\s*)?(0x[0-9a-f]+):\\s+stlr\\s+(x(?:[12]?[0-9]|30)|xzr),\\s*\\[(x(?:[12]?[0-9]|30)|sp)\\]$", re.I)

class Reject(ValueError):
    pass

def require(condition, error):
    if not condition:
        raise Reject(error)

def inspect(report):
    require(isinstance(report, dict) and report.get("schema") == SCHEMA, "wrong original FEX paired hardware schema")
    require(report.get("source_main_sha256") == MAIN_SHA and report.get("source_fex_commit") == FEX_SHA, "wrong original source or FEX revision")
    require(report.get("targets") == {k: hex(v) for k, v in TARGET.items()}, "source exact target addresses changed")
    require(report.get("original_file_values") == {k: hex(v) for k, v in OLD.items()}, "original file backed slot values not preserved")
    require(report.get("expected_values") == {k: hex(v) for k, v in NEW.items()}, "expected relocation values corrupted")
    require(report.get("entry_before_execute_thread") is True and report.get("both_access_watches_armed") is True,
            "watches not armed before original FEX guest execution")
    require(report.get("native_exit_code") == 117 and report.get("native_exited") is True and report.get("gdb_error") is None,
            "bounded original guest stop is unverified")
    for field in ("source_guest_x86_writer_rips_proven", "all_original_main_relocations_closed",
                  "guest_mprotect10_success", "original_main_RELRO_sealed", "android_wine_or_games_proven"):
        require(report.get(field) is False, "forbidden proof promotion: " + field)
    events = report.get("events")
    require(isinstance(events, list) and len(events) <= 120, "invalid hardware access event ledger")
    candidates = {k: [] for k in TARGET}
    for i, event in enumerate(events):
        require(isinstance(event, dict) and event.get("ordinal") == i, "hardware access chronology invalid")
        k = event.get("symbol")
        require(k in TARGET and event.get("target") == hex(TARGET[k]), "event not source-owned main relocation target")
        pc, insn, after = event.get("native_pc_after"), event.get("native_previous_insn"), event.get("qword_after")
        require(isinstance(pc, str) and HEX.fullmatch(pc) and isinstance(after, str) and HEX.fullmatch(after),
                "missing actual native PC or qword")
        require(isinstance(insn, str) and len(insn) < 256, "missing native previous instruction")
        jit = int(pc, 16) >= 0xff0000000000
        match = STLR.fullmatch(insn.strip())
        previous_stlr = bool(match and int(match.group(1), 16) == int(pc, 16) - 4)
        require(event.get("native_jit_pc") is jit and event.get("native_immediately_previous_stlr") is previous_stlr,
                "native JIT range or actual preceding instruction flags inconsistent")
        base = event.get("stlr_base_address")
        src = event.get("stlr_source_value")
        if previous_stlr:
            require(isinstance(base, str) and HEX.fullmatch(base) and isinstance(src, str) and HEX.fullmatch(src),
                    "STLR register values not available")
            require(int(base, 16) == TARGET[k] and int(src, 16) == int(after, 16),
                    "native STLR base/source registers do not match watched memory")
        else:
            require(base is None and src is None, "non-store audit access has synthetic STLR registers")
        possible = jit and previous_stlr and int(after, 16) == NEW[k]
        require(event.get("native_original_target_stlr_candidate") is possible,
                "hardware read or incorrect write presented as JIT target STLR")
        if possible:
            candidates[k].append(event)
    return {
        "schema": "kernix.g0.original-main-relative0-gmon-native-hardware-probe-result.v1",
        "source_main_sha256": MAIN_SHA,
        "original_fex_commit": FEX_SHA,
        "source_target_count": 2,
        "native_event_count": len(events),
        "native_STLR_candidate_count": {k: len(v) for k, v in candidates.items()},
        "native_STLR_candidates_observed_for_both": all(candidates.values()),
        "source_guest_x86_writer_RIPs_proven": False,
        "all_eight_original_main_relocations_closed": False,
        "mprotect10_success": False,
        "main_RELRO_sealed": False,
        "android_wine_or_games_proven": False,
        "note": "A native zero-to-zero STLR candidate requires real hardware access, source ownership and matching native registers. A zero snapshot, host LDR or disassembly string alone cannot pass. Guest writer RIP still requires an independent mapped guest instruction witness.",
    }

def negatives(report):
    cases = [
        ("main hash spoof", lambda v: v.update(source_main_sha256="0"*64)),
        ("wrong weak slot", lambda v: v["targets"].update(__gmon_start__="0x800003fe0")),
        ("wrong original relative", lambda v: v["original_file_values"].update(relative0="0x0")),
        ("wrong weak expected", lambda v: v["expected_values"].update(__gmon_start__="0x1")),
        ("no pre-execute trap", lambda v: v.update(entry_before_execute_thread=False)),
        ("watches missing", lambda v: v.update(both_access_watches_armed=False)),
        ("fabricated process exit", lambda v: v.update(native_exit_code=0)),
        ("fake guest RIP", lambda v: v.update(source_guest_x86_writer_rips_proven=True)),
        ("fake RELRO seal", lambda v: v.update(original_main_RELRO_sealed=True)),
        ("fake game", lambda v: v.update(android_wine_or_games_proven=True)),
    ]
    if report["events"]:
        cases += [
            ("forged watched slot", lambda v: v["events"][0].update(target="0x800003dc0")),
            ("forged native PC", lambda v: v["events"][0].update(native_pc_after="0x0")),
            ("false native STLR claim", lambda v: v["events"][0].update(native_original_target_stlr_candidate=not v["events"][0]["native_original_target_stlr_candidate"])),
            ("fake guest read/write classification", lambda v: v["events"][0].update(native_immediately_previous_stlr=not v["events"][0]["native_immediately_previous_stlr"])),
            ("non-hardware slot chronology", lambda v: v["events"][0].update(ordinal=123)),
        ]
    for i, (label, mutation) in enumerate(cases, 1):
        altered = copy.deepcopy(report)
        mutation(altered)
        try:
            inspect(altered)
        except (Reject, ValueError, KeyError, TypeError):
            print(f"KERNIX_G0_PENDING_TWO_TARGET_FALSE_PROOF_{i:02d}_REJECTED {label}")
        else:
            raise Reject("false proof accepted: " + label)
    return len(cases)

def main(argv):
    if len(argv) != 3 or argv[1] not in ("validate", "selftest"):
        print("Usage: classifier.py validate|selftest GDB_EVIDENCE.json", file=sys.stderr)
        return 2
    report = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
    result = inspect(report)
    print(json.dumps(result, sort_keys=True, indent=2))
    if argv[1] == "selftest":
        print("KERNIX_G0_PENDING_TWO_TARGET_ADVERSARIAL_REJECTIONS=" + str(negatives(report)))
    print("KERNIX_G0_PENDING_RELATIVE0_GMON_REAL_WATCH_PROBE_RESULT_NOT_X86_WRITER_RIP_OR_RELRO_SEAL")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except (Reject, KeyError, TypeError, ValueError) as e:
        print("KERNIX_G0_PENDING_TWO_TARGET_HARDWARE_CLASSIFIER_FAIL_CLOSED: " + str(e), file=sys.stderr)
        raise SystemExit(1)
