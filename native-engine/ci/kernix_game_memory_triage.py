#!/usr/bin/env python3
"""KERNIX independent game-memory triage gate. No games executed; no root-cause invention."""
from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

SCHEMA = "kernix.game-memory-triage-cases.v1"
ALLOWED_EVENTS = {
    "guest_va_reservation_retries_exhausted",
    "windows_breakpoint_exception",
    "extended_context_log",
    "black_screen",
    "launcher_zombie",
    "window_disappeared",
    "wineserver_sigsegv",
    "wine_message_queue_failure_hypothesis",
    "phone_app_hang_or_reboot",
    "game_runs_on_other_emulator",
    "mod_flicker_or_fps_regression",
}
ALLOWED_LAYERS = {
    "translator_guest_va", "guest_memory_protection", "wine_windows_abi",
    "linux_syscall_boundary", "graphics", "launcher", "host_thermal",
    "host_memory_pressure", "unknown",
}
# Do not equate failed guest VA *reservation* with physical RAM OOM or DXGI VRAM.
PROBE_FIELDS = {
    "first_failure_timestamp", "first_guest_rip", "guest_va_requested",
    "guest_va_requested_bytes", "guest_va_alignment_bytes",
    "requested_protection", "guest_va_region_owner",
    "guest_page_bytes", "host_page_bytes", "linux_errno_or_ntstatus",
    "host_maps_before_after", "wine_virtualquery_before_after",
    "android_pss_bytes", "android_available_ram_bytes",
    "vulkan_heap_budget_bytes", "wine_child_exit_state",
}
PLACEHOLDER = "not_collected"
ALLOWED_ROOT_CAUSES = {"unproven"}  # game-level failures not established by source-only G0
ALLOWED_STAGES = {"observed_without_root_cause", "observed_guest_va_reservation_retries"}

class TriageFailure(ValueError):
    pass

def require(test: bool, reason: str) -> None:
    if not test:
        raise TriageFailure(reason)

def validate_ledger(ledger: dict) -> dict:
    require(isinstance(ledger, dict) and ledger.get("schema") == SCHEMA, "schema mismatch")
    require(ledger.get("project_branch") == "kernix-native-engine-v1", "wrong branch")
    require(ledger.get("not_game_execution_evidence") is True, "CI cannot prove game launch")
    require(ledger.get("original_main_RELRO_sealed_under_FEX") is False, "RELRO remains open")
    require(ledger.get("android_gameplay_proven") is False, "gameplay not proven")
    cases = ledger.get("cases")
    require(isinstance(cases, list) and len(cases) >= 6, "missing historical failure cases")
    case_ids = set()
    report = []
    for case in cases:
        require(isinstance(case, dict), "malformed case")
        ident = case.get("case_id")
        require(isinstance(ident, str) and re.fullmatch(r"[a-z0-9_]{8,80}", ident) is not None, "invalid case id")
        require(ident not in case_ids, "duplicate case id")
        case_ids.add(ident)
        require(isinstance(case.get("game"), str) and case["game"].strip(), "missing game")
        require(isinstance(case.get("edition_or_context"), str) and case["edition_or_context"].strip(), "missing edition/context")
        require(case.get("gameplay_proven_by_kernix") is False, "cannot upgrade observations to gameplay")
        require(case.get("memory_root_cause") in ALLOWED_ROOT_CAUSES, "unproven memory root cause promoted")
        require(case.get("stage") in ALLOWED_STAGES, "unknown diagnostic stage")
        layers = case.get("hypothesis_layers")
        require(isinstance(layers, list) and len(layers) > 0 and len(set(layers)) == len(layers), "missing/duplicate hypothesis layers")
        require(set(layers) <= ALLOWED_LAYERS, "unrecognized hypothesis layer")
        events = case.get("observed_event_kinds")
        require(isinstance(events, list) and len(events) > 0 and len(set(events)) == len(events), "event evidence invalid")
        require(set(events) <= ALLOWED_EVENTS, "unrecognized observed event")
        require(isinstance(case.get("observed_details"), dict), "detail map required")
        probes = case.get("first_failure_probe_fields")
        require(isinstance(probes, dict) and set(probes) == PROBE_FIELDS, "first-failure probe field set incomplete")
        # Unknown data must be explicit, not filled with fabricated counts/addresses.
        for field, value in probes.items():
            require(isinstance(value, str) and value.strip(), "blank probe field "+field)
            if value != PLACEHOLDER:
                require(field in case.get("collected_probe_fields", []), "field silently populated without collected provenance: "+field)
        collected = case.get("collected_probe_fields", [])
        require(isinstance(collected, list) and set(collected) <= PROBE_FIELDS, "unknown collected field")
        require(all(probes[key] != PLACEHOLDER for key in collected), "collected field has no value")
        require(case.get("raw_personal_paths_included") is False, "private path must not be recorded")
        require(case.get("game_files_modified") is False, "historical gate cannot change game files")
        require(isinstance(case.get("next_narrow_probe"), str) and len(case["next_narrow_probe"]) >= 35, "insufficient actionable next probe")
        is_guest_va = "guest_va_reservation_retries_exhausted" in events
        if is_guest_va:
            require(case["stage"] == "observed_guest_va_reservation_retries", "VA reservation signature not classified")
            require("translator_guest_va" in layers, "guest VA evidence not assigned translator hypothesis")
            require(case["observed_details"].get("retry_attempts") == 16, "specific 16-attempt witness lost")
            require(case["observed_details"].get("ram_exhaustion_observed") is False, "guest VA exhaustion misclassified as host RAM exhaustion")
            require(case["observed_details"].get("dxgi_vram_exhaustion_observed") is False, "guest VA exhaustion misclassified as VRAM")
        else:
            require(case["stage"] == "observed_without_root_cause", "unsupported memory-stage upgrade")
        if "black_screen" in events:
            require(case.get("graphics_root_cause_proven") is False, "black screen cannot prove graphics fault")
        if "wineserver_sigsegv" in events:
            require(case.get("sigsegv_memory_root_cause_proven") is False, "SIGSEGV alone cannot prove memory root cause")
        if "extended_context_log" in events:
            require(case.get("extended_context_proves_memory_bug") is False, "context log alone cannot prove memory fault")
        report.append({"case_id": ident, "stage": case["stage"], "first_fault_data_collected": len(collected),
                       "memory_root_cause": case["memory_root_cause"], "gameplay_proven": False})
    require("tlou2_remastered_guest_va_retry" in case_ids, "The Last of Us II VA failure case missing")
    require("forza_horizon_5_extended_context" in case_ids, "Forza context evidence missing")
    require("witcher3_launcher_zombie_black" in case_ids, "Witcher lifetime regression missing")
    require("wine_proton_p11_wineserver_queue" in case_ids, "Wineserver runtime diagnostic missing")
    return {"schema": "kernix.game-memory-triage-validation.v1",
            "validated_case_count": len(cases),
            "root_causes_proven": 0,
            "observed_guest_va_reservation_cases": sum(x["stage"] == "observed_guest_va_reservation_retries" for x in report),
            "gameplay_proven": False,
            "main_RELRO_sealed": False,
            "results": report}

def require_bad(ledger: dict, case_id: str, field: str, value) -> None:
    copy_ = copy.deepcopy(ledger)
    case = next(x for x in copy_["cases"] if x["case_id"] == case_id)
    case[field] = value
    try:
        validate_ledger(copy_)
    except TriageFailure:
        return
    raise TriageFailure("mutation was incorrectly accepted: %s %s" % (case_id, field))

def negative_controls(ledger: dict) -> list[str]:
    targets = [
        ("tlou2_remastered_guest_va_retry", "memory_root_cause", "physical_RAM_oom"),
        ("tlou2_remastered_guest_va_retry", "stage", "observed_without_root_cause"),
        ("tlou2_remastered_guest_va_retry", "gameplay_proven_by_kernix", True),
        ("forza_horizon_5_extended_context", "extended_context_proves_memory_bug", True),
        ("forza_horizon_5_extended_context", "graphics_root_cause_proven", True),
        ("wine_proton_p11_wineserver_queue", "sigsegv_memory_root_cause_proven", True),
        ("witcher3_launcher_zombie_black", "graphics_root_cause_proven", True),
    ]
    for ident, key, value in targets:
        require_bad(ledger, ident, key, value)
    for key, value in [("original_main_RELRO_sealed_under_FEX", True),
                       ("android_gameplay_proven", True),
                       ("not_game_execution_evidence", False)]:
        bad = copy.deepcopy(ledger)
        bad[key] = value
        try:
            validate_ledger(bad)
        except TriageFailure:
            pass
        else:
            raise TriageFailure("global false-promotion mutation accepted: "+key)
    for ident, key, value in targets[:1]:
        bad = copy.deepcopy(ledger)
        case = next(x for x in bad["cases"] if x["case_id"] == ident)
        case["observed_details"]["ram_exhaustion_observed"] = True
        try:
            validate_ledger(bad)
        except TriageFailure:
            pass
        else:
            raise TriageFailure("guest VA was mislabeled RAM OOM")
    return ["KERNIX_GAME_MEMORY_TRIAGE_NEGATIVE_CONTROL_%02d_PASS" % i for i in range(1, 12)]

def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] not in ("validate", "selftest"):
        print("usage: kernix_game_memory_triage.py validate|selftest CASES.json", file=sys.stderr)
        return 2
    ledger = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
    output = validate_ledger(ledger)
    print(json.dumps(output, sort_keys=True, indent=2))
    if argv[1] == "selftest":
        for line in negative_controls(ledger):
            print(line)
    print("KERNIX_GAME_MEMORY_TRIAGE_FAIL_CLOSED_HISTORICAL_PROVENANCE_PASS_NOT_A_GAME_EXECUTION_CLAIM")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except (TriageFailure, ValueError, KeyError, TypeError) as error:
        print("KERNIX_GAME_MEMORY_TRIAGE_FAIL_CLOSED: %s" % error, file=sys.stderr)
        raise SystemExit(1)
