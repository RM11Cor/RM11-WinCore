#!/usr/bin/env python3
"""Classify authentic FEX ARM64 paired native hardware watch events.

This consumes CI evidence, not live game/Android memory. An AArch64 LDR in a
host audit is an actual hardware read, NOT an x86 zero-to-zero IRELATIVE store.
The same-process STLR control proves the watchpoint can observe FEX native JIT.
"""
from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

LDSO_SHA = "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"
MAIN_SHA = "9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412"
WATCH_SCHEMA = "kernix.g0.original-ldso-irelative-unfiltered-arm64-paired-hardware-access.v1"
JIT_SCHEMA = "kernix.g0.original-FEX-native-host-first-opcode-guest-JIT-block-coverage.v1"

class RefusedEvidence(ValueError):
    pass

def require(condition: bool, reason: str) -> None:
    if not condition:
        raise RefusedEvidence(reason)

def classify(watch: dict, jit: dict) -> dict:
    require(isinstance(watch, dict) and watch.get("schema") == WATCH_SCHEMA, "hardware watch schema missing")
    require(isinstance(jit, dict) and jit.get("schema") == JIT_SCHEMA, "source JIT span schema missing")
    require(watch.get("source_locked_ldso_sha256") == LDSO_SHA, "watch ldso source not pinned")
    require(jit.get("original_ldso_sha256") == LDSO_SHA, "JIT ldso source not pinned")
    require(watch.get("source_locked_main_sha256") == MAIN_SHA, "watch main source not pinned")
    require(watch.get("pre_execute_cpp_source_breakpoint_reached") is True, "native watch armed at wrong runtime stage")
    require(watch.get("both_native_unfiltered_hardware_access_watchpoints_installed") is True, "watch not armed")
    require(watch.get("zero_target_value_before_guest_execution") == "0x0", "original zero slot not initially zero")
    require(watch.get("main_relative1_value_before_guest_execution") == "0x1120", "main positive control not original")
    require(watch.get("native_process_exited") is True and watch.get("native_exit_code") == 117, "bounded FEX execution boundary changed")
    require(watch.get("gdb_error") is None, "GDB runtime failed")
    for key in (
        "guest_irelative_zero_to_zero_store_proven",
        "guest_original_irelative_resolver_executed_proven",
        "all_original_dynamic_relocations_closed",
        "main_PT_GNU_RELRO_sealed",
        "Android_Bionic_or_Wine_game_proven",
    ):
        require(watch.get(key) is False, "unsupported original ARM64 or game proof promoted: "+key)
    require(watch.get("FEX_guest_mprotect10_is_explicitly_unsupported") is True,
            "unsupported mprotect boundary must remain explicit")
    require(jit.get("original_writer_exact_native_FEX_JIT_three_byte_positive_control_proven") is True,
            "independent source JIT main writer control absent")
    require(jit.get("original_irelative_zero_writer_JIT_block_coverage_seen") is True,
            "source authentic zero writer compile request missing")
    require(jit.get("original_source_irelative_zero_store_opcode_source_sha_verified") is True,
            "source x86 zero writer byte identity missing")
    require(jit.get("original_irelative_resolver_JIT_block_coverage_seen") is False,
            "guest resolver compilation window materially changed")
    require(jit.get("reached_original_main_mprotect_boundary") is True,
            "guest loader stopped before prior boundary")
    require(jit.get("irelative_original_target_zero_store_proven") is False,
            "JIT compile-only proof cannot claim executed store")
    main = watch.get("original_main_relative_positive_control_access_events")
    zero = watch.get("original_ldso_irelative_zero_slot_access_events")
    require(isinstance(main, list) and 1 <= len(main) <= 12, "main hardware positive events missing")
    require(isinstance(zero, list) and 1 <= len(zero) <= 12, "zero slot native access missing or unclassifiable")
    all_events = main + zero
    for row in all_events:
        require(row.get("stop_from_real_GDB_hardware_access_watchpoint") is True, "nonhardware access")
        require(row.get("source_guest_rip_of_access_proven") is False, "guest RIP promoted without provenance")
        require(row.get("native_store_versus_read_proven") is False, "unvalidated old evidence store claim")
        require(row.get("guest_zero_to_zero_store_proven") is False, "unverified guest writer claim in raw evidence")
        require(re.fullmatch(r"0x[0-9a-f]+", row.get("host_pc_after_hardware_access", "")) is not None, "bad host PC")
        require(isinstance(row.get("native_PC_minus_4_instruction_disassembly"), str), "no host opcode witness")
    positives = [row for row in main
                 if row.get("observed_target") == "0x800003dc0"
                 and row.get("target_value_after_access") == "0x800001120"
                 and re.search(r"\bstlr\s+x7,\s*\[x10\]", row["native_PC_minus_4_instruction_disassembly"])
                 and int(row["host_pc_after_hardware_access"], 16) >= 0xff0000000000
                 and int(row.get("native_x28_state_register", "0"), 16) >= 0xff0000000000]
    require(len(positives) == 1, "no unique genuine native FEX JIT STLR positive hardware watch")
    # Earlier zero-slot watch used $pc >= 0xffff00000000 &&
    # $x28 >= 0xffff00000000. The native *actual* JIT STLR from this
    # source-pinned run lives at 0xff72..., with x28 also at 0xff72....
    # Consequently the historical condition would suppress a real JIT
    # store; its old no-stop result cannot establish nonexecution.
    obsolete_filter=0xffff00000000
    older_watch_filter_rejected_real_JIT=all(
        int(row["host_pc_after_hardware_access"],16)<obsolete_filter
        and int(row["native_x28_state_register"],16)<obsolete_filter
        for row in positives)
    require(older_watch_filter_rejected_real_JIT,
            "historical restrictive PC/X28 filter not disproven by this source-pinned JIT control")
    host_reads = [row for row in zero
                  if row.get("observed_target") == "0x801036360"
                  and row.get("target_value_after_access") == "0x0"
                  and "SampleOriginalLdsoThreeRelaReadOnly" in row["native_PC_minus_4_instruction_disassembly"]
                  and re.search(r"\bldr\s+x8,\s*\[x12,\s*x13\]", row["native_PC_minus_4_instruction_disassembly"])
                  and int(row["host_pc_after_hardware_access"],16) < 0xff0000000000]
    require(len(host_reads) == len(zero), "a zero target event was NOT source-classified as host-only read; fail closed")
    # Both observations come from one FEX process. Source compile block entry
    # evidence is another process/step; never conflate the two as a writer trace.
    return {
        "schema": "kernix.g0.fex-original-irelative-paired-hardware-event-classification.v1",
        "original_FEX_source_pinned": True,
        "original_source_ldso_sha256": LDSO_SHA,
        "same_FEX_process_original_main_native_STLR_positive_events": len(positives),
        "old_restrictive_native_PC_and_x28_filter_would_suppress_this_real_JIT_positive": older_watch_filter_rejected_real_JIT,
        "historical_conditional_no_watchpoint_hit_cannot_prove_zero_slot_nonexecution": True,
        "same_FEX_process_zero_slot_host_audit_LDR_events": len(host_reads),
        "same_FEX_process_zero_slot_native_JIT_write_events_observed": 0,
        "separate_FEX_process_source_zero_writer_JIT_compile_request_observed": True,
        "separate_FEX_process_resolver_JIT_compile_request_observed": False,
        "source_x86_zero_store_opcode": "498906",
        "source_guest_irelative_zero_store_rip": "0x80100fd60",
        "source_irelative_zero_target_guest_address": "0x801036360",
        "hardware_guest_zero_to_zero_write_proven": False,
        "source_guest_irelative_resolver_execution_proven": False,
        "all_three_original_ELF_relocations_closed": False,
        "main_PT_GNU_RELRO_sealed": False,
        "Android_Bionic_Wine_or_real_PC_games_proven": False,
        "no_native_JIT_zero_hit_within_bounded_run_does_not_prove_never_executes": True,
    }

def adversarial(watch: dict, jit: dict) -> list[str]:
    failures = []
    def bad_watch(mut, name):
        modified = copy.deepcopy(watch)
        mut(modified)
        try:
            classify(modified, jit)
        except RefusedEvidence:
            failures.append(name)
        else:
            raise RefusedEvidence("negative control incorrectly passed: "+name)
    def bad_jit(mut, name):
        modified = copy.deepcopy(jit)
        mut(modified)
        try:
            classify(watch, modified)
        except RefusedEvidence:
            failures.append(name)
        else:
            raise RefusedEvidence("negative control incorrectly passed: "+name)
    bad_watch(lambda x: x.update(guest_irelative_zero_to_zero_store_proven=True), "fake zero store")
    bad_watch(lambda x: x.update(main_PT_GNU_RELRO_sealed=True), "fake RELRO")
    bad_watch(lambda x: x.update(Android_Bionic_or_Wine_game_proven=True), "fake Android game")
    bad_watch(lambda x: x.update(native_exit_code=0), "erased unsupported original syscall")
    bad_watch(lambda x: x.update(original_main_relative_positive_control_access_events=[]), "missing hardware positive")
    bad_watch(lambda x: x["original_main_relative_positive_control_access_events"][2].update(
        native_PC_minus_4_instruction_disassembly="ldr x7, [x10]"), "fake STLR to LDR")
    bad_watch(lambda x: x["original_ldso_irelative_zero_slot_access_events"][0].update(
        native_PC_minus_4_instruction_disassembly="stlr x8, [x12]"), "fake host LDR to guest writer")
    bad_watch(lambda x: x["original_ldso_irelative_zero_slot_access_events"][0].update(
        source_guest_rip_of_access_proven=True), "promoted host read as original guest RIP")
    bad_jit(lambda x: x.update(original_irelative_zero_writer_JIT_block_coverage_seen=False),
            "missing separate JIT compilation witness")
    bad_jit(lambda x: x.update(irelative_original_target_zero_store_proven=True),
            "promoted FEX compilation to guest execution")
    require(len(failures)==10, "adversarial test count drift")
    return failures

def main(args: list[str]) -> int:
    if len(args)!=4 or args[1] not in {"validate","selftest"}:
        print("Usage: classifier.py validate|selftest ARM64_WATCH_JSON FEX_JIT_JSON", file=sys.stderr)
        return 2
    watch = json.loads(Path(args[2]).read_text())
    jit = json.loads(Path(args[3]).read_text())
    report = classify(watch, jit)
    print(json.dumps(report, sort_keys=True, indent=2))
    if args[1]=="selftest":
        for i,name in enumerate(adversarial(watch,jit),1):
            print(f"KERNIX_G0_FEX_IRELATIVE_HW_EVENT_NEGATIVE_CONTROL_{i:02d}_PASS {name}")
    print("KERNIX_G0_FEX_ORIGINAL_IRELATIVE_ZERO_SLOT_HOST_LDR_CLASSIFIED_MAIN_JIT_STLR_POSITIVE_PASS_NO_GUEST_ZERO_STORE_PROOF")
    return 0

if __name__=="__main__":
    try:
        raise SystemExit(main(sys.argv))
    except (RefusedEvidence, ValueError, TypeError, KeyError) as error:
        print("KERNIX_G0_FEX_PAIRED_HW_EVENT_CLASSIFIER_FAIL_CLOSED: "+str(error),file=sys.stderr)
        raise SystemExit(1)
