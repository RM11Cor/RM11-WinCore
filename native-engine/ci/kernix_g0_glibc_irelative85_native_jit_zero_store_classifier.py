#!/usr/bin/env python3
"""Fail-closed classifier for a real original glibc IRELATIVE index85 zero-store under FEX.

Consumes the source-pinned independent ARM64 GDB artifact, not simulated event
data or an Android device. Diagnostic FEX adds a CI-only emission marker after
source SHA attestation; this is NOT proof of stock FEX, Android or game launch.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
from pathlib import Path

LDSO_SHA256 = "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"
FEX_UPSTREAM_COMMIT = "02e24ca5c01ed0c864466ed573db347336f70170"
FEX_UPSTREAM_JIT_CPP_BLOB = "2a7e575d03c78e5687f4eddd539984415b8d60ca"
ELF_WRITER_RIP = "0x80100fd60"
LIBC_TARGET = "0x8042014c8"
LDSO_TARGET = "0x801036360"
SCHEMA = "kernix.g0.original-ldso-irelative-source-emitted-FEX-ARM64-code-execution-witness.v1"
SOURCE_MARKER = "KERNIX_G0_LIBC_SINGLE_ZERO_IRELATIVE_SOURCE_READONLY"
LOG_MARKER = "KERNIX_G0_FEX_ORIGINAL_LIBC_INDEX85_ZERO_TO_ZERO_SOURCE_STLR_STEP_EXECUTION_PROVEN_NOT_LDSO_OR_RELRO"

class Refuse(ValueError):
    pass

def check(ok: bool, why: str) -> None:
    if not ok:
        raise Refuse(why)

def classify(e: dict, provenance: dict, log: str) -> dict:
    check(isinstance(e, dict) and e.get("schema") == SCHEMA, "not original source guest/JIT execution receipt")
    check(isinstance(provenance, dict), "invalid source provenance")
    check(provenance.get("original_fex_commit") == FEX_UPSTREAM_COMMIT, "FEX git SHA not source pinned")
    check(provenance.get("jit_cpp_blob") == FEX_UPSTREAM_JIT_CPP_BLOB, "FEX original JIT.cpp blob drift")
    check(provenance.get("original_jit_sha_verified_before_diagnostic_instrumentation") is True, "source not verified before instrumentation")
    check(provenance.get("diagnostic_only_noop_abi_emission_marker_added") is True, "missing isolated code emission marker provenance")
    check(provenance.get("source_jit_cpp_mutated") is True, "instrumented build falsely identified as unchanged")
    check(provenance.get("production_FEX_original_source_unchanged") is True, "production FEX changed")
    check(e.get("source_fex_commit") == FEX_UPSTREAM_COMMIT, "executing another FEX source")
    check(e.get("source_original_ldso_sha256") == LDSO_SHA256, "unrecognized original loader ELF")
    check(e.get("source_writer_guest_rip") == ELF_WRITER_RIP, "not pinned GNU ldso writer")
    check(e.get("source_writer_x86_bytes") == "498906", "not the original mov %rax,(%r14) x86 opcode")
    check(e.get("compiler_native_preprologue_guest_entry_target_proven") is True, "FEX CompileCode was not trapped")
    check(e.get("source_pinned_FEX_noop_abi_marker_reached_after_code_emission") is True, "emitted source JIT code was not attested")
    check(e.get("native_emitted_code_size") == 68, "original writer emitted host JIT block shape changed")
    check(re.fullmatch(r"0x[0-9a-f]+", e.get("native_emitted_code_begin", "")) is not None, "no native code begin")
    check(re.fullmatch(r"[0-9a-f]{64}", e.get("native_emitted_code_bytes", "")) is not None, "emitted code hash missing")
    check(e.get("debugger_error") is None, "GDB diagnostic failed")
    check(e.get("native_exited") is True and e.get("native_exit_code") == 117, "expected unsupported original mprotect boundary not observed")
    check(e.get("original_guest_mprotect10_unsupported") is True, "mprotect support falsely promoted")
    candidates = e.get("native_emitted_store_candidate_addresses")
    check(isinstance(candidates, list), "host JIT candidates missing")
    stlr_candidates = [c for c in candidates if c.get("insn") == "stlr" and c.get("operands") == "x4, [x19]"]
    check(len(stlr_candidates) == 1, "ambiguous original store in native emitted JIT block")
    store_pc = int(stlr_candidates[0]["native_store_candidate_pc"], 16)
    code_start = int(e["native_emitted_code_begin"], 16)
    check(store_pc == code_start + 12, "emitted host store must be 12 bytes after this source block's entry")
    executions = e.get("native_emitted_store_execution_traps")
    check(isinstance(executions, list) and len(executions) == 2, "expected independent hardware trap at block entry and actual store")
    entry, store = executions
    check(entry.get("at_emitted_guest_JIT_entry") is True and entry.get("at_source_guest_JIT_emitted_STLR") is False
          and entry.get("native_code_pc") == e["native_emitted_code_begin"], "missing native entry hardware trap")
    check(store.get("at_emitted_guest_JIT_entry") is False and store.get("at_source_guest_JIT_emitted_STLR") is True
          and store.get("native_code_pc") == hex(store_pc), "missing exact STLR native execution trap")
    check(store.get("original_guest_RIP_source_witness") == ELF_WRITER_RIP, "host store not linked to source GNU ldso x86 RIP")
    check(store.get("source_register") == "0x0" and store.get("target_register") == LIBC_TARGET,
          "RAX/register value or index85 destination wrong")
    check(store.get("target_value_before_store") == "0x0" and store.get("native_zero_slot_after_store") == "0x0",
          "read-before/after zero-to-zero store value mismatch")
    check(store.get("native_store_executed_and_next_pc") == hex(store_pc + 4),
          "single-stepped store did not advance one native AArch64 instruction")
    check(store.get("original_guest_module") == "libc.so.6" and store.get("original_guest_libc_source_index") == 85,
          "dynamic target incorrectly attributed to original GNU loader")
    check(store.get("source_triad_glibc_index85_zero_to_zero_store_executed") is True,
          "missing exact source IRELATIVE record attribution")
    check(e.get("source_original_libc_irelative_index85_target_guest") == LIBC_TARGET
          and e.get("source_original_libc_irelative_index85_resolver_source_va") == "0xc8570",
          "original libc source ELF resolver/target changed")
    check(e.get("guest_original_libc_irelative_index85_zero_to_zero_store_proven") is True,
          "source authentic libc zero store not executed")
    check(e.get("guest_original_ldso_irelative_zero_store_executed_proven") is False
          and e.get("guest_original_irelative_zero_store_executed_proven") is False,
          "source libc target incorrectly promoted to GNU ldso target")
    check(e.get("guest_original_irelative_resolver_executed_proven") is False,
          "original ldso resolver entry falsely claimed")
    for name in ("all_three_ELF_relocations_closed", "main_PT_GNU_RELRO_sealed",
                 "Android_Bionic_or_Wine_game_proven"):
        check(e.get(name) is False, name + " not proven by a single libc store")
    source_rows = [line for line in log.splitlines()
                   if SOURCE_MARKER in line
                   and "index=85 target=8042014c8 resolver_va=c8570" in line
                   and "original_sha=1" in line and "zero_both=1" in line]
    check(len(source_rows) >= 1, "independent real same-process source-locked libc relocation record missing")
    check(LOG_MARKER in log, "real hardware store step succeeded marker missing from source CI log")
    check("KERNIX_G0_FEX_EMITTED_IRELATIVE_JIT_NATIVE_HARDWARE_EXECUTION_STOP " in log, "native execution trap not in raw log")
    return {
        "schema": "kernix.g0.original-fex-glibc-irelative-index85-zero-to-zero-hardware-execution-gate.v1",
        "original_FEX_commit": FEX_UPSTREAM_COMMIT,
        "upstream_original_JIT_cpp_blob_source_pinned": FEX_UPSTREAM_JIT_CPP_BLOB,
        "original_gnu_ldso_source_sha256": LDSO_SHA256,
        "diagnostic_build_only_noop_marker_injected": True,
        "production_FEX_was_not_modified": True,
        "original_x86_writer_from_GNU_ldso_rip": ELF_WRITER_RIP,
        "source_x86_opcode": "498906",
        "original_libc_relocation_source_index": 85,
        "original_libc_source_relocation_resolver_offset": "0xc8570",
        "actual_FEX_native_STLR_PC": hex(store_pc),
        "actual_FEX_guest_store_target": LIBC_TARGET,
        "actual_FEX_store_source_zero": True,
        "actual_FEX_store_destination_original_libc_source_owned": True,
        "actual_native_host_hardware_execution_breakpoint_tripped": True,
        "actual_native_arm64_STLR_executed_with_pc_advance": True,
        "target_value_before_and_after_zero": True,
        "libc_index85_zero_to_zero_store_proven_under_diagnostic_FEX": True,
        "original_gnu_ldso_separate_IRELATIVE_zero_target": LDSO_TARGET,
        "original_gnu_ldso_target_zero_to_zero_store_proven": False,
        "original_gnu_ldso_resolver_execution_proven": False,
        "original_libc_resolver_entry_and_return_independently_proven": False,
        "all_three_original_ELFs_dynamic_relocations_closed": False,
        "original_main_PT_GNU_RELRO_sealed": False,
        "Android_Bionic_Wine_or_real_PC_game_proven": False,
        "historical_game_VA_oom_telemetry_cases_are_not_proven_by_this_host_test": True,
    }

def assert_bad(e: dict, prov: dict, log: str, change, name: str) -> None:
    e1, p1 = copy.deepcopy(e), copy.deepcopy(prov)
    change(e1, p1)
    try:
        classify(e1, p1, log)
    except Refuse:
        return
    raise Refuse("negative control incorrectly accepted: " + name)

def negative_controls(e: dict, prov: dict, log: str) -> list[str]:
    cases = [
        (lambda x, p: x.update(source_writer_guest_rip="0x80100f91c"), "forged guest writer"),
        (lambda x, p: x.update(source_writer_x86_bytes="498907"), "forged source opcode"),
        (lambda x, p: x.update(guest_original_ldso_irelative_zero_store_executed_proven=True), "wrong loader target promoted"),
        (lambda x, p: x.update(main_PT_GNU_RELRO_sealed=True), "false RELRO"),
        (lambda x, p: x.update(Android_Bionic_or_Wine_game_proven=True), "false Android game"),
        (lambda x, p: x.update(guest_original_irelative_resolver_executed_proven=True), "false resolver entry"),
        (lambda x, p: x["native_emitted_store_execution_traps"][1].update(target_register=LDSO_TARGET), "libc target switched to loader"),
        (lambda x, p: x["native_emitted_store_execution_traps"][1].update(source_register="0x1"), "nonzero source"),
        (lambda x, p: x["native_emitted_store_execution_traps"][1].update(native_store_executed_and_next_pc=
                x["native_emitted_store_execution_traps"][1]["native_code_pc"]), "unexecuted native step"),
        (lambda x, p: x.update(native_emitted_store_execution_traps=[]), "missing real store hardware trap"),
        (lambda x, p: p.update(original_jit_sha_verified_before_diagnostic_instrumentation=False), "upstream source unattested"),
        (lambda x, p: p.update(source_jit_cpp_mutated=False), "instrumented source mislabeled unmodified"),
    ]
    for fn, name in cases:
        assert_bad(e, prov, log, fn, name)
    return ["KERNIX_G0_FEX_GLIBC85_ZERO_STORE_NEGATIVE_%02d_PASS" % i for i in range(1,len(cases)+1)]

def main(args: list[str]) -> int:
    if len(args) != 5 or args[1] not in {"validate", "selftest"}:
        print("Usage: classifier.py validate|selftest EVIDENCE_JSON PROVENANCE_JSON GDB_LOG", file=sys.stderr)
        return 2
    e = json.loads(Path(args[2]).read_text())
    provenance = json.loads(Path(args[3]).read_text())
    log = Path(args[4]).read_text(errors="replace")
    result = classify(e, provenance, log)
    print(json.dumps(result, indent=2, sort_keys=True))
    if args[1] == "selftest":
        for msg in negative_controls(e, provenance, log):
            print(msg)
    print("KERNIX_G0_SOURCE_PINNED_FEX_GLIBC85_REAL_NATIVE_ZERO_TO_ZERO_STORE_ACCEPTED_LDSO_RELRO_GAMES_FAIL_CLOSED")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except (Refuse, ValueError, TypeError, KeyError) as exc:
        print("KERNIX_G0_FEX_GLIBC85_STORE_CLASSIFICATION_REFUSED: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
