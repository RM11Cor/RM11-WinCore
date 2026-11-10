#!/usr/bin/env python3
"""Strict independent forensic classification of original GNU IFUNC85 raw FEX access.

A GDB AArch64 'awatch' can trap READ or WRITE, and an 'old=0/new=0'
store may not fire 'watch'. This analyzer can NEVER certify a new writer:
a true guest x86 source-store/JIT/native-store chain requires its own gate.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA, LDSO_SHA, decode_original_libc, classify,
)

WATCH = "original-libc-IFUNC85-DT_RELA-zero-REAL-ARM64-FEX-RAW-DIAGNOSTIC"
ACCESS = "original-libc-IFUNC85-DT_RELA-zero-REAL-ARM64-FEX-RAW-ACCESS"
SOURCE = "original-libc-IFUNC85-DT_RELA-zero-source-only-NO-NATIVE-PROOF"
PRIOR = "original-libc-IFUNC145-146-two-independent-native-hardware-writer-batch-PROOF.json"


def require(ok: bool, label: str) -> None:
    if not ok:
        raise AssertionError("IFUNC85 independent READ-vs-WRITE forensic FAIL-CLOSED: " + label)


def load(path: Path) -> dict:
    require(path.is_file() and not path.is_symlink(), "regular JSON file " + path.name)
    result = json.loads(path.read_text())
    require(isinstance(result, dict), "JSON object " + path.name)
    return result


def text(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), "regular log " + path.name)
    data = path.read_bytes()
    require(300 < len(data) < 500000, "bounded log " + path.name)
    return data.decode("utf-8", errors="replace")


def original_source(triad: Path, src: Path, prev: Path) -> tuple[str,str]:
    libcpath = triad / "lib/x86_64-linux-gnu/libc.so.6"
    ldsopath = triad / "lib64/ld-linux-x86-64.so.2"
    require(libcpath.is_file() and ldsopath.is_file(), "original x86 source")
    libc, ldso = libcpath.read_bytes(), ldsopath.read_bytes()
    require(len(libc) == 2118168 and hashlib.sha256(libc).hexdigest() == LIBC_SHA,
            "exact original SHA x86 GNU libc")
    require(len(ldso) == 235408 and hashlib.sha256(ldso).hexdigest() == LDSO_SHA,
            "exact original SHA x86 GNU ldso")
    records = decode_original_libc(libc)
    require(classify(records)["original_total_RELA_and_JMPREL"] == 147,
            "147 original relocation source records")
    r = records[85]
    require((r["index"],r["table"],r["table_index"],r["r_type"],r["r_sym"]) ==
            (85,"DT_RELA",85,37,0), "real original GNU DT_RELA IFUNC85")
    require(r["original_source_qword"] == "0x0", "original zero QWORD")
    plan = load(src/(SOURCE+".json"))
    target = r["source_guest_target"]
    require(plan["original_guest_target"] == target and
            plan["original_table"] == "DT_RELA" and
            plan["original_relocation_index"] == 85 and
            plan["original_table_ordinal"] == 85 and
            plan["original_unmodified_target_qword"] == "0x0" and
            plan["original_guest_resolver"] == hex(0x804000000+r["r_addend"]),
            "source plan qword target/descriptor parity")
    require(plan["original_source_libc_sha256"] == LIBC_SHA and
            plan["original_source_ldso_sha256"] == LDSO_SHA and
            plan["previously_independently_certified_native_writers"] == 61 and
            plan["new_native_writer_attestations"] == 0 and
            plan["source_only_not_native_hardware_proof"] is True,
            "source-only plan release gate")
    prevproof = load(prev/PRIOR)
    require(prevproof["original_source_libc_sha256"] == LIBC_SHA and
            prevproof["original_source_ldso_sha256"] == LDSO_SHA and
            prevproof["original_source_indices"] == [145,146] and
            prevproof["prior_independently_certified_native_hardware_target_count"] == 59 and
            prevproof["unique_original_libc_native_hardware_writer_target_count"] == 61 and
            len(prevproof["two_independent_native_hardware_writer_receipts"]) == 2 and
            sum(map(len,prevproof["twenty_native_hardware_tamper_cases_rejected"].values())) == 20,
            "prior independently proven 61 writer ledger")

    source_gdb = text(src/(SOURCE+".gdb")) if False else (src/(SOURCE+".gdb")).read_text()
    require(source_gdb.startswith("set pagination off\nset confirm off\n"),
            "real multiline GNU GDB commands")
    require(source_gdb.count("watch -location *(unsigned long long *)"+target) == 1,
            "source exact original target only once")
    require("awatch -location" not in source_gdb and
            "KERNIX_G0_IFUNC85_DT_RELA_RAW_UNVERIFIED_HIT" in source_gdb,
            "source writer-only watch remains immutable")
    return target, source_gdb


def classify_raw(triad: Path, src: Path, native: Path, prev: Path, out: Path) -> dict:
    target, source_gdb = original_source(triad,src,prev)
    report = load(native/(WATCH+".json"))
    watch_log = text(native/(WATCH+".log"))
    require(report["original_source_index"] == 85 and
            report["original_table"] == "DT_RELA" and
            report["original_source_target"] == target and
            report["native_hardware_write_independently_attested"] is False and
            report["old_native_writer_ledger_still_valid_count"] == 61 and
            report["Android_Bionic_Wine_Proton_games_proven"] is False,
            "strictly unproven watch-only source summary")
    require(report["candidate_raw_hardware_log_sha256"] ==
            hashlib.sha256(watch_log.encode()).hexdigest(),
            "watch raw log original sha256 parity")

    access_summary = load(native/(ACCESS+".json"))
    access_log = text(native/(ACCESS+".log"))
    access_gdb = (native/(ACCESS+".gdb")).read_text()
    expected_gdb = source_gdb.replace(
        "watch -location *(unsigned long long *)"+target,
        "awatch -location *(unsigned long long *)"+target,
    ).replace("KERNIX_G0_IFUNC85_DT_RELA_RAW_UNVERIFIED_HIT",
              "KERNIX_G0_IFUNC85_DT_RELA_RAW_UNVERIFIED_ACCESS")
    require(access_gdb == expected_gdb, "unchanged original GDB source except awatch and marker")
    require(access_summary["original_source_index"] == 85 and
            access_summary["original_table"] == "DT_RELA" and
            access_summary["original_source_target"] == target and
            access_summary["native_hardware_write_independently_attested"] is False and
            access_summary["original_GNU_native_writer_ledger_unchanged"] == 61 and
            access_summary["raw_access_includes_reads_not_automatically_a_writer"] is True,
            "access raw is a READ-or-WRITE observation, never proof")
    require(access_summary["log_sha256"] ==
            hashlib.sha256(access_log.encode()).hexdigest(),
            "access native log original sha256 parity")

    arm = "KERNIX_G0_IFUNC85_DT_RELA_CANDIDATE_PREWATCH target="+target
    hit = "KERNIX_G0_IFUNC85_DT_RELA_RAW_UNVERIFIED_ACCESS target="+target
    a = access_log.find(arm)
    h = access_log.find(hit)
    zeros = bool(re.search(r"^"+re.escape(target)+
                            r":\s+0x0{16}\b",access_log,re.MULTILINE))
    hardware_events = len(re.findall(
        r"^Hardware access \(read/write\) watchpoint 2:",
        access_log,re.MULTILINE))
    # GDB first prints an ARMED declaration; a later 'Value = ' or similar
    # trap, the raw access marker and native PC are needed for actual access.
    observed = bool(a>=0 and h>a and zeros and hardware_events>=2)
    native_marker = re.search(
        r"KERNIX_G0_IFUNC85_DT_RELA_RAW_UNVERIFIED_ACCESS target="+
        re.escape(target)+r" pc=0x([0-9a-f]+) x19=0x([0-9a-f]+) RAW_NOT_INDEPENDENT=1",
        access_log,
    )
    candidate_pc = bool(native_marker and observed and
                        int(native_marker.group(1),16)>0xffff00000000)
    # An instruction string after awatch is not enough to conclude a
    # DT_RELA guest store: data READ can trigger this same hardware trap.
    native_store_text = bool(re.search(
        r"\b(?:stlr|str|stur|stp)\s+",
        access_log[h:] if h>=0 else "",re.IGNORECASE))
    outobj = {
        "schema":"kernix.g0.original-ifunc85-independent-raw-access-read-vs-write-forensic.v1",
        "original_source_index":85,
        "original_table":"DT_RELA",
        "original_source_target":target,
        "original_zero_at_arm_seen":zeros and a>=0,
        "raw_arm64_hardware_access_event_detected":observed,
        "raw_arm64_access_pc_candidate_seen":candidate_pc,
        "raw_arm64_nearby_native_store_mnemonic_text_seen":native_store_text,
        "raw_watch_log_sha256":hashlib.sha256(watch_log.encode()).hexdigest(),
        "raw_access_log_sha256":hashlib.sha256(access_log.encode()).hexdigest(),
        "raw_access_includes_reads_and_writes":True,
        "source_x86_DT_RELA_specific_store_jit_proven":False,
        "source_guest_original_IFUNC85_CALL_C3_RET_stack_READ_proven":False,
        "original_IFUNC85_native_hardware_writer_independently_attested":False,
        "all_147_in_one_guest_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
        "previously_independently_certified_native_writer_count":61,
        "newly_certified_writer_target_count":0,
        "remaining_original_writer_source_targets":86,
        "next_gate":"Independently prove native real WRITE address/register/store instruction and exact x86 DT_RELA source guest JIT mapping; never count awatch read",
    }
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(outobj,indent=2)+"\n")
    return outobj


if __name__=="__main__":
    require(len(sys.argv)==6,
            "usage: original-triad-root source-plan-dir raw-native-artifacts-dir prior61-proof-dir output.json")
    result=classify_raw(*map(Path,sys.argv[1:]))
    print("KERNIX_G0_IFUNC85_RAW_ACCESS_FORENSIC_COMPLETE_HOLD_61_147",json.dumps(result,sort_keys=True))
