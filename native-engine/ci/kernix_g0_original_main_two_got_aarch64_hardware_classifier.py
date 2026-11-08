#!/usr/bin/env python3
"""Classify same-process genuine ARM64 hardware watch events at original main GOT.

An ARM64 watchpoint event with a plausible native store opcode in the guest JIT
VA region is a native JIT store witness, NOT proof of the exact original
x86_64 ld-linux writer source RIP, correct symbol version binding, full main
RELRO closure, Linux mprotect support, or any Android Windows game.
"""
from __future__ import annotations
import copy
import json
import re
import sys
from pathlib import Path

SHA="9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412"
FEX="02e24ca5c01ed0c864466ed573db347336f70170"
SCHEMA="kernix.g0.original-main-puts-libc-start-real-FEX-ARM64-hardware-GOT-access.v1"
ADDR={"puts":0x800003fd0,"__libc_start_main":0x800003fd8}
EXPECTED={"puts":0x804087bc0,"__libc_start_main":0x80402a200}
STORE=re.compile(r"\b(stlr|str|stur|stp)\b")
READ=re.compile(r"\b(ldr|ldur|ldp|ldar)\b")
HEXPAT=re.compile(r"0x[0-9a-f]+")

class Refuse(ValueError):pass
def check(ok,reason):
    if not ok:raise Refuse(reason)

def classify(report:dict)->dict:
    check(isinstance(report,dict) and report.get("schema")==SCHEMA,"source original dual GOT watchpoint evidence schema missing")
    check(report.get("source_main_sha256")==SHA and report.get("source_fex_commit")==FEX,
          "GOT source original ELF or pinned FEX provenance drift")
    check(report.get("source_original_GOT_targets")=={k:hex(v) for k,v in ADDR.items()},
          "not same original main puts and libc_start_main source ELF targets")
    check(report.get("source_libc_export_expected_final")=={k:hex(v) for k,v in EXPECTED.items()},
          "source libc export expected values changed")
    check(isinstance(report.get("source_original_GOT_initial"),dict)
          and set(report["source_original_GOT_initial"])==set(ADDR)
          and all(HEXPAT.fullmatch(v) for v in report["source_original_GOT_initial"].values()),
          "source original ELF file-backed GOT initials missing")
    check(report.get("source_original_mprotect10_boundary")==0x801025db9,
          "original first unsupported x86_64 guest syscall boundary drift")
    check(report.get("source_ExecuteThread_Cpp_entry_reached") is True
          and report.get("dual_unfiltered_hardware_access_watchpoints_armed") is True,
          "native source watchpoint not actually armed before FEX guest execution")
    check(report.get("native_process_exited") is True
          and report.get("host_native_exit_code")==117 and report.get("gdb_error") is None,
          "real FEX guest did not reach the expected bounded unsupported mprotect10 stop")
    for flag in ("source_guest_x86_GOT_writer_RIP_proven","all_original_main_relocation_writers_closed",
                 "original_main_PT_GNU_RELRO_sealed","Android_Bionic_Wine_or_game_proven"):
        check(report.get(flag) is False,"guest memory or game release gate falsely promoted: "+flag)
    events=report.get("native_host_access_events")
    check(isinstance(events,list) and len(events)<=120,"invalid or unbounded GDB event capture")
    checked=[]
    by_key={key:[] for key in ADDR}
    for index,row in enumerate(events):
        check(isinstance(row,dict) and row.get("ordinal")==index,"GDB hardware event not chronologically numbered")
        key=row.get("symbol")
        check(key in ADDR and row.get("original_guest_source_target")==hex(ADDR[key]),
              "GDB native hardware event target does not belong to original source main")
        pc=row.get("native_PC_after_access")
        value=row.get("observed_qword_after_access")
        check(isinstance(pc,str) and HEXPAT.fullmatch(pc) is not None
              and isinstance(value,str) and HEXPAT.fullmatch(value) is not None,
              "actual host PC or observed memory value missing")
        check(row.get("expected_final_qword")==hex(EXPECTED[key]),"GDB expected exported value drift")
        insn=row.get("native_disasm_before_PC")
        check(isinstance(insn,str) and len(insn)<=512 and "0x" in insn and ":" in insn,
              "native ARM64 instruction disassembly source absent")
        is_jit=int(pc,16)>=0xff0000000000
        is_store=STORE.search(insn) is not None
        check(row.get("native_jit_address_range") is is_jit
              and row.get("previous_native_instruction_is_store_opcode") is is_store
              and row.get("native_JIT_store_opcode_at_original_GOT") is (is_jit and is_store),
              "native JIT store / host audit read classification flags were tampered")
        check(row.get("source_original_x86_GOT_writer_instruction_proven") is False
              and row.get("guest_RELRO_sealed_proven") is False,
              "unverified guest writer or RELRO promoted in raw GDB event")
        by_key[key].append(row)
        checked.append(row)
    candidates={key:[e for e in rows
                     if e["native_JIT_store_opcode_at_original_GOT"]
                     and int(e["observed_qword_after_access"],16)==EXPECTED[key]]
                for key,rows in by_key.items()}
    return {
        "schema":"kernix.g0.original-main-two-RELRO-GOT-hardware-access-native-ARM64-FEX-classifier.v1",
        "original_main_ELF_SHA256":SHA,
        "source_FEX_commit":FEX,
        "source_original_GOT_targets":{k:hex(v) for k,v in ADDR.items()},
        "source_initial_GOT_values":report["source_original_GOT_initial"],
        "total_native_hardware_access_events":len(checked),
        "native_hardware_access_events_per_symbol":{k:len(v) for k,v in by_key.items()},
        "native_JIT_store_opcodes_observed_per_symbol":{k:sum(bool(x["native_JIT_store_opcode_at_original_GOT"]) for x in v)
                                                        for k,v in by_key.items()},
        "native_JIT_store_candidate_final_expected_value_events_per_symbol":{k:len(v) for k,v in candidates.items()},
        "both_source_GOT_expected_final_values_hardware_trap_jit_store_observed":all(len(v)>0 for v in candidates.values()),
        "each_native_hardware_trap_source_PC_and_storing_opcode_checked":True,
        "source_guest_x86_64_GOT_writer_RIP_proven":False,
        "original_MAIN_RELRO_all_eight_writer_PCs_proven":False,
        "FEX_guest_original_main_mprotect10_real_success":False,
        "original_main_PT_GNU_RELRO_sealed":False,
        "Android_Bionic_Wine_or_real_games_proven":False,
        "note":"A native JIT PC and store opcode at an original GOT address is evidence of an ARM64 hardware store, not a source-guest-RIP correlation. No automatic permission change."
    }

def negatives(report):
    cases=[
       ("wrong original source hash",lambda x:x.update(source_main_sha256="0"*64)),
       ("fake RELRO seal",lambda x:x.update(original_main_PT_GNU_RELRO_sealed=True)),
       ("false Android success",lambda x:x.update(Android_Bionic_Wine_or_game_proven=True)),
       ("wrong expected puts address",lambda x:x["source_libc_export_expected_final"].update(puts="0x0")),
       ("no pre-execute witness",lambda x:x.update(source_ExecuteThread_Cpp_entry_reached=False)),
       ("no genuine host exit",lambda x:x.update(host_native_exit_code=0)),
       ("unknown original target",lambda x:x["source_original_GOT_targets"].update(puts="0x800003fe0")),
       ("incorrect original loader boundary",lambda x:x.update(source_original_mprotect10_boundary=0x80101a8e0)),
    ]
    if report["native_host_access_events"]:
        cases += [
          ("forged GDB event source target",lambda x:x["native_host_access_events"][0].update(original_guest_source_target="0x8042014c8")),
          ("forged native original store provenance",lambda x:x["native_host_access_events"][0].update(source_original_x86_GOT_writer_instruction_proven=True)),
          ("forged ARM64 JIT region flag",lambda x:x["native_host_access_events"][0].update(native_jit_address_range=not x["native_host_access_events"][0]["native_jit_address_range"])),
          ("forged execution number",lambda x:x["native_host_access_events"][0].update(ordinal=18)),
        ]
    for idx,(label,mut) in enumerate(cases,1):
        copy_=copy.deepcopy(report)
        mut(copy_)
        try:classify(copy_)
        except (Refuse,TypeError,ValueError,KeyError):
            print(f"KERNIX_G0_ORIGINAL_MAIN_DUAL_GOT_NATIVE_FALSE_PROOF_{idx:02d}_REJECTED {label}")
        else:
            raise Refuse("adversarial false GOT hardware evidence accepted: "+label)
    check(len(cases)==(12 if report["native_host_access_events"] else 8),"native event adversarial count drift")
    return len(cases)

def main(argv):
    if len(argv)!=3 or argv[1] not in ("validate","selftest"):
        print("Usage: classifier.py validate|selftest FEX_HARDWARE_GDB_EVIDENCE.json",file=sys.stderr)
        return 2
    report=json.loads(Path(argv[2]).read_text())
    evidence=classify(report)
    print(json.dumps(evidence,indent=2,sort_keys=True))
    if argv[1]=="selftest":negatives(report)
    print("KERNIX_G0_MAIN_TWO_GOT_NATIVE_ARM64_UNFILTERED_HW_EVENTS_CLASSIFIED_GUEST_X86_WRITER_AND_RELRO_STILL_UNPROVEN")
    return 0

if __name__=="__main__":
    try:raise SystemExit(main(sys.argv))
    except (Refuse,KeyError,TypeError,ValueError) as exc:
        print("KERNIX_G0_DUAL_MAIN_GOT_FEX_HARDWARE_CLASSIFICATION_FAIL_CLOSED: "+str(exc),file=sys.stderr)
        raise SystemExit(1)
