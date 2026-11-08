#!/usr/bin/env python3
"""Source-authentic main RELATIVE1 positive and weak zero GOT native hardware events.

The same pinned ARM64 FEX GDB process arms two unconditional access watches
before original guest ExecuteThread. An ARM64 host-audit LDR is never a guest
zero-to-zero store; require an actual native JIT store opcode and address for
that. Source guest x86 writer RIP, RELRO and mprotect remain unproven.
"""
from __future__ import annotations
import copy
import json
import re
import sys
from pathlib import Path

SCHEMA="kernix.g0.original-main-relative1-weakzero-FEX-ARM64-hardware-access.v1"
SHA="9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412"
FEX="02e24ca5c01ed0c864466ed573db347336f70170"
TARGETS={"relative1":0x800003dc0,"_ITM_deregisterTMCloneTable":0x800003fe0}
INITIAL={"relative1":0x1120,"_ITM_deregisterTMCloneTable":0}
FINAL={"relative1":0x800001120,"_ITM_deregisterTMCloneTable":0}
STORES=re.compile(r"\b(stlr|str|stur|stp)\b")
HEX=re.compile(r"0x[0-9a-f]+")

class Reject(ValueError):pass
def need(value,msg):
    if not value:raise Reject(msg)

def classify(report:dict)->dict:
    need(isinstance(report,dict) and report.get("schema")==SCHEMA,
         "not original source same-process FEX relative1 weak-zero hardware observation")
    need(report.get("source_main_sha256")==SHA and report.get("source_fex_commit")==FEX,
         "original GNU ELF or upstream FEX source pin missing")
    need(report.get("source_original_relocation_targets")=={k:hex(v) for k,v in TARGETS.items()},
         "incorrect original ELF RELATIVE and weak GLOB_DAT source offsets")
    need(report.get("source_original_initial_values")=={k:hex(v) for k,v in INITIAL.items()},
         "initial source original ELF zero or nonzero RELATIVE value corrupted")
    need(report.get("source_original_target_expected_final")=={k:hex(v) for k,v in FINAL.items()},
         "real original source destination values changed")
    need(report.get("source_original_mprotect10_boundary")==0x801025db9,
         "the original guest mprotect boundary changed")
    need(report.get("source_ExecuteThread_Cpp_entry_reached") is True
         and report.get("pair_unfiltered_hardware_access_watchpoints_armed") is True,
         "native watches not armed before original FEX ExecuteThread")
    need(report.get("native_process_exited") is True and report.get("host_native_exit_code")==117
         and report.get("gdb_error") is None,
         "bounded FEX guest did not reach known intentionally unsupported mprotect10")
    for key in ("source_guest_x86_writer_RIP_proven",
                "all_original_main_relocation_writers_closed",
                "original_main_PT_GNU_RELRO_sealed",
                "Android_Bionic_Wine_or_game_proven"):
        need(report.get(key) is False,"unproven guest x86 writer, memory seal or gameplay promoted: "+key)
    arr=report.get("native_host_access_events")
    need(isinstance(arr,list) and len(arr)<=120,"unbounded or missing authentic watchpoint events")
    by_target={key:[] for key in TARGETS}
    for i,row in enumerate(arr):
        need(row.get("ordinal")==i and row.get("symbol") in TARGETS,"hardware event chronology or symbol inconsistent")
        key=row["symbol"]
        need(row.get("original_guest_relocation_target")==hex(TARGETS[key]),
             "wrong target memory address for source original ELF")
        need(row.get("expected_final_qword")==hex(FINAL[key]),
             "wrong expected source relocation output")
        pc=row.get("native_PC_after_access")
        val=row.get("observed_qword_after_access")
        insn=row.get("native_disasm_before_PC")
        need(isinstance(pc,str) and HEX.fullmatch(pc) and isinstance(val,str) and HEX.fullmatch(val),
             "native source PC or post-access qword missing")
        need(isinstance(insn,str) and 0<len(insn)<512 and ":" in insn and "0x" in insn,
             "native ARM64 previous opcode witness missing")
        jit=int(pc,16)>=0xff0000000000
        opcode=bool(STORES.search(insn))
        need(row.get("native_jit_address_range") is jit
             and row.get("previous_native_instruction_is_store_opcode") is opcode
             and row.get("native_JIT_store_opcode_at_original_relocation_slot") is (jit and opcode),
             "native JIT STLR or host-audit LDR falsely classified")
        need(row.get("source_original_x86_writer_instruction_proven") is False
             and row.get("guest_RELRO_sealed_proven") is False,
             "source x86 guest writer instruction or RELRO falsely inferred")
        by_target[key].append(row)
    positive=[e for e in by_target["relative1"]
              if e["native_JIT_store_opcode_at_original_relocation_slot"]
              and int(e["observed_qword_after_access"],16)==FINAL["relative1"]]
    zero=[e for e in by_target["_ITM_deregisterTMCloneTable"]
          if e["native_JIT_store_opcode_at_original_relocation_slot"]
          and int(e["observed_qword_after_access"],16)==0]
    need(report.get("native_main_relative1_actual_JIT_store_positive_events")==len(positive)
         and len(positive)>=1, "missing actual native original source RELATIVE JIT positive store")
    need(report.get("native_main_weakzero_zero_to_zero_JIT_store_candidate_events")==len(zero),
         "weak-zero source guest value did not have matching native JIT store classification")
    return {
        "schema":"kernix.g0.original-main-relative-positive-vs-weakzero-ARM64-FEX-hardware-classification.v1",
        "original_main_ELF_sha256":SHA,
        "original_FEX_upstream_commit":FEX,
        "source_relative1_target":"0x800003dc0",
        "source_weak_zero_GLOB_DAT_target":"0x800003fe0",
        "source_weak_zero_dynamic_symbol":"_ITM_deregisterTMCloneTable",
        "real_FEX_process_guest_stop_at_original_mprotect10":True,
        "native_hardware_access_watch_events_total":len(arr),
        "native_hardware_events_relative1":len(by_target["relative1"]),
        "native_hardware_events_weak_zero":len(by_target["_ITM_deregisterTMCloneTable"]),
        "native_jit_source_relative1_real_store_positive_count":len(positive),
        "native_jit_source_weak_zero_zero_to_zero_store_candidate_count":len(zero),
        "native_zero_slot_read_only_Cpp_audit_accesses_are_not_writes":True,
        "source_x86_64_guest_writer_RIP_proven":False,
        "all_original_main_RELRO_eight_guest_writer_RIPs_proven":False,
        "mprotect10_actual_guest_success":False,
        "main_PT_GNU_RELRO_sealed":False,
        "Android_Bionic_Wine_or_real_games_proven":False,
        "interpretation":"An FEX JIT native hardware store at zero slot may prove an ARM64 write but does not by itself establish original x86 source RIP, full dynamic relocation closure or page permissions."
    }

def selftest(raw:dict)->int:
    cases=[
       ("fake original SHA",lambda v:v.update(source_main_sha256="0"*64)),
       ("moved weak GOT target",lambda v:v["source_original_relocation_targets"].update(_ITM_deregisterTMCloneTable="0x800003fff")),
       ("fake weak source expected final",lambda v:v["source_original_target_expected_final"].update(_ITM_deregisterTMCloneTable="0x1")),
       ("fake zero input",lambda v:v["source_original_initial_values"].update(_ITM_deregisterTMCloneTable="0x1")),
       ("fake guest RELRO seal",lambda v:v.update(original_main_PT_GNU_RELRO_sealed=True)),
       ("fake guest source writer RIP",lambda v:v.update(source_guest_x86_writer_RIP_proven=True)),
       ("fake original main relocation closure",lambda v:v.update(all_original_main_relocation_writers_closed=True)),
       ("fake game",lambda v:v.update(Android_Bionic_Wine_or_game_proven=True)),
       ("unproven pre-execute arm",lambda v:v.update(pair_unfiltered_hardware_access_watchpoints_armed=False)),
       ("wrong bounded exit",lambda v:v.update(host_native_exit_code=0)),
       ("forged native positive count",lambda v:v.update(native_main_relative1_actual_JIT_store_positive_events=100)),
    ]
    if raw["native_host_access_events"]:
        cases.extend([
          ("fake event x86 writer",lambda v:v["native_host_access_events"][0].update(source_original_x86_writer_instruction_proven=True)),
          ("fake event JIT flag",lambda v:v["native_host_access_events"][0].update(native_jit_address_range=not v["native_host_access_events"][0]["native_jit_address_range"])),
          ("fake event target",lambda v:v["native_host_access_events"][0].update(original_guest_relocation_target="0x801036360")),
        ])
    for i,(label,change) in enumerate(cases,1):
        bad=copy.deepcopy(raw)
        change(bad)
        try:classify(bad)
        except (Reject,KeyError,TypeError,ValueError):
            print(f"KERNIX_G0_MAIN_WEAKZERO_HARDWARE_FALSE_PROOF_{i:02d}_REJECTED {label}")
        else:raise Reject("false zero or other guest write proof accepted: "+label)
    return len(cases)

def main(args:list[str])->int:
    if len(args)!=3 or args[1] not in ("validate","selftest"):
        print("Usage: weakzero.py validate|selftest FEX_HW_EVIDENCE.json",file=sys.stderr)
        return 2
    raw=json.loads(Path(args[2]).read_text())
    result=classify(raw)
    print(json.dumps(result,indent=2,sort_keys=True))
    if args[1]=="selftest":selftest(raw)
    print("KERNIX_G0_ORIGINAL_MAIN_RELATIVE_NATIVE_STLR_CONTROL_PROVEN_WEAK_ZERO_NATIVE_HW_CLASSIFIED_NO_FAKE_RELRO_OR_GAME")
    return 0

if __name__=="__main__":
    try:raise SystemExit(main(sys.argv))
    except (Reject,KeyError,TypeError,ValueError) as exc:
        print("KERNIX_G0_MAIN_WEAKZERO_REAL_NATIVE_HARDWARE_CLASSIFIER_FAIL_CLOSED: "+str(exc),file=sys.stderr)
        raise SystemExit(1)
