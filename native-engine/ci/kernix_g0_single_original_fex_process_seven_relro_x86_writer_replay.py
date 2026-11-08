#!/usr/bin/env python3
"""Original GNU ld-linux per-source exact x86 writer ledger from a single original FEX process.

From independently archived 2026-11-08 real Linux ARM64 hardware watchpoints,
source x86 byte disassembly, FEX guest-to-host JIT RIP map, native STLR registers,
and true weak zero-to-zero access traps. Source main PT_GNU_RELRO has eight
destinations: source original loader's writer witnesses touch seven, while a
*separate* original main RELATIVE #2 lies outside that page. The eighth page
destination RELATIVE #0 had an authored fixture, not original-loader attribution.

This replay is NOT independent re-execution of original GDB. It is strictly
a fail-closed independent reclassification of the archived genuine-process
report and its source bounds. No mprotect(10) success and no Windows game.
"""
from __future__ import annotations
import copy
import json
import sys
from pathlib import Path

MAIN = "9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412"
LDSO = "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"
SCHEMA = "kernix.g0.original-main-eight-ldso-GNU-source-writers-one-FEX-process.v1"
SOURCE_EVENTS = {
    "RELATIVE_INDEX1":("0x800003dc0","RELATIVE","0x80100f91c",True),
    "RELATIVE_INDEX2":("0x800004008","RELATIVE","0x80100f91c",False),
    "LIBC_START_MAIN":("0x800003fd8","GLOB_DAT","0x80100fb8b",True),
    "WEAK_DEREGISTER":("0x800003fe0","GLOB_DAT_ZERO_TO_ZERO","0x80100fb8b",True),
    "WEAK_GMON":("0x800003fe8","GLOB_DAT_ZERO_TO_ZERO","0x80100fb8b",True),
    "WEAK_REGISTER":("0x800003ff0","GLOB_DAT_ZERO_TO_ZERO","0x80100fb8b",True),
    "CXA_FINALIZE":("0x800003ff8","GLOB_DAT","0x80100fb8b",True),
    "PLT_PUTS":("0x800003fd0","JUMP_SLOT","0x80100fb8b",True),
}
CHRONO = (
    "gdb_exit_zero",
    "all_eight_watchpoints_registered_and_hit_once_each",
    "libc_real_relro_before_first_original_ldso_main_store",
    "each_native_hit_before_capture",
    "each_capture_before_next_installation",
    "next_installation_then_armed_marker_then_native_hit",
    "weak_zero_initial_read_before_each_access_monitor",
    "all_marks_and_real_next_main_relro_and_denial",
)
class Closed(ValueError):
    pass

def require(ok,why):
    if not ok: raise Closed(why)

def inspect(data):
    require(isinstance(data,dict) and data.get("schema")==SCHEMA,"source original GDB same-process proof schema changed")
    require(data.get("main_sha256")==MAIN and data.get("ldso_sha256")==LDSO,"SHA-pinned main or original GNU ldso changed")
    flags={
       "same_FEX_process_all_eight_original_main_ldso_writers_proven":True,
       "same_process_original_loader_real_RELATIVE_writers":2,
       "same_process_original_loader_real_nonzero_GLOB_DAT_and_PLT_writers":3,
       "same_process_original_loader_real_zero_to_zero_weak_GLOB_DAT_writers":3,
       "relative_index0_source_fixture_owned_not_original_GNU_ldso":True,
       "all_nine_original_main_relocation_values_source_matched_in_earlier_process":True,
       "all_nine_main_relocations_in_one_process_proven_complete":False,
       "three_ELF_GNU_ldso_libc_main_dynamic_relocation_closure_proven":False,
       "native_main_PT_GNU_RELRO_sealed":False,
       "FEX_original_main_puts_exit_zero_proven":False,
       "Android_Bionic_phone_execution_proven":False,
       "Wine_Proton_or_Windows_game_proven":False,
    }
    for key,expected in flags.items():
        require(type(data.get(key)) is type(expected) and data.get(key)==expected,
                "invalid original FEX 8 native-source writer boundary: "+key)
    diag=data.get("diagnostics")
    require(isinstance(diag,dict) and diag.get("gdb_exit")==0
            and type(diag["gdb_exit"]) is int,
            "original FEX ARM64 diagnostic process not bounded exit zero")
    timing=diag.get("strict_execution_order_gates")
    per=diag.get("per_original_native_writer_and_source_x86_instruction")
    ids=diag.get("registered_watchpoint_ids")
    require(isinstance(timing,dict) and set(timing)==set(CHRONO)
            and all(timing[k] is True for k in CHRONO),
            "original GNU x86 writer event chronology or guest RELRO boundary missing")
    require(isinstance(per,dict) and set(per)==set(SOURCE_EVENTS)
            and all(per[k] is True for k in SOURCE_EVENTS),
            "not all eight original native hardware traps + original x86 writer instructions")
    require(ids==[z for i in range(2,10) for z in (i,i)],
            "GDB original FEX watchpoint install/hit pair chronology tampered")
    page=[{"name":name,"original_source_main_destination":addr,
           "dynamic_relocation":kind,"source_original_gnu_x86_writer_rip":rip,
           "native_STLR_and_original_x86_instruction_watch_proven":True}
          for name,(addr,kind,rip,is_page) in SOURCE_EVENTS.items() if is_page]
    outside=[{"name":name,"original_source_main_destination":addr,"source_original_gnu_x86_writer_rip":rip}
             for name,(addr,kind,rip,is_page) in SOURCE_EVENTS.items() if not is_page]
    require(len(page)==7 and len(outside)==1 and outside[0]["original_source_main_destination"]=="0x800004008",
            "outside-RELRO source main relative index2 must not be miscounted as page")
    require(len(set(x["original_source_main_destination"] for x in page))==7,
            "source original 7 guest PT_GNU_RELRO destinations duplicated")
    require(sum(x["dynamic_relocation"]=="GLOB_DAT_ZERO_TO_ZERO" for x in page)==3,
            "one original zero-to-zero weak GOT source writer is missing")
    return {
       "schema":"kernix.g0.main-7of8-original-gnu-x86-writers-one-fex-process-replay.v1",
       "original_main_sha256":MAIN,
       "original_ldso_sha256":LDSO,
       "source_upstream_FEX_pin":"02e24ca5c01ed0c864466ed573db347336f70170",
       "original_same_FEX_process_native_x86_writer_watchpoints":8,
       "source_main_relro_page_slots":8,
       "original_source_gnu_x86_writer_instructions_proven_on_relro_page":7,
       "original_source_ldso_writer_outside_main_relro_page":outside,
       "source_page_confirmed_guest_writer_addresses":page,
       "unproven_original_gnu_writer_page_slot_RELATIVE0":"0x800003db8",
       "authored_original_main_RELATIVE0_fixture_not_gnu_loader":True,
       "all_nine_main_relocations_completed_in_one_process":False,
       "whole_original_ldso_libc_main_relocation_closure_proven":False,
       "guest_original_main_mprotect10_success_proven":False,
       "guest_original_main_PT_GNU_RELRO_sealed":False,
       "Android_Bionic_Wine_Proton_games_proven":False,
       "classification":"archived authentic one-process per-write source x86 JIT mapping / hardware events, not newly executed guest",
    }

def negatives(d):
    cases=[
      ("main digest",lambda x:x.update(main_sha256="wrong")),
      ("ldso digest",lambda x:x.update(ldso_sha256="wrong")),
      ("fabricated process",lambda x:x["diagnostics"].update(gdb_exit=117)),
      ("duplicate watch IDs",lambda x:x["diagnostics"]["registered_watchpoint_ids"].__setitem__(0,0)),
      ("fake original ldso source",lambda x:x.update(relative_index0_source_fixture_owned_not_original_GNU_ldso=False)),
      ("fake full closure",lambda x:x.update(all_nine_main_relocations_in_one_process_proven_complete=True)),
      ("fake triad closure",lambda x:x.update(three_ELF_GNU_ldso_libc_main_dynamic_relocation_closure_proven=True)),
      ("fake relro seal",lambda x:x.update(native_main_PT_GNU_RELRO_sealed=True)),
      ("fake game",lambda x:x.update(Wine_Proton_or_Windows_game_proven=True)),
      ("fake zero write count",lambda x:x.update(same_process_original_loader_real_zero_to_zero_weak_GLOB_DAT_writers=2)),
      ("fake original writer count",lambda x:x.update(same_process_original_loader_real_RELATIVE_writers=3)),
    ]
    for key in CHRONO:
        cases.append(("false original guest chronology "+key,
             lambda x,k=key:x["diagnostics"]["strict_execution_order_gates"].__setitem__(k,False)))
    for key in SOURCE_EVENTS:
        cases.append(("faked GNU x86 writer for "+key,
             lambda x,k=key:x["diagnostics"]["per_original_native_writer_and_source_x86_instruction"].__setitem__(k,False)))
    require(len(cases)==27,"expected exact 27 source-bound spoof mutations")
    for i,(name,change) in enumerate(cases,1):
        altered=copy.deepcopy(d)
        change(altered)
        try:inspect(altered)
        except (Closed,KeyError,TypeError,ValueError):
            print(f"KERNIX_G0_SINGLE_FEX_SEVEN_RELRO_WRITER_FALSE_PROOF_{i:02d}_REJECTED {name}")
        else:
            raise Closed("false source-original GNU writer accepted: "+name)
    return len(cases)

def main(argv):
    if len(argv)!=3 or argv[1]!="selftest":
        print("usage: gate.py selftest ONE_FEX_EIGHT_GUEST_WRITERS.json",file=sys.stderr)
        return 2
    data=json.loads(Path(argv[2]).read_text())
    result=inspect(data)
    require(negatives(data)==27,"missing 27 mandatory corrupt original writer proofs")
    print(json.dumps(result,indent=2,sort_keys=True))
    print("KERNIX_G0_SEVEN_OF_EIGHT_ORIGINAL_MAIN_RELRO_X86_WRITER_EVENTS_IN_ONE_FEX_PROVEN_RELATIVE0_FIXTURE_EXCLUDED")
    return 0

if __name__=="__main__":
    try:raise SystemExit(main(sys.argv))
    except (Closed,KeyError,TypeError,ValueError) as exc:
        print("KERNIX_G0_ORIGINAL_ONE_FEX_SEVEN_PAGE_WRITER_REPLAY_FAIL_CLOSED: "+str(exc),file=sys.stderr)
        raise SystemExit(1)
