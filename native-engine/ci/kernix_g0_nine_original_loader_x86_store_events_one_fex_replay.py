#!/usr/bin/env python3
"""Strict replay: nine source-authentic original main GNU loader x86 writer events.

An old successful FEX ARM64 native GDB run preserved real hardware traps,
source SHA, JIT RIP maps and live registers for original main ELF's nine
dynamic relocation destinations. Eight targets are inside original main
PT_GNU_RELRO; one RELATIVE#2 target is OUTSIDE RELRO. RELATIVE#0 is only
admissible after both the earlier authored test fixture write and the later
native hardware watch of the original GNU loader's same-value rewrite.

Reclassify exact logged evidence and compare with an independent 8-event
one-process proof. This does not rerun real FEX, demonstrate all process
ldso/libc relocation completion, execute mprotect(10), seal page, or run games.
"""
from __future__ import annotations
import copy
import json
import sys
from pathlib import Path
from kernix_g0_single_original_fex_process_seven_relro_x86_writer_replay import (
    inspect as seven_inspect, Closed as SevenClosed,
)

MAIN = "9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412"
LDSO = "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"
SCHEMA = "kernix.g0.original-main-nine-GNU-loader-source-store-events-one-FEX-process.v1"
SOURCE = {
    "RELATIVE_INDEX0": ("0x800003db8", "RELATIVE", "0x80100f91c", True),
    "RELATIVE_INDEX1": ("0x800003dc0", "RELATIVE", "0x80100f91c", True),
    "RELATIVE_INDEX2": ("0x800004008", "RELATIVE", "0x80100f91c", False),
    "LIBC_START_MAIN": ("0x800003fd8", "GLOB_DAT", "0x80100fb8b", True),
    "WEAK_DEREGISTER": ("0x800003fe0", "WEAK_GLOB_DAT_ZERO_TO_ZERO", "0x80100fb8b", True),
    "WEAK_GMON": ("0x800003fe8", "WEAK_GLOB_DAT_ZERO_TO_ZERO", "0x80100fb8b", True),
    "WEAK_REGISTER": ("0x800003ff0", "WEAK_GLOB_DAT_ZERO_TO_ZERO", "0x80100fb8b", True),
    "CXA_FINALIZE": ("0x800003ff8", "GLOB_DAT", "0x80100fb8b", True),
    "PLT_PUTS": ("0x800003fd0", "JUMP_SLOT", "0x80100fb8b", True),
}
CHRONO = (
    "gdb_exit_zero",
    "original_source_addend_before_authored_fixture",
    "fixture_initial_write_before_original_loader_rewrite",
    "all_eight_watchpoints_registered_and_hit_once_each",
    "libc_real_relro_before_first_original_ldso_main_store",
    "each_native_hit_before_capture",
    "each_capture_before_next_installation",
    "next_installation_then_armed_marker_then_native_hit",
    "weak_zero_initial_read_before_each_access_monitor",
    "all_marks_and_real_next_main_relro_and_denial",
)
class FailClosed(ValueError):
    pass
def require(x,msg):
    if not x: raise FailClosed(msg)

def inspect(nine, old_eight):
    require(isinstance(nine,dict) and nine.get("schema")==SCHEMA,
            "wrong SHA-pinned original GNU ld-linux 9 source writer FEX schema")
    require(nine.get("main_sha256")==MAIN and nine.get("ldso_sha256")==LDSO,
            "original source ELF SHA mismatched")
    should={
        "same_FEX_process_all_nine_original_main_ldso_source_writer_events_proven":True,
        "original_main_RELATIVE_index0_fixture_prewrite_and_original_ldso_rewrite":True,
        "original_main_two_other_RELATIVE_writer_events":2,
        "original_main_three_weak_zero_GLOB_DAT_writer_events":3,
        "original_main_three_libc_symbolic_and_PLT_writer_events":3,
        "main_all_nine_authentic_original_ldso_store_instructions_seen":True,
        "all_three_ELF_ldso_libc_main_relocations_closed":False,
        "main_PT_GNU_RELRO_sealed":False,
        "libc_and_ldso_full_relocation_and_IFUNC_proven":False,
        "main_puts_exit_zero_under_FEX_proven":False,
        "Android_Bionic_or_Wine_games_proven":False,
    }
    for k,v in should.items():
        require(type(nine.get(k)) is type(v) and nine.get(k)==v,
                "invalid original GNU dynamic linker provenance assertion: "+k)
    d=nine.get("diagnostics")
    require(isinstance(d,dict) and type(d.get("gdb_exit")) is int and d["gdb_exit"]==0,
            "real original GNU FEX writer GDB process did not finish bounded")
    chrono=d.get("same_process_chronological_checks")
    hits=d.get("native_store_per_GNU_source_guest_RIP")
    ids=d.get("native_hardware_watchpoint_ids")
    require(isinstance(chrono,dict) and set(chrono)==set(CHRONO) and
            all(chrono[k] is True for k in CHRONO),
            "original loader writer traps or fixture chronology unproven")
    require(isinstance(hits,dict) and set(hits)==set(SOURCE) and
            all(hits[k] is True for k in SOURCE),
            "nine original main GNU x86 writer source instructions not individually mapped")
    require(ids==[a for i in range(2,11) for a in (i,i)],
            "not nine original GNU loader source writer trap installation/hit pairs")
    require(d.get("source_addend_before_authored_fixture") is True
            and d.get("fixture_write_preceded_gnu_ldso_original_index0_rewrite") is True,
            "RELATIVE#0 early fixture not separated from original GNU ld-linux rewrite")
    # Independently collected genuine FEX process captured previous eight
    # original loader x86 instructions without index0 fixture rewrite.
    prior=seven_inspect(old_eight)
    require(prior["original_source_gnu_x86_writer_instructions_proven_on_relro_page"]==7,
            "prior eight-source original FEX capture contradicts nine-writer proof")
    require(prior["original_ldso_sha256"]==LDSO and prior["original_main_sha256"]==MAIN,
            "source SHA drift between independent FEX hardware captures")
    for name in SOURCE:
        if name=="RELATIVE_INDEX0": continue
        require(old_eight["diagnostics"]["per_original_native_writer_and_source_x86_instruction"].get(name) is True,
                "independently gathered other eight source instructions inconsistent: "+name)
    records=[
        {"original_source_main_relocation":name,
         "original_source_main_target":dest,
         "source_original_gnu_ldso_guest_writer_rip":rip,
         "type":kind,
         "original_GNU_x86_store_native_STLR_witness_proven":True}
        for name,(dest,kind,rip,in_page) in SOURCE.items() if in_page
    ]
    outside=[
        {"original_source_main_relocation":name,"original_source_main_target":dest,
         "source_original_gnu_ldso_guest_writer_rip":rip}
        for name,(dest,kind,rip,in_page) in SOURCE.items() if not in_page
    ]
    require(len(records)==8 and len({r["original_source_main_target"] for r in records})==8,
            "not eight unique original RELRO source targets")
    require(len(outside)==1 and outside[0]["original_source_main_target"]=="0x800004008",
            "source main RELATIVE index2 outside page was misclassified")
    require(sum(r["type"]=="WEAK_GLOB_DAT_ZERO_TO_ZERO" for r in records)==3,
            "zero-to-zero source x86 writer evidence incomplete")
    return {
       "schema":"kernix.g0.original-main-8of8-exact-gnu-source-x86-writer-events-one-FEX-process-replay.v1",
       "original_source_main_sha256":MAIN,
       "original_source_ldso_sha256":LDSO,
       "source_pinned_FEX_commit":"02e24ca5c01ed0c864466ed573db347336f70170",
       "original_main_source_RELRO_page_unique_targets":8,
       "source_original_gnu_x86_writer_instruction_witness_targets":8,
       "original_gnu_loader_writer_events_in_one_native_FEX_process_including_outside_page":9,
       "source_original_main_relro_writer_events":records,
       "outside_page_relative_index2_original_gnu_writer":outside,
       "original_main_relative0_fixtured_then_GNU_ldso_same_value_rewrite_proven":True,
       "three_original_weak_zero_to_zero_source_guest_x86_store_witnesses":3,
       "crosschecked_against_earlier_same_FEX_eight_source_writers":True,
       "original_full_ldso_libc_main_relocation_closure_proven":False,
       "original_main_guest_mprotect10_success":False,
       "original_main_PT_GNU_RELRO_sealed":False,
       "android_bionic_wine_proton_games_proven":False,
       "warning":"Independently reclassified archived source JIT and hardware store evidence. Full original ld-linux/libc/IFUNC closure, mprotect10 and Android game execution remain unproven."
    }

def negatives(nine,eight):
    negatives=[
      ("source main sha",lambda x:x.update(main_sha256="bad")),
      ("original ldso sha",lambda x:x.update(ldso_sha256="bad")),
      ("fake nine proven",lambda x:x.update(main_all_nine_authentic_original_ldso_store_instructions_seen=False)),
      ("fake relative0 rewrite",lambda x:x.update(original_main_RELATIVE_index0_fixture_prewrite_and_original_ldso_rewrite=False)),
      ("fake other relative count",lambda x:x.update(original_main_two_other_RELATIVE_writer_events=1)),
      ("fake weak zero count",lambda x:x.update(original_main_three_weak_zero_GLOB_DAT_writer_events=2)),
      ("fake symbolic count",lambda x:x.update(original_main_three_libc_symbolic_and_PLT_writer_events=2)),
      ("fake full closure",lambda x:x.update(all_three_ELF_ldso_libc_main_relocations_closed=True)),
      ("fake relro",lambda x:x.update(main_PT_GNU_RELRO_sealed=True)),
      ("fake IFUNC proof",lambda x:x.update(libc_and_ldso_full_relocation_and_IFUNC_proven=True)),
      ("fake main puts pass",lambda x:x.update(main_puts_exit_zero_under_FEX_proven=True)),
      ("fake games",lambda x:x.update(Android_Bionic_or_Wine_games_proven=True)),
      ("fabricated gdb exit",lambda x:x["diagnostics"].update(gdb_exit=117)),
      ("falsified hardware pair",lambda x:x["diagnostics"]["native_hardware_watchpoint_ids"].__setitem__(0,7)),
      ("fabricated fixture order",lambda x:x["diagnostics"].update(fixture_write_preceded_gnu_ldso_original_index0_rewrite=False)),
    ]
    for key in CHRONO:
        negatives.append(("corrupt strict chronology "+key,
            lambda x,k=key:x["diagnostics"]["same_process_chronological_checks"].__setitem__(k,False)))
    for key in SOURCE:
        negatives.append(("corrupt source writer "+key,
            lambda x,k=key:x["diagnostics"]["native_store_per_GNU_source_guest_RIP"].__setitem__(k,False)))
    require(len(negatives)==34,"unexpected number of adversarial source x86 proof mutations")
    for i,(title,fn) in enumerate(negatives,1):
        altered=copy.deepcopy(nine)
        fn(altered)
        try:inspect(altered,eight)
        except (FailClosed,SevenClosed,ValueError,KeyError,TypeError):
            print(f"KERNIX_G0_NINE_SOURCE_MAIN_X86_WRITER_FALSE_PROOF_{i:02d}_REJECTED {title}")
        else:raise FailClosed("false GNU ldso source writer claim accepted: "+title)
    return len(negatives)

def main(args):
    if len(args)!=4 or args[1]!="selftest":
        print("usage: gate.py selftest NINE_SOURCE_WRITERS.json EIGHT_PRIOR_ORIGINAL_WRITERS.json",file=sys.stderr)
        return 2
    nine=json.loads(Path(args[2]).read_text())
    eight=json.loads(Path(args[3]).read_text())
    result=inspect(nine,eight)
    require(negatives(nine,eight)==34,"mandatory 34 source guest writer false evidence mutations incomplete")
    print(json.dumps(result,indent=2,sort_keys=True))
    print("KERNIX_G0_ALL_EIGHT_ORIGINAL_MAIN_RELRO_GNU_X86_WRITER_EVENTS_SOURCE_PROVEN_NINE_INCLUDE_ONE_OUTSIDE_PAGE_NO_RELRO_SEAL")
    return 0
if __name__=="__main__":
    try:raise SystemExit(main(sys.argv))
    except (FailClosed,SevenClosed,KeyError,TypeError,ValueError) as ex:
        print("KERNIX_G0_NINE_ORIGINAL_GNU_SOURCE_WRITERS_CLASSIFIER_FAIL_CLOSED: "+str(ex),file=sys.stderr)
        raise SystemExit(1)
