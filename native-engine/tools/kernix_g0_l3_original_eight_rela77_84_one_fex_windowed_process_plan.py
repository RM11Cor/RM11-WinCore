#!/usr/bin/env python3
"""G0-L3 original GNU 77..84: plan ONE FEX host process with TWO sequential
windows of 4 AArch64 hardware GDB watchpoints, not eight simultaneous slots.
Source-only: counts zero new runtime proofs. Same PID + all 8 native events
must be independently certified before L3 can pass.
"""
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
from kernix_g0_l2_original_four_rela81_84_one_fex_process_plan import (
    plan as l2_plan,GDB as GDB_L2,OUT as OUT_L2,
)
from kernix_g0_l1_original_two_rela81_82_one_fex_process_plan import GDB_SCRIPT
from kernix_g0_original_globdat_batch71_80_source_after131 import (
    run as first_source,SOURCE_NAME as FIRST_SOURCE_NAME,
)
from kernix_g0_original_batch81_84_source_after141 import (
    run as last_source,SOURCE_NAME as LAST_SOURCE_NAME,
)
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import GUEST_MAIN

SCHEMA="kernix.g0.l3.original-gnu-rela77-84-eight-same-arm64-fex-pid-two-four-watchpoint-windows-source.v1"
OUT="KERNIX-G0-L3-Original-GNU-RELA77-84-Eight-Two-Window-Same-FEX-PID-SOURCE-ONLY.json"
GDB="kernix-g0-l3-eight-source-two-watchpoint-windows-one-fex-process.gdb"
INDICES=list(range(77,85))

def need(ok,msg):
    if not ok:raise AssertionError("KERNIX_G0_L3_EIGHT_GNU_SOURCE_FAIL_CLOSED: "+msg)
def read(p:Path,lim=2500000):
    need(p.is_file() and not p.is_symlink(),"immutable file "+str(p))
    b=p.read_bytes()
    need(0<len(b)<=lim,"bounded original source "+str(p))
    return b

def plan(triad:Path,prior131:Path,source71:Path,prior141:Path,source81:Path,
         prior147:Path,repo:Path,out:Path):
    out.mkdir(parents=True,exist_ok=True)
    existing=l2_plan(triad,prior141,source81,prior147,repo,out/"verified-l2")
    need(existing["original_source_indices"]==[81,82,83,84]
         and existing["four_live_same_FEX_process_writers_certified_by_source"] is False,
         "authenticated original GNU 81..84 static input is not runtime proof")
    old=first_source(triad,prior131,repo,out/"verified-source71")
    need(old["original_source_indices"]==list(range(71,81))
         and read(source71/FIRST_SOURCE_NAME)==read(out/"verified-source71"/FIRST_SOURCE_NAME),
         "original GNU 77..80 source records SHA-identical to separately audited batch E")
    later=last_source(triad,prior141,repo,out/"verified-source81")
    need(later["original_source_indices"]==list(range(81,85))
         and read(source81/LAST_SOURCE_NAME)==read(out/"verified-source81"/LAST_SOURCE_NAME),
         "original GNU 81..84 source records SHA-identical to previous four-guest proof")
    selected=[]
    for row in old["ten_original_gnu_source_relocation_metadata"][6:]:
        need(row["index"] in range(77,81),"exact original indices77..80")
        selected.append(row)
    selected+=later["four_original_gnu_source_relocation_metadata"]
    need([r["index"] for r in selected]==INDICES,"all 8 original source indices in GNU relocation order")
    outrows=[]
    for r in selected:
        sym=r["symbol"]
        need(r["relocation_type"]=="R_X86_64_GLOB_DAT"
             and r["relocation_type_id"]==6
             and r["initial_qword"]=="0x0" and sym is not None
             and sym["symbol_index"]==r["symbol_index"]
             and sym["source_definition_address_candidate_if_non_TLS"],
             "source 77..84 four-plus-four non-TLS GNU original 64-bit dynamic GLOB_DAT")
        outrows.append({
           "index":r["index"],"target":r["target"],
           "relocation_type":r["relocation_type"],
           "symbol":sym["symbol_name"],"symbol_index":r["symbol_index"],
           "candidate":sym["source_definition_address_candidate_if_non_TLS"],
           "original_memory_backing":r["original_memory_backing"]})
    need(len({r["target"] for r in outrows})==8,"all eight actual GNU source target addresses distinct")
    need([x["target"] for x in outrows]==[
        "0x804202f98","0x804202fa0","0x804202fa8","0x804202fb0",
        "0x804202fb8","0x804202fc0","0x804202fc8","0x804202fd8"
    ],"eight untouched original GNU guest source qword destinations exact")
    need([x["candidate"] for x in outrows]==[
        "0x804201700","0x80420ad58","0x8042032e8","0x804211808",
        "0x804204378","0x80420b2b8","0x80420a4e0","0x8040ad500"
    ],"eight source SHA-derived actual GNU ELF symbol definitions exact")
    host=repo/GUEST_MAIN
    need(host.is_file() and not host.is_symlink(),"real original FEX GNU host driver source")
    lines=[i for i,line in enumerate(host.read_text().splitlines(),1)
           if line.strip()=="++RealOriginalLdsoLibcCloses;"]
    need(len(lines)==1,"unique actual FEX host source before original interpreter writes")
    script=GDB_SCRIPT
    transformations=[
      ("KERNIX_G0_L1_","KERNIX_G0_L3_"),
      ('return len(state["hits"])==len(rows)','return len(state["hits"]) in (4,8)'),
      ('for row in rows:\n                OriginalWriter(row)',
       'for row in rows[:4]:\n                OriginalWriter(row)'),
      ('jmark("TWO_HARDWARE_WRITERS_ARMED_ONE_PID",pid=pid,indices=[r["index"] for r in rows])',
       'jmark("FIRST_FOUR_HARDWARE_WRITERS_ARMED_ONE_PID",pid=pid,indices=[r["index"] for r in rows[:4]])'),
      ("TWO_REAL_ORIGINAL_RELOCATION_WRITERS_SAME_ARM64_FEX_PID",
       "EIGHT_REAL_ORIGINAL_RELOCATION_WRITERS_SAME_ARM64_FEX_PID"),
      ("__ROW_DATA__",repr(outrows)),
      ("__HOST_FILE__",GUEST_MAIN),
      ("__HOST_LINE__",str(lines[0])),
    ]
    for a,b in transformations:
        need(a in script,"exact previous proven FEX GDB template contract "+a[:75])
        script=script.replace(a,b)
    original="run\npython\n"
    need(script.count(original)==1,"unique GDB original FEX guest first-window stopping point")
    step=r'''run
python
assert state["failure"] is None, "first four original GNU native writes failed: "+str(state["failure"])
assert state["armed"] and state["startup_pid"] is not None and state["startup_pid"]>0
assert [v["index"] for v in state["hits"]]==[77,78,79,80], "first four distinct real GNU source stores not observed"
assert len({v["pid"] for v in state["hits"]})==1
for bp in tuple(gdb.breakpoints() or ()):
    if isinstance(bp,OriginalWriter): bp.delete()
for row in rows[4:]:
    OriginalWriter(row)
jmark("SECOND_FOUR_HARDWARE_WRITERS_ARMED_SAME_PID",pid=state["startup_pid"],indices=[r["index"] for r in rows[4:]],already_observed=[r["index"] for r in state["hits"]])
end
continue
python
'''
    script=script.replace(original,step)
    need(script.count("class OriginalWriter(")==1
         and script.count("wp_class=gdb.WP_WRITE")==1
         and script.count('ArmBeforeOriginalLoaderWrites("')==1
         and script.count("SECOND_FOUR_HARDWARE_WRITERS_ARMED_SAME_PID")==1
         and script.count("EIGHT_REAL_ORIGINAL_RELOCATION_WRITERS_SAME_ARM64_FEX_PID")==1
         and script.count("run\n")==1
         and script.count("\ncontinue\npython\n")==1,
         "one FEX guest process, 4 real GDB native watchpoint slots rearmed while stopped, second window")
    (out/GDB).write_text(script)
    doc={"schema":SCHEMA,"original_source_libc_sha256":LIBC_SHA,
         "original_source_ldso_sha256":LDSO_SHA,
         "original_source_indices":INDICES,"source_tuples":outrows,
         "first_watchpoint_window_indices":[77,78,79,80],
         "second_watchpoint_window_indices":[81,82,83,84],
         "maximum_simultaneously_armed_hardware_watchpoints":4,
         "single_uninterrupted_real_FEX_inferior_required":True,
         "source_plan_gdb_script_sha256":hashlib.sha256(script.encode()).hexdigest(),
         "new_same_FEX_process_original_writers_proven":0,
         "all_147_same_guest_native_execution_proven":False,
         "full_original_libc_147_process_relocation_closure_proven":False,
         "Android_Bionic_Wine_Proton_games_proven":False}
    (out/OUT).write_text(json.dumps(doc,indent=2)+"\n")
    print("KERNIX_G0_L3_EIGHT_ORIGINAL_GNU_WRITERS_ONE_ARM64_FEX_PID_TWO_FOUR_HARDWARE_WATCH_WINDOWS_SOURCE_ONLY",len(outrows))
    return doc

if __name__=="__main__":
    need(len(sys.argv)==9,
         "usage GNU-triad prior131 original-source71 prior141 original-source81 canonical147 repo output")
    plan(*map(Path,sys.argv[1:]))
