#!/usr/bin/env python3
"""KERNIX G0-L2: plan four original ELF source-target native hardware writes in ONE FEX process.

Rebuild true original GNU libc source data (81,82,83,84) and canonical 147
INDIVIDUAL writer ledger; neither supplies any same-process certification.
Only the subsequent actual live Linux ARM64 GDB run can do so.
"""
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
from kernix_g0_l1_original_two_rela81_82_one_fex_process_plan import (
    GDB_SCRIPT as TWO_SCRIPT,plan as two_plan,
    SOURCE_OUT as TWO_OUT,SOURCE_GDB as TWO_GDB,
)
from kernix_g0_original_batch81_84_source_after141 import (
    run as four_source, SOURCE_NAME,
)
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import GUEST_MAIN

SCHEMA="kernix.g0.l2.original-gnu-rela81-84-four-writers-one-real-arm64-fex-process-plan.v1"
OUT="KERNIX-G0-L2-Original-GNU-RELA81-84-Four-Same-FEX-Process-Source-Only.json"
GDB="kernix-g0-l2-four-real-writers-one-native-process.gdb"
INDICES=list(range(81,85))

def need(ok,msg):
    if not ok:raise AssertionError("KERNIX_G0_L2_FOUR_ORIGINAL_SOURCE_FAIL_CLOSED: "+msg)
def read(path,maximum=2000000):
    need(path.is_file() and not path.is_symlink(),"regular immutable source "+str(path))
    d=path.read_bytes()
    need(0<len(d)<=maximum,"bounded immutable source "+str(path))
    return d

def plan(triad:Path,prior141:Path,source81:Path,prior147:Path,repo:Path,out:Path):
    out.mkdir(parents=True,exist_ok=True)
    # First validate the prior successful two-target plan against the immutable
    # original ELF triad, source records, canonical 147 writer receipts and
    # original FEX host driver before extending to four targets.
    base=two_plan(triad,prior141,source81,prior147,repo,out/"reverified-two")
    need(base["original_source_indices"]==[81,82]
         and base["new_same_process_native_hardware_writers_proven"]==0,
         "previous SHA GNU two-source validation is necessary but not a 4-source proof")
    four=four_source(triad,prior141,repo,out/"reverified-four")
    need(read(out/"reverified-four"/SOURCE_NAME)==read(source81/SOURCE_NAME),
         "all four actual original GNU source relocation rows re-derived SHA")
    rows=four["four_original_gnu_source_relocation_metadata"]
    need(len(rows)==4 and [r["index"] for r in rows]==INDICES,
         "all four original ELF DT_RELA records in actual source order")
    selected=[]
    for r in rows:
        need(r["relocation_type"]=="R_X86_64_GLOB_DAT"
             and r["initial_qword"]=="0x0"
             and r["relocation_type_id"]==6,
             "four genuine original 64-bit GLOB_DAT source tuples")
        sym=r["symbol"]
        need(sym is not None and sym["symbol_index"]==r["symbol_index"]
             and sym["source_definition_address_candidate_if_non_TLS"] is not None,
             "each ELF-defined resolved candidate from SHA-locked libc")
        selected.append({
          "index":r["index"],"target":r["target"],
          "symbol":sym["symbol_name"],"symbol_index":r["symbol_index"],
          "candidate":sym["source_definition_address_candidate_if_non_TLS"],
          "relocation_type":r["relocation_type"],
          "original_memory_backing":r["original_memory_backing"]})
    need([r["target"] for r in selected]==[
        "0x804202fb8","0x804202fc0","0x804202fc8","0x804202fd8"
    ],"four specific authentic SHA GNU source qword destinations")
    need([r["candidate"] for r in selected]==[
        "0x804204378","0x80420b2b8","0x80420a4e0","0x8040ad500"
    ],"four exact original GNU symbol definition destination candidates")
    host=repo/GUEST_MAIN
    need(host.is_file() and not host.is_symlink(),"unchanged genuine FEX original guest host executable source")
    lines=[i for i,line in enumerate(host.read_text().splitlines(),1)
           if line.strip()=="++RealOriginalLdsoLibcCloses;"]
    need(len(lines)==1,"unique real host-line breakpoint before original loader relocation writer")
    script=TWO_SCRIPT
    changes=[
      ("KERNIX_G0_L1_","KERNIX_G0_L2_"),
      ("TWO_HARDWARE_WRITERS_ARMED_ONE_PID","FOUR_HARDWARE_WRITERS_ARMED_ONE_PID"),
      ("TWO_REAL_ORIGINAL_RELOCATION_WRITERS_SAME_ARM64_FEX_PID","FOUR_REAL_ORIGINAL_RELOCATION_WRITERS_SAME_ARM64_FEX_PID"),
      ("__ROW_DATA__",repr(selected)),
      ("__HOST_FILE__",GUEST_MAIN),
      ("__HOST_LINE__",str(lines[0])),
    ]
    for original,new in changes:
        need(original in script,"exact previous proven source GDB template contract "+original)
        script=script.replace(original,new)
    need(script.count("class OriginalWriter(")==1
         and script.count('ArmBeforeOriginalLoaderWrites("')==1
         and script.count("wp_class=gdb.WP_WRITE")==1
         and "return len(state[\"hits\"])==len(rows)" in script
         and "all_147_same_guest_proven=False" in script,
         "one real FEX host process with four independently indexed actual GDB hardware writer traps")
    (out/GDB).write_text(script)
    source={
      "schema":SCHEMA,
      "original_source_libc_sha256":LIBC_SHA,
      "original_source_ldso_sha256":LDSO_SHA,
      "original_source_indices":INDICES,
      "source_tuples":selected,
      "previous_two_writer_same_guest_PIDs_not_reused":True,
      "canonical_individual_writer_count":147,
      "original_host_before_relocations_source_line":lines[0],
      "gdb_script_sha256":hashlib.sha256(script.encode()).hexdigest(),
      "four_live_same_FEX_process_writers_certified_by_source":False,
      "all_147_same_guest_native_execution_proven":False,
      "full_original_libc_147_process_relocation_closure_proven":False,
      "Android_Bionic_Wine_Proton_games_proven":False,
    }
    (out/OUT).write_text(json.dumps(source,indent=2)+"\n")
    print("KERNIX_G0_L2_ORIGINAL_GNU_FOUR_RELA81_84_ONE_NATIVE_FEX_PID_SOURCE_ONLY_NO_HARDWARE_PROOF",selected,flush=True)
    return source

if __name__=="__main__":
    need(len(sys.argv)==7,"usage original-GNU-triad ledger141 original-source81..84 canonical147 repo output")
    plan(*map(Path,sys.argv[1:]))
