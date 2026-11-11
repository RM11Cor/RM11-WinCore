#!/usr/bin/env python3
"""G0-L40-C first genuine 4 original ELF GLOB_DAT 80..83 native writer probes.

Tackle stage C gradually WITHOUT calling the 19 IRELATIVE (incl zero at
85) or 16 JUMP_SLOT complete. Source SHA original GNU libc + ldso,
canonical independent 147 writer ledger, original FEX host breakpoint
before GNU interpreter continuation, four actual native GDB hardware
writepoints, one real ARM64 FEX inferior. Source is not native proof.
"""
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
from kernix_g0_l40_c_original_mixed_rela_jmprel80_119_source_plan import (
    run as original_mixed,SCHEMA as MIXED_SCHEMA
)
from kernix_g0_l1_original_two_rela81_82_one_fex_process_plan import GDB_SCRIPT
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import GUEST_MAIN

SCHEMA="kernix.g0.l40c.original-gnu-80-83-first-four-authentic-globdat-one-real-fex-pid-native-plan.v1"
OUT="KERNIX-G0-L40-C-GNU-GLOB-DAT80-83-Four-Original-Writers-One-FEX-PID-SOURCE-ONLY.json"
GDB="kernix-g0-l40-c-original-globdat80-83-one-real-fex-pid.gdb"
IDX=[80,81,82,83]

def need(ok,msg):
    if not ok:raise AssertionError("KERNIX_G0_C_FOUR_GLOB_DAT_SOURCE_FAIL_CLOSED: "+msg)
def plan(triad:Path,canonical:Path,repo:Path,out:Path):
    out.mkdir(parents=True,exist_ok=True)
    source=original_mixed(triad,canonical,out/"source-verified")
    need(source["schema"]==MIXED_SCHEMA
         and source["original_source_indices"]==list(range(80,120))
         and source["new_same_guest_native_writers_proven"]==0,
         "authentic original GNU mixed40 source SHA with zero new runtime proofs")
    first=source["all_forty_source_records"][:4]
    need(len(first)==4 and [r["index"] for r in first]==IDX,
         "first contiguous four source genuine ELF relocation ordinals")
    rows=[]
    for r in first:
        need(r["original_table"]=="DT_RELA"
            and r["original_table_ordinal"]==r["index"]
            and r["relocation_type"]=="R_X86_64_GLOB_DAT"
            and r["relocation_type_number"]==6
            and r["original_source_file_qword"]=="0x0"
            and r["symbol_source_defined_candidate_if_non_TLS"] is not None,
            "authentic source GLOB_DAT requires original defined candidate and zero initial qword")
        rows.append({
            "index":r["index"],"target":r["original_guest_target"],
            "symbol":r["symbol_name"],"symbol_index":r["symbol_index"],
            "candidate":r["symbol_source_defined_candidate_if_non_TLS"],
            "relocation_type":r["relocation_type"],
        })
    need(len({r["target"] for r in rows})==4,
         "four distinct actual original GNU source target qwords")
    need([r["target"] for r in rows]==[
        "0x804202fb0","0x804202fb8","0x804202fc0","0x804202fc8"],
        "exact original source SHA GNU first four targets 80-83")
    need([r["candidate"] for r in rows]==[
        "0x804211808","0x804204378","0x80420b2b8","0x80420a4e0"],
        "exact SHA original GNU defined symbol expected target values")
    host=repo/GUEST_MAIN
    need(host.is_file() and not host.is_symlink(),"real existing FEX original interpreter host source")
    before=[i for i,line in enumerate(host.read_text().splitlines(),1)
            if line.strip()=="++RealOriginalLdsoLibcCloses;"]
    need(len(before)==1,"unique original FEX native host ELF source before guest relocations")
    script=GDB_SCRIPT
    transformations=[
        ("KERNIX_G0_L1_","KERNIX_G0_L40_C_"),
        ("TWO_HARDWARE_WRITERS_ARMED_ONE_PID","FOUR_HARDWARE_WRITERS_ARMED_ONE_PID"),
        ("TWO_REAL_ORIGINAL_RELOCATION_WRITERS_SAME_ARM64_FEX_PID",
         "FOUR_REAL_ORIGINAL_GLOB_DAT_80_83_WRITERS_SAME_ARM64_FEX_PID"),
        ("__ROW_DATA__",repr(rows)),
        ("__HOST_FILE__",GUEST_MAIN),
        ("__HOST_LINE__",str(before[0]))
    ]
    for a,z in transformations:
        need(a in script,"real four source GDB native FEX provenance template "+a)
        script=script.replace(a,z)
    need(script.count('wp_class=gdb.WP_WRITE')==1
         and script.count('ArmBeforeOriginalLoaderWrites("')==1
         and script.count('run\n')==1
         and "return len(state[\"hits\"])==len(rows)" in script,
         "single real GNU original FEX process four separate hardware native writepoints")
    import ast
    blocks=script.split("\npython\n")[1:]
    need(len(blocks)==2,"initial GDB Python hardware watchpoint and final assertion")
    for block in blocks:
        ast.parse(block.split("\nend\n")[0])
    (out/GDB).write_text(script)
    data={
        "schema":SCHEMA,
        "original_libc_sha256":LIBC_SHA,"original_ldso_sha256":LDSO_SHA,
        "source_indices":IDX,"four_genuine_original_ELF_GLOB_DAT_source_tuples":rows,
        "initial_host_after_source_libc_close_line":before[0],
        "original_fex_native_watchpoint_script_sha256":hashlib.sha256(script.encode()).hexdigest(),
        "genuine_one_FEX_arm64_native_process_required":True,
        "real_native_hardware_writer_observations_proven_by_source":0,
        "source85_IRELATIVE_zero_or_resolver_return_proven":False,
        "other_35_stage_C_original_targets_native_writers_proven_here":False,
        "stage_C_40_original_writers_one_process_proven":False,
        "all_147_original_loader_dynamic_relocations_in_one_FEX_process_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False
    }
    (out/OUT).write_text(json.dumps(data,indent=2)+"\n")
    print("KERNIX_G0_C_FIRST_4_AUTHENTIC_ORIGINAL_GNU_GLOB_DAT_ONE_FEX_NATIVE_WATCH_PLAN",
          rows,"ZERO_RUNTIME_NATIVE_PROOFS",flush=True)
    return data
if __name__=="__main__":
    need(len(sys.argv)==5,"usage original_SHA_GNU_triad canonical147 repo_root out")
    plan(*map(Path,sys.argv[1:]))
