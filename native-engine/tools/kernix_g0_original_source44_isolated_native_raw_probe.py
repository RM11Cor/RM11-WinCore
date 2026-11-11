#!/usr/bin/env python3
"""Isolated source 44 native retry with no ten-sibling retests.

Original GNU libc DT_RELA[44] R_X86_64_GLOB_DAT _rtld_global_ro
source guest target 0x804202eb0. Source SHA and FEX are unchanged.
Raw GDB only: do not count this as a certified additional writer.
"""
from pathlib import Path
import hashlib,json,sys
from kernix_g0_original_globdat_batch41_50_source_after103 import (
    INDICES, SOURCE_NAME, run as reverify_source,
)
from kernix_g0_original_batch41_50_native_parallel_raw import run_one,regular,RAW_SCHEMA

def need(ok,msg):
    if not ok:raise AssertionError("KERNIX_G0_GNU_SOURCE44_RETRY_FAIL_CLOSED: "+msg)

def main(triad:Path,previous103:Path,source:Path,repo:Path,executable:Path,output:Path):
    input_data=json.loads(regular(source/SOURCE_NAME,500000))
    reverified_dir=output/"reverified-source"
    ours=reverify_source(triad,previous103,repo,reverified_dir)
    need(input_data==ours,"authentic SHA-pinned GNU source archive compared with independently decoded ELF")
    need(input_data["original_source_indices"]==list(range(41,51)),"ten original source indices")
    row=input_data["ten_original_gnu_source_relocation_metadata"][44-41]
    need(row["index"]==44
         and row["symbol"]["symbol_name"]=="_rtld_global_ro"
         and row["symbol_index"]==7
         and row["target"]=="0x804202eb0"
         and row["relocation_type"]=="R_X86_64_GLOB_DAT"
         and row["initial_qword"]=="0x0","unaltered original GNU DT_RELA44")
    gdb=source/"original-gnu-dtrela44-source-only.gdb"
    need(regular(gdb,500000)==regular(reverified_dir/gdb.name,500000),
         "exact original GDB source watch plan")
    need(executable.is_file() and not executable.is_symlink(),"original Linux ARM64 built FEX host guest")
    target=output/"isolated44"
    target.mkdir(parents=True,exist_ok=True)
    result=run_one(44,row,gdb,triad,executable,target)
    record={
       "schema":"kernix.g0.original-gnu-source44-isolated-two-native-hardware-modes-raw-no-proof.v1",
       "original_source_libc_sha256":input_data["original_source_libc_sha256"],
       "original_source_ldso_sha256":input_data["original_source_ldso_sha256"],
       "original_source_index":44,
       "original_guest_target":row["target"],
       "original_dynamic_symbol_name":row["symbol"]["symbol_name"],
       "previous_certified_native_writer_target_count_before_isolated_retry":112,
       "watch_awatch_original_native_raw_result":result,
       "independently_certified_new_native_writer_targets":0,
       "original_source44_hardware_proof_requires_independent_review":True,
       "no_other_source_target_retested":True,
       "Android_Bionic_Wine_Proton_games_proven":False
    }
    (output/"source44-isolated-raw-summary.json").write_text(json.dumps(record,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_DTRELA44_ISOLATED_RAW_COMPLETE", json.dumps(result,sort_keys=True))
    return record

if __name__=="__main__":
    need(len(sys.argv)==7,"usage triad prior103 original-source-batch repo native-FEX-executable output-dir")
    main(*map(Path,sys.argv[1:]))
