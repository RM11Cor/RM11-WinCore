#!/usr/bin/env python3
"""Fail-closed source-authentic 4/8 x86 guest writer RIP evidence replay.

Four distinct original main PT_GNU_RELRO destination addresses, independently
captured in bounded original FEX ARM64 Linux diagnostic executions.
Source-original ld-linux x86 writer RIP is NOT a final linker closure,
same-process completion, guest main RELRO mprotect(10), or game runtime.
"""
from __future__ import annotations
import copy
import json
import sys
from pathlib import Path
from kernix_g0_original_main_two_exact_guest_writers_crossrun_gate import (
    classify as two_exact,
    Refuse as PairRefuse,
)

MAIN = "9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412"
LDSO = "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"
FEX = "02e24ca5c01ed0c864466ed573db347336f70170"
RELATIVE = "0x800003dc0"
CXA = "0x800003ff8"
class Closed(ValueError):
    pass

def must(x, explanation):
    if not x: raise Closed(explanation)

def relative1(d):
    must(isinstance(d,dict) and d.get("schema") ==
         "kernix.g0.embedded-FEX-original-main-nonfixture-native-watchpoint-linux-aarch64.v1",
         "incorrect original RELATIVE1 hardware evidence schema")
    require={
      "source_branch":"kernix-native-engine-v1",
      "original_FEX_upstream_commit":FEX,
      "original_main_sha256":MAIN,
      "main_relative_source_index":1,
      "guest_target":RELATIVE,
      "source_addend":"0x1120",
      "expected_relocated_value":"0x800001120",
      "observed_old_value":"0x1120",
      "observed_new_value":"0x800001120",
      "native_host_store_instruction":"stlr x7, [x10]",
      "original_guest_writer_RIP":"0x80100f91c",
      "FEX_source_JIT_reconstructed_guest_RIP_candidate":"0x80100f91c",
      "original_ldso_source_instruction_three_bytes":"48890e",
      "original_ldso_source_instruction_file_offset":"0xf91c",
      "precise_live_guest_RCX_from_host_x7":"0x800001120",
      "precise_live_guest_RSI_from_host_x10":RELATIVE,
    }
    for key,value in require.items():
        must(d.get(key)==value, "original RELATIVE1 source witness mismatch "+key)
    positives=(
      "native_hardware_watchpoint_observed",
      "native_host_pc_minus_four_store_verified",
      "native_host_data_register_x7_exact",
      "native_host_address_register_x10_exact",
      "native_JIT_entry_to_STLR_no_x7_x10_overwrite_verified",
      "original_ldso_source_sha256_rechecked",
      "original_ldso_guest_three_bytes_equal_exact_source_ELF",
      "original_ldso_mov_qword_rsi_rcx_source_semantics_with_native_stlr_crosschecked",
      "upstream_FEX_x64_fixed_GPR_mapping_source_verified",
      "precise_live_guest_RSI_RCX_values_proven",
      "original_ldso_one_opcode_full_guest_block_bytes_verified",
      "exact_original_guest_writer_RIP_proven",
    )
    for key in positives: must(d.get(key) is True, "missing RELATIVE1 proof "+key)
    must(d.get("FEX_RIP_map_pairs_for_native_store")==[[4,0,2],[8,0,2]],
         "original FEX relative one-instruction RIP map drift")
    for key in ("original_loader_full_relocation_closure_proven",
                "original_main_RELRO_sealed","Android_Bionic_or_phone_executed",
                "Wine_Proton_or_gameplay_proven"):
        must(d.get(key) is False,"forbidden relative 1 promotion "+key)
    # Original dynamic loader instruction is distinct from the authored
    # fixture's earlier write to RELATIVE#0.
    return {"source_symbol":"RELATIVE#1","relocation_type":"RELATIVE",
            "original_main_target":RELATIVE,
            "source_original_x86_ldso_writer_RIP":"0x80100f91c",
            "source_exact_x86_writer_opcode":"mov qword ptr [rsi],rcx",
            "native_ARM64_store":"stlr x7,[x10]",
            "source_exact_guest_RIP_proven":True,
            "authored_relative0_fixture_excluded":True}

def cxa(d):
    must(isinstance(d,dict) and d.get("schema")==
         "kernix.g0.main-globdat-cxa-finalize-exact-original-guest-rip.v1",
         "incorrect original __cxa_finalize evidence schema")
    eq={
      "original_main_sha256":MAIN,
      "original_ldso_sha256":LDSO,
      "original_ldso_guest_RIP_candidate":"0x80100fb8b",
      "original_ldso_source_file_offset":"0xfb8b",
      "original_ldso_exact_source_instruction_bytes":"4c8908",
      "original_GNU_ldso_decoded_x86_store":"mov qword ptr [rax], r9",
      "source_main_GLOB_DAT_target":CXA,
      "source_libc_function_guest_pointer":"0x8040472a0",
      "negative_mutations_rejected":9,
    }
    for key,value in eq.items():
        must(d.get(key)==value, "original __cxa_finalize source witness mismatch "+key)
    for key in (
      "same_guest_opcode_bytes_source_and_live",
      "single_3byte_x86_mov_memory_store_verified",
      "native_64bit_store_hardware_watchpoint_and_registers_verified",
      "FEX_single_instruction_jit_RIP_map_verified",
      "precise_original_guest_writer_RIP_proven",
      "prior_native_source_and_version_witness_validated",
    ):
        must(d.get(key) is True,"original __cxa_finalize missing source write proof "+key)
    for key in ("other_GLOB_DAT_or_PLT_writer_RIPs_proven",
                "full_original_loader_relocation_closure_proven",
                "main_PT_GNU_RELRO_sealed","Android_Bionic_or_Wine_games_proven"):
        must(d.get(key) is False,"forbidden cxa proof promotion "+key)
    return {"source_symbol":"__cxa_finalize","relocation_type":"GLOB_DAT",
            "original_main_target":CXA,
            "source_original_x86_ldso_writer_RIP":"0x80100fb8b",
            "source_exact_x86_writer_opcode":"mov qword ptr [rax],r9",
            "native_ARM64_store":"stlr x13,[x4]",
            "source_exact_guest_RIP_proven":True}

def classify(all_four):
    must(isinstance(all_four,list) and len(all_four)==4,"exact four writer receipts required")
    strong,puts,rel,cxa_rec = all_four
    first=two_exact(strong,puts)
    r=relative1(rel)
    c=cxa(cxa_rec)
    existing=[{"source_symbol":p["source_symbol"],
       "relocation_type":p["source_relocation_type"],
       "original_main_target":p["original_main_guest_destination"],
       "source_original_x86_ldso_writer_RIP":p["original_ldso_x86_writer_RIP"],
       "source_exact_x86_writer_opcode":p["guest_opcode"],
       "native_ARM64_store":p["native_jit_store_opcode"],
       "source_exact_guest_RIP_proven":True} for p in first["slots"]]
    entries=existing+[r,c]
    addresses=[e["original_main_target"] for e in entries]
    must(len(set(addresses))==4,"duplicate or missing source-main 4/8 original RELRO targets")
    must(set(addresses)=={RELATIVE,CXA,"0x800003fd8","0x800003fd0"},
         "out-of-scope source main PT_GNU_RELRO destination")
    must(first["original_main_eight_guest_x86_writer_instructions_proven"] is False,
         "false eight-source writer closure")
    must(first["main_PT_GNU_RELRO_sealed"] is False,
         "false source main guest protection")
    return {
      "schema":"kernix.g0.original-main-four-of-eight-x86-source-writer-replay-only.v1",
      "source_main_sha256":MAIN,
      "source_original_ldso_sha256":LDSO,
      "source_FEX_upstream_commit":FEX,
      "source_original_main_RELRO_slot_total":8,
      "exact_individually_proven_original_GNU_x86_guest_writer_targets":4,
      "sources":[42489056749,42512834255,42513285101],
      "slots":entries,
      "not_proven_original_GNU_ldso_source_writers":[
          "0x800003db8","0x800003fe0","0x800003fe8","0x800003ff0"
      ],
      "RELATIVE0_prior_authored_fixture_never_counts_as_original_ldso":True,
      "source_guest_processes_are_separate_do_not_prove_same_process_loader_closure":True,
      "all_eight_original_GNU_x86_writer_RIPs_proven":False,
      "authentic_original_main_guest_mprotect10_succeeded":False,
      "authentic_original_main_PT_GNU_RELRO_sealed":False,
      "android_bionic_wine_proton_games_proven":False,
    }

def negatives(receipts):
    mutations=[
      ("relative source wrong",2,lambda v:v.update(original_main_sha256="bad")),
      ("relative source wrong FEX",2,lambda v:v.update(original_FEX_upstream_commit="bad")),
      ("relative wrong index",2,lambda v:v.update(main_relative_source_index=0)),
      ("relative wrong destination",2,lambda v:v.update(guest_target="0x800003db8")),
      ("relative fake old",2,lambda v:v.update(observed_old_value="0x1160")),
      ("relative fake new",2,lambda v:v.update(observed_new_value="0x800001160")),
      ("relative wrong guest RIP",2,lambda v:v.update(original_guest_writer_RIP="0x80100f91d")),
      ("relative fake opcode",2,lambda v:v.update(original_ldso_source_instruction_three_bytes="48890f")),
      ("relative JIT source mapping mutated",2,lambda v:v.update(FEX_RIP_map_pairs_for_native_store=[[4,1,2],[8,0,2]])),
      ("relative fake FEX store",2,lambda v:v.update(native_host_store_instruction="ldr x7,[x10]")),
      ("relative fake full closure",2,lambda v:v.update(original_loader_full_relocation_closure_proven=True)),
      ("relative fake relro",2,lambda v:v.update(original_main_RELRO_sealed=True)),
      ("cxa wrong main sha",3,lambda v:v.update(original_main_sha256="bad")),
      ("cxa wrong ldso sha",3,lambda v:v.update(original_ldso_sha256="bad")),
      ("cxa source x86 opcode",3,lambda v:v.update(original_ldso_exact_source_instruction_bytes="4c8909")),
      ("cxa wrong target",3,lambda v:v.update(source_main_GLOB_DAT_target="0x800003fe8")),
      ("cxa wrong pointer",3,lambda v:v.update(source_libc_function_guest_pointer="0")),
      ("cxa no native hardware store",3,lambda v:v.update(native_64bit_store_hardware_watchpoint_and_registers_verified=False)),
      ("cxa wrong JIT RIP",3,lambda v:v.update(original_ldso_guest_RIP_candidate="0x80100fb8c")),
      ("cxa fake RELRO",3,lambda v:v.update(main_PT_GNU_RELRO_sealed=True)),
    ]
    for i,(label,idx,fn) in enumerate(mutations,1):
        copy_values=copy.deepcopy(receipts)
        fn(copy_values[idx])
        try: classify(copy_values)
        except (Closed,PairRefuse,TypeError,KeyError,ValueError):
            print(f"KERNIX_G0_FOUR_OF_EIGHT_FALSE_X86_SOURCE_PROOF_{i:02d}_REJECTED {label}")
        else: raise Closed("false original guest RIP proof accepted: "+label)
    return len(mutations)

def main(argv):
    if len(argv)!=6 or argv[1]!="selftest":
        print("usage: replay.py selftest STRONG_JSON PUTS_JSON RELATIVE1_JSON CXA_JSON",
              file=sys.stderr)
        return 2
    inputs=[json.loads(Path(p).read_text()) for p in argv[2:]]
    result=classify(inputs)
    must(negatives(inputs)==20,"independent 20 mutation tests incomplete")
    print(json.dumps(result,sort_keys=True,indent=2))
    print("KERNIX_G0_FOUR_OF_EIGHT_EXACT_ORIGINAL_MAIN_X86_GNU_WRITER_RIPS_REPLAYED_RELRO_AND_GAMES_OPEN")
    return 0

if __name__=="__main__":
    try: raise SystemExit(main(sys.argv))
    except (Closed,PairRefuse,ValueError,TypeError,KeyError) as e:
        print("KERNIX_G0_FOUR_OF_EIGHT_REPLAY_FAIL_CLOSED: "+str(e),file=sys.stderr)
        raise SystemExit(1)
