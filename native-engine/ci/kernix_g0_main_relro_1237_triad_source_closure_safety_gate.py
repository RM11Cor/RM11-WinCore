#!/usr/bin/env python3
"""Original GNU main RELRO cannot seal merely because its nine writes are observed.

Source authentic FEX hardware proof: all nine source-main GNU writer events,
8 on page + 1 outside, including later loader re-write after authored fixture.
Separately source-authentic read-only census: main 9, original ldso 14, libc
1214 = 1237 relocation targets. Many are only source/live-memory matches;
IFUNC, original ldso IRELATIVE self-resolver, individual guest writer RIPs,
and the original main x86 mprotect(10) success remain UNPROVEN.

This is an intentionally negative readiness gate, not permission to issue
mprotect, force pages read-only, or claim Android / Wine / actual game launch.
"""
from __future__ import annotations
import copy
import json
import sys
from pathlib import Path
from kernix_g0_nine_original_loader_x86_store_events_one_fex_replay import (
    inspect as nine_inspect, FailClosed as NineFailClosed,
)
MAIN="9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412"
LDSO="cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"
LIBC="7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906"
SCHEMA="kernix.g0.original-1237-triad-source-relocations-one-nine-writer-process-closure-gaps.v1"
class NotReady(ValueError):
    pass
def require(cond,msg):
    if not cond:raise NotReady(msg)

def classify(triad,nine,eight):
    nine_proof=nine_inspect(nine,eight)
    require(nine_proof["source_original_gnu_x86_writer_instruction_witness_targets"]==8,
            "original source main writer receipts incomplete")
    require(isinstance(triad,dict) and triad.get("schema")==SCHEMA,
            "wrong original original-triad source relocation ledger")
    require(triad.get("source_sha256")==dict(main=MAIN,ldso=LDSO,libc=LIBC),
            "mismatching source original ELF exact immutable sha256")
    flags={
      "one_FEX_process_nine_main_original_ldso_writer_events_proven":True,
      "all_original_triad_source_relocation_targets_count":1237,
      "original_main_source_relocations":9,
      "original_ldso_source_relocations":14,
      "original_libc_source_relocations":1214,
      "ldso_11_RELR_all_expected_at_real_main_RELRO":True,
      "ldso_2_GLOB_DAT_nonzero_at_real_main_RELRO":True,
      "ldso_one_IRELATIVE_source_index2_target":"0x801036360",
      "ldso_one_IRELATIVE_still_zero_at_real_main_RELRO":True,
      "ldso_IRELATIVE_original_resolver_guest_execution_proven":False,
      "libc_1067_RELR_expected_before_libc_RELRO":True,
      "libc_147_RELA_JMPREL_live_nonzero_before_libc_RELRO":146,
      "libc_IRELATIVE_45_nonzero_one_zero_before_libc_RELRO":True,
      "native_x86_separate_reference_libc_IRELATIVE_index85_returns_zero":True,
      "libc_all_IFUNC_resolvers_and_native_writer_proven":False,
      "original_ldso_guest_source_relr_and_rela_writer_rips_proven":False,
      "all_original_dynamic_relocations_closed_proven":False,
      "original_main_PT_GNU_RELRO_sealed":False,
      "original_main_puts_and_exit_zero_FEX_proven":False,
      "Android_Bionic_or_Wine_game_runtime_proven":False,
    }
    for key,expected in flags.items():
        require(type(triad.get(key)) is type(expected) and triad.get(key)==expected,
                "invalid original triad source relocation closure boundary: "+key)
    require(triad.get("read_only_source_reconciled_targets")=={
        "main":9,"ldso_relr":11,"ldso_rela":3,
        "libc_relr":1067,"libc_rela_jmprel":147,
    },"bad triad source record group census")
    require(9+11+3+1067+147==1237 and 9+14+1214==1237,
            "triad source reconciliation arithmetic invalid")
    require(triad.get("next_narrow_gate") is not None and
            "IRELATIVE" in triad["next_narrow_gate"],
            "the unresolved GNU ldso IFUNC self-resolver must remain visible")
    return {
      "schema":"kernix.g0.original-1237-triad-source-ledger-nine-main-writers-readiness-held.v1",
      "main_sha256":MAIN,"ldso_sha256":LDSO,"libc_sha256":LIBC,
      "source_relocation_targets_readonly_reconciled":1237,
      "main_exact_original_guest_x86_writer_events":9,
      "original_main_RELRO_source_guest_writer_events":8,
      "source_main_outside_RELRO_relative2_writer_events":1,
      "ldso_source_relocation_targets":14,
      "libc_source_relocation_targets":1214,
      "only_nine_main_writer_events_directly_authenticated_in_this_single_process":True,
      "other_source_targets_without_per_slot_writer_provenance_in_this_trace":1228,
      "not_a_claim_that_all_other_1228_stores_are_unexecuted":True,
      "original_ldso_irelative_zero_result_guest_resolver_execution_proven":False,
      "all_libc_IFUNC_original_guest_writer_proven":False,
      "all_original_triad_relocations_completed_proven":False,
      "source_original_main_guest_mprotect10_success_proven":False,
      "source_original_main_PT_GNU_RELRO_sealed":False,
      "source_host16k_guest4k_permission_semantics_on_phone_proven":False,
      "Android_Wine_Proton_games_proven":False,
      "next_gate":"Bounded, source-authentic original ldso IRELATIVE resolver execution and guest writer, libc IFUNC zero-source proof, and real guest mprotect(10) after relevant relocation closure with write-denial/16K safety checks."
    }

def adversarial(triad,nine,eight):
    cases=[
      ("main digest forged",lambda x:x["source_sha256"].update(main="bad")),
      ("ldso digest forged",lambda x:x["source_sha256"].update(ldso="bad")),
      ("libc digest forged",lambda x:x["source_sha256"].update(libc="bad")),
      ("faked 1237 count",lambda x:x.update(all_original_triad_source_relocation_targets_count=1238)),
      ("faked original main count",lambda x:x.update(original_main_source_relocations=8)),
      ("faked ldso count",lambda x:x.update(original_ldso_source_relocations=15)),
      ("faked libc count",lambda x:x.update(original_libc_source_relocations=1215)),
      ("fake libcrelr source",lambda x:x["read_only_source_reconciled_targets"].update(libc_relr=1066)),
      ("fake nine original main",lambda x:x.update(one_FEX_process_nine_main_original_ldso_writer_events_proven=False)),
      ("fake ldso rela",lambda x:x.update(ldso_11_RELR_all_expected_at_real_main_RELRO=False)),
      ("fake ldso irelative return",lambda x:x.update(ldso_IRELATIVE_original_resolver_guest_execution_proven=True)),
      ("fake libc ifunc",lambda x:x.update(libc_all_IFUNC_resolvers_and_native_writer_proven=True)),
      ("fake ldso writer closure",lambda x:x.update(original_ldso_guest_source_relr_and_rela_writer_rips_proven=True)),
      ("fake all triad closure",lambda x:x.update(all_original_dynamic_relocations_closed_proven=True)),
      ("fake original RELRO seal",lambda x:x.update(original_main_PT_GNU_RELRO_sealed=True)),
      ("fake original main execution",lambda x:x.update(original_main_puts_and_exit_zero_FEX_proven=True)),
      ("fake Android game execution",lambda x:x.update(Android_Bionic_or_Wine_game_runtime_proven=True)),
      ("fake ldso zero slot",lambda x:x.update(ldso_one_IRELATIVE_source_index2_target="0x801036368")),
      ("fake libc IFUNC returns",lambda x:x.update(libc_147_RELA_JMPREL_live_nonzero_before_libc_RELRO=147)),
      ("remove next IFUNC gate",lambda x:x.update(next_narrow_gate="All ready")),
    ]
    require(len(cases)==20,"not all twenty source triad closure negative controls")
    for i,(title,mutation) in enumerate(cases,1):
        altered=copy.deepcopy(triad)
        mutation(altered)
        try:classify(altered,nine,eight)
        except (NotReady,NineFailClosed,KeyError,ValueError,TypeError):
            print(f"KERNIX_G0_TRIAD_RELRO_FALSE_READY_{i:02d}_DENIED {title}")
        else:
            raise NotReady("corrupt unproven linker closure accepted: "+title)
    return len(cases)

def main(args):
    if len(args)!=5 or args[1]!="selftest":
        print("usage: triad.py selftest TRIAD.json NINE.json EIGHT.json",file=sys.stderr)
        return 2
    triad,nine,eight=[json.loads(Path(f).read_text()) for f in args[2:]]
    result=classify(triad,nine,eight)
    require(adversarial(triad,nine,eight)==20,"triad false ready rejections missing")
    print(json.dumps(result,indent=2,sort_keys=True))
    print("KERNIX_G0_NINE_REAL_MAIN_X86_WRITERS_1237_SOURCE_TRIAD_TARGETS_BUT_ORIGINAL_MPROTECT_AND_FULL_CLOSURE_NOT_READY")
    return 0
if __name__=="__main__":
    try:raise SystemExit(main(sys.argv))
    except (NotReady,NineFailClosed,KeyError,ValueError,TypeError) as err:
        print("KERNIX_G0_ORIGINAL_GNU_TRIAD_RELRO_NOT_READY_FAIL_CLOSED: "+str(err),file=sys.stderr)
        raise SystemExit(1)
