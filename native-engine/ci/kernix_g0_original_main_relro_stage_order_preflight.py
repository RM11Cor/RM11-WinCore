#!/usr/bin/env python3
"""Cross-run original main PT_GNU_RELRO mprotect(10) *stage* proof only.

Original native x86 GNU loader: 46 libc IFUNC stores -> real successful
mprotect10 for libc and main -> original ldso's own IFUNC resolver -> zero
store -> original ldso's later mprotect. GNU loader genuinely needs the main
mprotect BEFORE its own final IRELATIVE resolver. Requiring closure of the
whole 1237-relocation triad before this stage would deadlock it.

Independent FEX Linux ARM64 source-authentic guest x86 runtime reaches
the exact main RELRO source syscall10 but does not dispatch it. Another
source-pinned FEX diagnostic proves the 9 original-main relocation store
instructions. These are NOT the same uninterrupted proof for a native page
protection / late IRELATIVE / Android game.

This is a preflight and fails closed. Never claim FEX syscall10 worked.
"""
from __future__ import annotations
import copy
import json
import sys
from pathlib import Path
from kernix_g0_nine_original_loader_x86_store_events_one_fex_replay import (
    inspect as original_nine, FailClosed as NineRejected,
)

SCHEMA = "kernix.g0.original-GNU-ldso-irelative-mprotect10-native-x86-vs-FEX-ARM64-differential.v1"
class Rejected(ValueError): pass
def need(condition,message):
    if not condition:raise Rejected(message)

def inspect(diff,nine,eight):
    r=original_nine(nine,eight)
    need(isinstance(diff,dict) and diff.get("schema")==SCHEMA,
         "wrong source x86 native-vs-FEX original loader execution chronology")
    fields={
      "native_original_libc_IFUNC_writer_events":46,
      "native_original_libc_IFUNC_event_indices":"0..45",
      "native_mprotect_success_entry_return_events_before_ldso_self_resolver":[46,47,48,49],
      "native_original_GNU_ldso_self_IFUNC_resolver_event_index":50,
      "native_original_GNU_ldso_self_IFUNC_store_event_index":51,
      "native_GNU_ldso_self_IFUNC_slot_zero_to_zero_store_source_attested":True,
      "native_loader_later_self_mprotect_events":[52,53],
      "FEX_arm64_source_libc_IFUNC_writer_traps":46,
      "FEX_arm64_original_guest_first_unsupported_mprotect_number":10,
      "FEX_arm64_original_mprotect_guest_RIP":"0x801025db9",
      "FEX_arm64_original_guest_main_RELRO_page":"0x800003000",
      "FEX_arm64_original_guest_main_RELRO_length_bytes":4096,
      "FEX_arm64_original_guest_main_RELRO_requested_protection":"PROT_READ",
      "FEX_arm64_original_guest_main_RELRO_still_rw_unsealed":True,
      "FEX_arm64_GNU_ldso_self_resolver_not_reached_within_bounded_process":True,
      "FEX_arm64_GNU_ldso_self_slot_guest_store_proven":False,
      "this_differential_proves_guest_syscall10_boundary_before_self_resolver_in_this_harness":True,
      "direct_proof_of_cause_of_unrelated_game_memory_failures":False,
      "main_PT_GNU_RELRO_sealed_under_FEX":False,
      "all_original_dynamic_relocation_writes_verified":False,
      "Android_Bionic_Wine_or_PC_games_proven":False,
    }
    for k,v in fields.items():
        need(type(diff.get(k)) is type(v) and diff.get(k)==v,
             "source native-x86 guest order / FEX not-sealed stage mismatch: "+k)
    need(r["original_main_relative0_fixtured_then_GNU_ldso_same_value_rewrite_proven"] is True,
         "original relative0 loader store shadowed by authored fixture")
    need(r["source_original_gnu_x86_writer_instruction_witness_targets"]==8,
         "original main PT_GNU_RELRO write attestation incomplete")
    need(r["original_gnu_loader_writer_events_in_one_native_FEX_process_including_outside_page"]==9,
         "original main all nine GNU ldso source writes not seen")
    need(r["original_full_ldso_libc_main_relocation_closure_proven"] is False,
         "fake total three ELF process relocation closure")
    need(r["original_main_guest_mprotect10_success"] is False,
         "FEX has not applied native source mprotect")
    return {
      "schema":"kernix.g0.original-main-source-mprotect-stage-preflight.v1",
      "source_guest_main_PT_GNU_RELRO_page":"0x800003000",
      "source_guest_main_page_size":4096,
      "source_original_guest_syscall_number":10,
      "source_original_guest_syscall_rip":"0x801025db9",
      "source_guest_requested_protection":"PROT_READ",
      "original_main_source_guest_x86_writer_addresses_authenticated":8,
      "original_main_source_guest_x86_writer_events_including_outside_page":9,
      "native_reference_libc_source_irelative_store_event_count":46,
      "native_x86_original_main_mprotect_success_brackets_pre_self_stage":[46,47,48,49],
      "native_x86_original_ldso_self_irelative_follows_main_mprotect_at_event":50,
      "native_x86_original_ldso_self_zero_store_follows_resolver_at_event":51,
      "source_FEX_guest_main_mprotect10_stops_as_unsupported":True,
      "separate_traces_do_not_prove_one_uninterrupted_FEX_post_mprotect_run":True,
      "original_source_main_mprotect_stage_relro_writers_preceding_traced":True,
      "original_ldso_own_IRELATIVE_resolver_must_not_be_prerequisite_to_main_mprotect":True,
      "original_ldso_and_libc_1237_source_relocation_targets_not_full_process_closed":True,
      "original_FEX_live_native_vma_source_ownership_must_still_be_attested":True,
      "host_16k_native_page_vs_guest_4k_relro_requires_separate_subpage_authorization":True,
      "source_stage_mprotect_planning_not_real_kernel_syscall":True,
      "actual_FEX_guest_mprotect10_success":False,
      "source_FEX_guest_original_main_PT_GNU_RELRO_sealed":False,
      "FEX_original_ldso_self_irelative_resolver_executed":False,
      "Android_Bionic_Wine_Proton_games_proven":False,
      "next":"Implement live source-owned 4KiB exact main page protection only on a supported native layout after real G0 source x86 trap; observe native kernel return and post-seal write denial, then original GNU loader self IRELATIVE guest execution. Reject plain 16KiB rounding of 4KiB guest RELRO."
    }

def adversarial(diff,nine,eight):
    cases=[
      ("wrong source schema",lambda x:x.update(schema="no")),
      ("native libc IFUNC count forged",lambda x:x.update(native_original_libc_IFUNC_writer_events=45)),
      ("native ordering wrong",lambda x:x.update(native_mprotect_success_entry_return_events_before_ldso_self_resolver=[46,47,50,49])),
      ("native ldso self resolver skipped",lambda x:x.update(native_original_GNU_ldso_self_IFUNC_resolver_event_index=48)),
      ("native self store out of order",lambda x:x.update(native_original_GNU_ldso_self_IFUNC_store_event_index=49)),
      ("no source-original native self store",lambda x:x.update(native_GNU_ldso_self_IFUNC_slot_zero_to_zero_store_source_attested=False)),
      ("missing later loader self mprotect",lambda x:x.update(native_loader_later_self_mprotect_events=[52])),
      ("wrong guest FEX libc JIT write count",lambda x:x.update(FEX_arm64_source_libc_IFUNC_writer_traps=45)),
      ("wrong main mprotect number",lambda x:x.update(FEX_arm64_original_guest_first_unsupported_mprotect_number=11)),
      ("wrong GNU ldso syscall RIP",lambda x:x.update(FEX_arm64_original_mprotect_guest_RIP="0x801025dba")),
      ("wrong source main 4k page",lambda x:x.update(FEX_arm64_original_guest_main_RELRO_page="0x800004000")),
      ("oversized 16k mprotect",lambda x:x.update(FEX_arm64_original_guest_main_RELRO_length_bytes=16384)),
      ("unsafe original RW instead of RO",lambda x:x.update(FEX_arm64_original_guest_main_RELRO_requested_protection="PROT_READ|PROT_WRITE")),
      ("silently sealed FEX page",lambda x:x.update(main_PT_GNU_RELRO_sealed_under_FEX=True)),
      ("faked FEX self resolver",lambda x:x.update(FEX_arm64_GNU_ldso_self_resolver_not_reached_within_bounded_process=False)),
      ("faked self zero writer",lambda x:x.update(FEX_arm64_GNU_ldso_self_slot_guest_store_proven=True)),
      ("faked full 1237 closure",lambda x:x.update(all_original_dynamic_relocation_writes_verified=True)),
      ("faked Android game",lambda x:x.update(Android_Bionic_Wine_or_PC_games_proven=True)),
    ]
    need(len(cases)==18,"stage-preflight missing adversarial negatives")
    for i,(title,change) in enumerate(cases,1):
        a=copy.deepcopy(diff);change(a)
        try:inspect(a,nine,eight)
        except (Rejected,NineRejected,KeyError,ValueError,TypeError):
            print(f"KERNIX_G0_SOURCE_MAIN_MPROTECT_STAGE_FALSE_POSITIVE_{i:02d}_REJECTED {title}")
        else:raise Rejected("false original source main mprotect stage accepted: "+title)
    return len(cases)

def main(args):
    if len(args)!=5 or args[1]!="selftest":
        print("usage: stage.py selftest DIFF.json NINE.json EIGHT.json",file=sys.stderr)
        return 2
    d,n,e=[json.loads(Path(p).read_text()) for p in args[2:]]
    result=inspect(d,n,e)
    need(adversarial(d,n,e)==18,"missing 18 source stage forged-claim controls")
    print(json.dumps(result,indent=2,sort_keys=True))
    print("KERNIX_G0_SOURCE_MAIN_RELRO_MPROTECT_STAGE_ORDER_AUTHENTICATED_NOT_NATIVE_FEX_SYSCALL_OR_POST_SELF_IFUNC")
    return 0

if __name__=="__main__":
    try:raise SystemExit(main(sys.argv))
    except (Rejected,NineRejected,KeyError,ValueError,TypeError) as err:
        print("KERNIX_G0_SOURCE_MAIN_RELRO_MPROTECT_STAGE_PREFLIGHT_FAIL_CLOSED: "+str(err),file=sys.stderr)
        raise SystemExit(1)
