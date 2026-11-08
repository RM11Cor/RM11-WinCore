#!/usr/bin/env python3
"""Source-pinned eight-of-eight ORIGINAL MAIN RELRO hardware store observation matrix.

Combines four *independent bounded* source-original FEX AArch64 GDB processes
and exact original ELF target addresses. This is not original GNU ld-linux
x86 guest instruction provenance, mprotect success, or gaming readiness.
An authored RELATIVE#0 early fixture write is explicitly excluded from
claims about the unmodified original ld-linux relocation algorithm.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

from kernix_g0_original_main_two_got_aarch64_hardware_classifier import classify as got_classify
from kernix_g0_original_main_relative_weakzero_hw_classifier import classify as rel_weak_classify
from kernix_g0_original_main_pending_two_target_hw_classifier import inspect as rel0_gmon_classify
from kernix_g0_original_main_pending_cxa_register_hw_classifier import inspect as cxa_register_classify

SHA = "9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412"
FEX = "02e24ca5c01ed0c864466ed573db347336f70170"
EXACT = {
    "relative0": "0x800003db8",
    "relative1": "0x800003dc0",
    "puts": "0x800003fd0",
    "__libc_start_main": "0x800003fd8",
    "_ITM_deregisterTMCloneTable": "0x800003fe0",
    "__gmon_start__": "0x800003fe8",
    "_ITM_registerTMCloneTable": "0x800003ff0",
    "__cxa_finalize": "0x800003ff8",
}
ZERO_TO_ZERO = [
    "_ITM_deregisterTMCloneTable", "__gmon_start__", "_ITM_registerTMCloneTable"
]
class GateError(ValueError):
    pass

def must(ok, why):
    if not ok:
        raise GateError(why)

def examine(raws):
    must(len(raws) == 4, "exact four hardware watch pair receipts required")
    dual, relweak, rel0gmon, cxareg = raws
    got = got_classify(dual)
    weak = rel_weak_classify(relweak)
    pair = rel0_gmon_classify(rel0gmon)
    last = cxa_register_classify(cxareg)
    must(got["original_main_ELF_SHA256"] == SHA and got["source_FEX_commit"] == FEX,
         "source original main or FEX source drift in first dual pair")
    must(weak["original_main_ELF_sha256"] == SHA and weak["original_FEX_upstream_commit"] == FEX,
         "source original main or FEX source drift in relative/weak pair")
    must(pair["source_main_sha256"] == SHA and pair["original_fex_commit"] == FEX,
         "source original main or FEX source drift in third pair")
    must(last["source_main_sha256"] == SHA and last["original_fex_commit"] == FEX,
         "source original main or FEX source drift in fourth pair")
    got_count = got["native_JIT_store_candidate_final_expected_value_events_per_symbol"]
    weak_count = {
        "relative1": weak["native_jit_source_relative1_real_store_positive_count"],
        "_ITM_deregisterTMCloneTable": weak["native_jit_source_weak_zero_zero_to_zero_store_candidate_count"],
    }
    third_count = pair["native_STLR_candidate_count"]
    last_count = last["native_STLR_candidate_count"]
    counts = {**got_count, **weak_count, **third_count, **last_count}
    must(set(counts) == set(EXACT) and all(isinstance(v,int) and v >= 1 for v in counts.values()),
         "not eight distinct source ELF RELRO hardware store destination candidates")
    must(got["source_original_GOT_targets"] == {k:EXACT[k] for k in ("puts","__libc_start_main")},
         "GOT source provenance corrupted")
    must(pair["native_STLR_candidates_observed_for_both"] is True
         and last["native_STLR_candidates_observed_for_both"] is True
         and got["both_source_GOT_expected_final_values_hardware_trap_jit_store_observed"] is True,
         "hardware write pair incomplete")
    must(pair["relative0_fixture_write_not_original_ldso_writer_attributed"] is True
         and last["__cxa_finalize_source_guest_writer_RIP_still_unproven"] is True,
         "fake GNU x86 ldso writer attribution in matrix")
    must(weak["main_PT_GNU_RELRO_sealed"] is False
         and got["original_main_PT_GNU_RELRO_sealed"] is False
         and pair["main_RELRO_sealed"] is False
         and last["main_RELRO_sealed"] is False,
         "unproved main GNU RELRO seal promoted")
    must(got["Android_Bionic_Wine_or_real_games_proven"] is False
         and weak["Android_Bionic_Wine_or_real_games_proven"] is False
         and pair["android_wine_or_games_proven"] is False
         and last["android_wine_or_games_proven"] is False,
         "unproved real PC game promoted")
    return {
      "schema":"kernix.g0.original-main-8-relro-source-address-native-arm64-store-observation-matrix.v1",
      "source_original_main_sha256":SHA,
      "source_FEX_upstream_commit":FEX,
      "source_main_relro_unique_targets":8,
      "native_ARM64_hardware_stlr_observed_address_count":len(counts),
      "per_source_slot_native_jit_store_observation_counts":counts,
      "source_guest_slot_targets":EXACT,
      "weak_zero_to_zero_slots_requires_actual_native_stlr":ZERO_TO_ZERO,
      "independent_bounded_FEX_GDB_hardware_capture_pairs":4,
      "source_original_x86_GNU_ldso_writer_RIP_proven_for_all_eight":False,
      "source_relative0_harness_authored_fixture_write_excluded_from_loader_attribution":True,
      "original_GNU_main_dynamic_relocations_closed":False,
      "original_GNU_main_mprotect10_succeeded":False,
      "main_PT_GNU_RELRO_sealed":False,
      "Android_Bionic_Wine_Proton_or_PC_gameplay_proven":False,
      "next_gate":"Per-target original x86 ld-linux guest RIP mapping and authentic post-relocation mprotect(10) read-only write-denial on source-owned guest RELRO page.",
    }

def main(argv):
    if len(argv) != 5:
        print("usage: matrix.py GOT_HW.json RELATIVE_WEAK_HW.json REL0_GMON_HW.json CXA_REGISTER_HW.json", file=sys.stderr)
        return 2
    raws = [json.loads(Path(x).read_text()) for x in argv[1:]]
    matrix = examine(raws)
    print(json.dumps(matrix,indent=2,sort_keys=True))
    print("KERNIX_G0_EIGHT_SOURCE_ADDRESSES_NATIVE_ARM64_STLR_OBSERVED_NOT_ORIGINAL_GNU_LDSO_RELOCATION_CLOSURE")
    return 0

if __name__=="__main__":
    try:
        raise SystemExit(main(sys.argv))
    except (GateError,ValueError,KeyError,TypeError) as exc:
        print("KERNIX_G0_EIGHT_MAIN_NATIVE_STLR_MATRIX_FAIL_CLOSED: "+str(exc), file=sys.stderr)
        raise SystemExit(1)
