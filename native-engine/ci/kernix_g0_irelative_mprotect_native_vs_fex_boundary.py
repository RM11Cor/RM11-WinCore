#!/usr/bin/env python3
"""Compare real GNU ldso source ELF x86 syscall chronology to bounded FEX ARM64 G0.

This is a read-only diagnostic regression gate. It MUST NOT grant mprotect(10)
success in production, modify a game prefix or claim all PT_GNU_RELRO relocation
closure. The original x86 native reference (source SHA-pinned) executes mprotect
and ldso's final self IFUNC; a separate FEX diagnostic stops at its unsupported
guest syscall 10 after glibc IFUNC stores.
"""
from __future__ import annotations
import copy
import json
import re
import sys
from pathlib import Path

NATIVE_SCHEMA = "kernix.g0.native-x86-source-original-gnu-ldso-self-irelative-vs-libc46-execution-order.v1"
FEX_SCHEMA = "kernix.g0.original-ldso-irelative-source-emitted-FEX-ARM64-code-execution-witness.v1"
ORIGINAL_LDSO_SHA = "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"
ORIGINAL_LIBC_SHA = "7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906"
FEX_COMMIT = "02e24ca5c01ed0c864466ed573db347336f70170"

class GateError(ValueError):
    pass

def demand(ok: bool, why: str) -> None:
    if not ok:
        raise GateError(why)

def classify(native:dict, fex:dict, fexlog:str) -> dict:
    demand(isinstance(native,dict) and native.get("schema")==NATIVE_SCHEMA, "native chronological source reference missing")
    demand(isinstance(fex,dict) and fex.get("schema")==FEX_SCHEMA, "source FEX ARM64 executable trace missing")
    demand(native.get("original_ldso_sha256")==ORIGINAL_LDSO_SHA, "native GNU source loader SHA drift")
    demand(native.get("original_libc_sha256")==ORIGINAL_LIBC_SHA, "native original libc SHA drift")
    demand(native.get("original_self_irelative_source_target")=="0x36360"
           and native.get("original_self_resolver_source_rip")=="0x1a8e0"
           and native.get("original_x86_self_and_libc_irelative_writer_source_rip")=="0xfd60",
           "original ldso source resolver, writer or target changed")
    demand(native.get("original_libc_original_dt_rela_records")==86
           and native.get("original_libc_original_dt_jmprel_records")==61
           and native.get("original_libc_source_irelative_count")==46,
           "all source 147 dynamic libc rows not preserved")
    demand(native.get("original_main_native_exited") is True
           and native.get("original_main_native_exit_code")==0 and native.get("GDB_error") is None,
           "original native x86 execution not clean")
    event=native.get("event_order")
    demand(isinstance(event,list) and len(event)==54, "native x86 event chronology count drift")
    demand([v["event_index"] for v in event]==list(range(54)), "native event order malformed")
    glibc=native.get("source_libc_irelative_store_events")
    demand(isinstance(glibc,list) and len(glibc)==46, "original native source libc IFUNC stores incomplete")
    demand([v["event_index"] for v in glibc]==list(range(46)), "source libc IFUNC writes not first")
    demand(len({v["source_libc_irelative_record_index"] for v in glibc})==46,
           "source original libc IFUNC record duplicated")
    demand(native.get("native_original_last_libc_irelative_event_index")==45,
           "native original libc IFUNC last store not indexed")
    native_mprotect=native.get("native_x86_mprotect10_entry_exit_events")
    demand(isinstance(native_mprotect,list) and len(native_mprotect)==6, "native x86 source mprotect event sequence changed")
    demand([v["event_index"] for v in native_mprotect]==[46,47,48,49,52,53],
           "native mprotect did not bracket self IFUNC resolver/write")
    for pair in range(3):
        first=native_mprotect[pair*2]
        last=native_mprotect[pair*2+1]
        demand(first["original_x86_syscall_number"]==last["original_x86_syscall_number"]==10,
               "not actual Linux x86 syscall mprotect number 10")
        demand(first["native_x86_rax_at_stop"]=="0xffffffffffffffda"
               and last["native_x86_rax_at_stop"]=="0x0",
               "native host mprotect did not enter kernel then succeed with Linux return zero")
        demand(first["native_mprotect_page_address"]==last["native_mprotect_page_address"]
               and first["native_mprotect_size"]==last["native_mprotect_size"]
               and first["native_mprotect_prot"]==last["native_mprotect_prot"]=="0x1",
               "native mprotect entry/exit arguments changed or rights not PROT_READ")
        addr=int(first["native_mprotect_page_address"],16)
        length=int(first["native_mprotect_size"],16)
        demand(addr%4096==0 and length%4096==0 and length>=4096 and length<=0x10000,
               "native source mprotect outside bounded 4K-aligned RELRO size")
    demand([v["inside_original_libc_guest_mapped_region"] for v in native_mprotect]==
           [True,True,False,False,False,False],
           "native first real mprotect does not protect original libc range")
    resolver=native.get("source_loader_self_resolver_entry_events")
    store=native.get("source_loader_self_store_events")
    demand(isinstance(resolver,list) and len(resolver)==1 and resolver[0]["event_index"]==50,
           "actual original GNU ldso native IFUNC resolver entry missing")
    demand(isinstance(store,list) and len(store)==1 and store[0]["event_index"]==51,
           "actual original GNU ldso native zero-store missing")
    demand(store[0]["native_value_register_RAX"]=="0x0"
           and store[0]["destination_qword_before_store"]=="0x0"
           and store[0]["original_x86_instruction_bytes"]=="498906",
           "not original GNU self IRELATIVE source writer zero-to-zero")
    demand(native.get("original_loader_self_resolver_first_event_index")==50
           and native.get("original_loader_self_zero_store_first_event_index")==51
           and native.get("mprotect10_between_last_libc_stlr_and_original_ldso_resolver") is True,
           "native Linux syscall10 not located before original GNU self resolver")
    demand(native.get("native_original_self_resolver_entry_after_libc_count") is True
           and native.get("native_x86_original_ldso_self_store_before_first_libc_irelative_store") is False,
           "native source ldso/libc IFUNC order contradicted")
    for name in ("FEX_ARM64_original_self_irelative_executed_proven",
                 "FEX_ARM64_original_self_irelative_store_proven",
                 "main_PT_GNU_RELRO_sealed_under_FEX","Android_Wine_or_PC_games_proven"):
        demand(native.get(name) is False, "native x86 proof falsely promoted to FEX or Android: "+name)
    demand(fex.get("source_fex_commit")==FEX_COMMIT
           and fex.get("source_original_ldso_sha256")==ORIGINAL_LDSO_SHA,
           "FEX diagnostic source provenance drift")
    demand(fex.get("source_writer_guest_rip")=="0x80100fd60"
           and fex.get("source_writer_x86_bytes")=="498906",
           "not original source GNU ldso x86 translated writer")
    demand(fex.get("writer_native_STLR_repeated_execution_count")==46
           and fex.get("original_libc_index85_zero_target_store_trap_count")==1,
           "FEX original glibc 46 sources no longer reached")
    demand(fex.get("original_ldso_zero_target_store_trap_count")==0
           and fex.get("guest_original_ldso_irelative_zero_store_executed_proven") is False
           and fex.get("guest_original_irelative_resolver_executed_proven") is False,
           "GNU ldso FEX self relocator falsely promoted")
    demand(fex.get("original_guest_mprotect10_unsupported") is True,
           "bounded FEX mprotect must not be silently marked supported")
    demand(fex.get("native_exit_code")==117 and fex.get("native_exited") is True
           and fex.get("debugger_error") is None,
           "original guest FEX halted somewhere other than existing bounded syscall boundary")
    for name in ("all_three_ELF_relocations_closed","main_PT_GNU_RELRO_sealed",
                 "Android_Bionic_or_Wine_game_proven"):
        demand(fex.get(name) is False, "unsupported full memory or game promotion: "+name)
    # Require exact real guest RIP, main RELRO page, size, protection, and
    # explicit NO SEAL marker from the immutable ARM64 GDB runtime log.
    m=re.search(r"KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL "
                r"num=10 rip=801025db9 rdi=800003000 rsi=1000 rdx=1(?:\s|$)",fexlog)
    demand(m is not None, "frozen FEX runner source did not actually report guest mprotect10 main RELRO syscall")
    demand(re.search(r"KERNIX_G0_REAL_ORIGINAL_MAIN_PT_GNU_RELRO_AFTER_LIBC_RELRO_NEXT_MPROTECT10_SOURCE_ONLY_PASS "
                     r"addr=800003000 len=1000 prot=1 rights=rw-p NOT_SEALED_NO_FULL_RELOCATION_PROOF",
                     fexlog) is not None,
           "FEX source did not attest same first unsupported main RELRO RW page at 0x800003000")
    return {
        "schema":"kernix.g0.original-GNU-ldso-irelative-mprotect10-native-x86-vs-FEX-ARM64-differential.v1",
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
        "safe_implementation_requirement":"Do not return 0 for mprotect unless exact original guest page rights are atomically applied and per-object relocation closure plus guest page ownership are proven; never silently RWX, no host arbitrary-pointer mprotect.",
        "main_PT_GNU_RELRO_sealed_under_FEX":False,
        "all_original_dynamic_relocation_writes_verified":False,
        "Android_Bionic_Wine_or_PC_games_proven":False,
    }

def selftests(native:dict,fex:dict,log:str)->int:
    adversarial=[
        ("fake original full RELRO",lambda n,f:n.update(main_PT_GNU_RELRO_sealed_under_FEX=True)),
        ("fake successful FEX syscall",lambda n,f:f.update(original_guest_mprotect10_unsupported=False)),
        ("fake GNU ldso FEX zero store",lambda n,f:f.update(guest_original_ldso_irelative_zero_store_executed_proven=True)),
        ("fake FEX own resolver",lambda n,f:f.update(guest_original_irelative_resolver_executed_proven=True)),
        ("skip native 4K RELRO mprotect",lambda n,f:n["native_x86_mprotect10_entry_exit_events"].pop(2)),
        ("false kernel mprotect result",lambda n,f:n["native_x86_mprotect10_entry_exit_events"][1].update(native_x86_rax_at_stop="0xffffffffffffffff")),
        ("native relocator before libc",lambda n,f:n.update(original_loader_self_resolver_first_event_index=0)),
        ("mismatched x86 writer store",lambda n,f:n["source_loader_self_store_events"][0].update(original_x86_instruction_bytes="498907")),
        ("false game launch",lambda n,f:f.update(Android_Bionic_or_Wine_game_proven=True)),
        ("false FEX normal exit",lambda n,f:f.update(native_exit_code=0)),
        ("wrong FEX guest main mprotect site",lambda n,f:f.update(source_writer_guest_rip="0x80100fd64")),
        ("mismatch native ELF source",lambda n,f:n.update(original_libc_sha256="0"*64)),
    ]
    for i,(label,edit) in enumerate(adversarial,1):
        n,f=copy.deepcopy(native),copy.deepcopy(fex)
        edit(n,f)
        try:
            classify(n,f,log)
        except GateError:
            print(f"KERNIX_G0_MPROTECT10_DIFFERENTIAL_FALSE_PROOF_{i:02d}_REJECTED {label}")
            continue
        raise GateError("adversarial mutation accepted: "+label)
    return len(adversarial)

def main(argv:list[str])->int:
    if len(argv)!=5 or argv[1] not in ("validate","selftest"):
        print("Usage: differential.py validate|selftest NATIVE.json FEX.json FEX_GDB_LOG",file=sys.stderr)
        return 2
    native=json.loads(Path(argv[2]).read_text())
    fex=json.loads(Path(argv[3]).read_text())
    log=Path(argv[4]).read_text(errors="replace")
    report=classify(native,fex,log)
    print(json.dumps(report,indent=2,sort_keys=True))
    if argv[1]=="selftest":
        require(selftests(native,fex,log)==12,"negative proof test count drift")
    print("KERNIX_G0_NATIVE_X86_FIRST_46_LIBC_IFUNCS_THEN_SUCCESSFUL_MPROTECT_THEN_LDSO_SELF_IFUNC_FEX_STOPS_PRE_SELF_AT_UNSUPPORTED_MPROTECT10_PASS_NO_SEAL_CLAIM")
    return 0

if __name__=="__main__":
    try:
        raise SystemExit(main(sys.argv))
    except (GateError,ValueError,KeyError,TypeError) as exc:
        print("KERNIX_G0_MPROTECT10_CHRONOLOGY_DIFFERENTIAL_FAIL_CLOSED: "+str(exc),file=sys.stderr)
        raise SystemExit(1)
