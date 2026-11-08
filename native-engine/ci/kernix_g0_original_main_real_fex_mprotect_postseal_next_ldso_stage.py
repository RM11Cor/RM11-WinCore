#!/usr/bin/env python3
"""Independently reconcile *actual* original FEX guest x86 main mprotect(10).

A real ARM64 Linux kernel returned success changing source-locked original
main guest PT_GNU_RELRO page to RO in the live FEX process. The FEX callback
then tested an actual child SIGSEGV and set guest RAX=0. The guest resumed
to its NEXT source ldso self-range mprotect(10) at 0x801036000, where an old
source-main-only diagnostic guard refused it. The GNU ldso's own IRELATIVE
resolver/writer has not been separately watched: do not promote its proof.

This checks original runner output + immutable native x86 chronology, not
independent reexecution and not Android/Wine/PC gameplay.
"""
from __future__ import annotations
import copy
import json
import re
import sys
from pathlib import Path

SCHEMA="kernix.g0.original-main-real-fex-source-guest-mprotect10-native-4k-page-post-denial.v1"
NATIVE="kernix.g0.original-GNU-ldso-irelative-mprotect10-native-x86-vs-FEX-ARM64-differential.v1"
class Refused(ValueError):pass

def require(good,why):
    if not good:raise Refused(why)

def exactly_once(src,pattern):
    lines=[line for line in src.splitlines() if pattern in line]
    require(len(lines)==1,"ambiguous real FEX milestone "+pattern)
    return lines[0]

def classify(fex,raw,native):
    require(isinstance(fex,dict) and fex.get("schema")==SCHEMA,
        "wrong source original real guest FEX x86 mprotect receipt")
    expected={
      "original_main_guest_x86_syscall10_source_RIP":"0x801025db9",
      "original_main_4k_guest_relro":"0x800003000",
      "original_main_source_eight_qwords_verified":True,
      "same_original_FEX_process_libc_relro_native_syscall_succeeded":True,
      "same_original_FEX_process_main_guest_syscall10_kernel_mprotect_succeeded":True,
      "same_original_FEX_process_main_guest_page_native_r_only":True,
      "adjacent_guest_page_native_rw_unchanged":True,
      "postprotect_fork_child_actual_SIGSEGV_write_denied":True,
      "native_linux_arm64_4k_guest_4k_host":True,
      "native_FEX_guest_RAX_zero_only_after_kernel_and_child_write_denial":True,
      "later_original_ldso_self_irelative_resolver_executed_proven":False,
      "all_triad_dynamic_relocation_completed_proven":False,
      "Android_Bionic_or_Wine_games_proven":False,
    }
    for key,value in expected.items():
        require(type(fex.get(key)) is type(value) and fex.get(key)==value,
                "incorrect actual source FEX kernel protection receipt "+key)
    ec=fex.get("bounded_guest_process_exit_code_after_protected_page")
    require(type(ec) is int and 0<ec<124,
            "FEX diagnostic was not bounded by its next intentional source guard")
    require(isinstance(native,dict) and native.get("schema")==NATIVE,
            "missing source-pinned real native x86 chronology reference")
    require(native.get("native_original_GNU_ldso_self_IFUNC_resolver_event_index")==50
            and native.get("native_original_GNU_ldso_self_IFUNC_store_event_index")==51
            and native.get("native_loader_later_self_mprotect_events")==[52,53],
            "different original x86 loader self IRELATIVE/protection order")
    require(native.get("FEX_arm64_original_guest_main_RELRO_page")=="0x800003000"
            and native.get("FEX_arm64_original_mprotect_guest_RIP")=="0x801025db9",
            "native reference does not match source authentic FEX guest page and RIP")
    require(native.get("FEX_arm64_GNU_ldso_self_slot_guest_store_proven") is False
            and native.get("main_PT_GNU_RELRO_sealed_under_FEX") is False,
            "historical native FEX before-repair boundary must remain historical")
    libc=exactly_once(raw,"KERNIX_G0_REAL_ORIGINAL_LIBC_SOURCE_GNU_RELRO_MPROTECT10_RW_TO_RO_FOUR_4K_PAGES_PASS")
    opcode=exactly_once(raw,"KERNIX_G0_ORIGINAL_LDSO_MAIN_MPROTECT_SYSCALL_OPCODE_READONLY")
    main=exactly_once(raw,"KERNIX_G0_ORIGINAL_FEX_GNU_MAIN_PT_GNU_RELRO_LIVE_GUEST_SYSCALL10_KERNEL_RO_CHILD_WRITE_DENIED")
    following=exactly_once(raw,"KERNIX_G0_REAL_NEXT_MAIN_RELRO_SOURCE_AUDIT_REJECT")
    require(raw.index(libc)<raw.index(opcode)<raw.index(main)<raw.index(following),
            "real Linux ARM64 FEX original guest syscall10 stage event order false")
    for item in (
      "guest_rip=801025db9","target=800003000","len=1000","prot=1",
      "native_rights=r--p","next_guest_page=rw-p",
      "eight_original_main_values_verified=1",
      "actual_host_mprotect_succeeded=1","guest_rax_zero_after_kernel=1",
      "ldso_self_IFUNC_not_yet_proven=1","android_games_not_tested=1"
    ):
        require(item in main, "missing exact live original FEX native mprotect or deny witness "+item)
    require(re.search(r"request=801036000 expected=800003000.*live=r--p",following),
            "post-main FEX source next ldso self-range mprotect request not identified")
    require("KERNIX_G0_REAL_FEX_GNU_MAIN_RELRO_NATIVE_MPROTECT_FAIL_CLOSED" not in raw,
            "kernel main mprotect had a validation failure")
    require("KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL" not in raw,
            "source FEX did not progress through original main mprotect")
    return {
      "schema":"kernix.g0.main-real-fex-source-guest-kernel-mprotect-next-self-ldso-request-observed.v1",
      "source_FEX_linux_arm64_guest_syscall10_main_4k_kernel_success":True,
      "original_main_PT_GNU_RELRO_kernel_ro_and_real_child_write_denial":True,
      "original_main_8_source_got_slots_expected_values":True,
      "same_process_libc_then_main_relro_native_protection":True,
      "next_original_gnu_ldso_own_page_protection_requested_after_main":"0x801036000",
      "next_ldso_page_request_was_intentionally_denied_by_main_only_guard":True,
      "native_x86_reference_self_irelative_resolver_before_later_self_protection":True,
      "actual_FEX_self_irelative_x86_guest_resolver_rip_proven":False,
      "actual_FEX_original_ldso_self_irelative_zero_writer_proven":False,
      "actual_FEX_original_ldso_next_self_relro_page_sealed":False,
      "original_main_guest_returns_from_loader_exit_zero_proven":False,
      "full_original_three_elf_relocations_closed_proven":False,
      "android_bionic_wine_proton_games_proven":False,
      "next_gate":"At genuine original FEX post-main source boundary, observe original GNU ldso resolver x86 RIP 0x80101a8e0 and real zero-to-zero STLR writer to 0x801036360. Only then independently authorize exact original ldso source PT_GNU_RELRO at 0x801036000; never redirect an arbitrary guest pointer."
    }

def negatives(fex,raw,native):
    mutation=[
      ("fake main kernel success",lambda f,n,l:f.update(same_original_FEX_process_main_guest_syscall10_kernel_mprotect_succeeded=False)),
      ("fake native RO",lambda f,n,l:f.update(same_original_FEX_process_main_guest_page_native_r_only=False)),
      ("fake write denial",lambda f,n,l:f.update(postprotect_fork_child_actual_SIGSEGV_write_denied=False)),
      ("fake previous libc protection",lambda f,n,l:f.update(same_original_FEX_process_libc_relro_native_syscall_succeeded=False)),
      ("fake eight values",lambda f,n,l:f.update(original_main_source_eight_qwords_verified=False)),
      ("fake guest RAX proof",lambda f,n,l:f.update(native_FEX_guest_RAX_zero_only_after_kernel_and_child_write_denial=False)),
      ("fake unsupported source IFUNC closure",lambda f,n,l:f.update(later_original_ldso_self_irelative_resolver_executed_proven=True)),
      ("fake global linker closure",lambda f,n,l:f.update(all_triad_dynamic_relocation_completed_proven=True)),
      ("fake Android game",lambda f,n,l:f.update(Android_Bionic_or_Wine_games_proven=True)),
      ("wrong original guest page",lambda f,n,l:f.update(original_main_4k_guest_relro="0x800004000")),
      ("wrong original guest RIP",lambda f,n,l:f.update(original_main_guest_x86_syscall10_source_RIP="0x801025dba")),
      ("fake normal program exit",lambda f,n,l:f.update(bounded_guest_process_exit_code_after_protected_page=0)),
      ("native x86 last self stage out of order",lambda f,n,l:n.update(native_original_GNU_ldso_self_IFUNC_resolver_event_index=48)),
    ]
    for i,(title,change) in enumerate(mutation,1):
        f=copy.deepcopy(fex); n=copy.deepcopy(native);l=[raw]
        change(f,n,l)
        try:classify(f,l[0],n)
        except (Refused,ValueError,KeyError,TypeError):
            print(f"KERNIX_G0_REAL_ORIGINAL_GUEST_MPROTECT_POST_STAGE_FALSE_PROOF_{i:02d}_REJECTED {title}")
        else:raise Refused("false original main FEX guest seal proof accepted: "+title)
    for i,(title,old,new) in enumerate([
      ("wrong main guest protection","native_rights=r--p","native_rights=rw-p"),
      ("wrong next ldso page","request=801036000","request=800003000"),
      ("wrong kernel source","actual_host_mprotect_succeeded=1","actual_host_mprotect_succeeded=0"),
      ("wrong writable neighbor","next_guest_page=rw-p","next_guest_page=r--p"),
      ("wrong source guest RIP","guest_rip=801025db9","guest_rip=801025dba"),
    ],len(mutation)+1):
        t=raw.replace(old,new,1)
        require(t!=raw,"corrupt log mutation absent "+title)
        try:classify(fex,t,native)
        except (Refused,ValueError,KeyError,TypeError):
            print(f"KERNIX_G0_REAL_ORIGINAL_GUEST_MPROTECT_POST_STAGE_FALSE_PROOF_{i:02d}_REJECTED {title}")
        else:raise Refused("corrupt native FEX source kernel log accepted: "+title)
    return len(mutation)+5

def main(args):
    if len(args)!=5 or args[1]!="selftest":
        print("usage: gate.py selftest FEX_RECEIPT.json FEX_STDERR.log NATIVE_REFERENCE.json",file=sys.stderr)
        return 2
    fex=json.loads(Path(args[2]).read_text())
    raw=Path(args[3]).read_text(errors="replace")
    native=json.loads(Path(args[4]).read_text())
    result=classify(fex,raw,native)
    require(negatives(fex,raw,native)==18,"missing 18 fake original GNU FEX protection proofs")
    print(json.dumps(result,indent=2,sort_keys=True))
    print("KERNIX_G0_REAL_FEX_GNU_MAIN_RELRO_KERNEL_PROTECTED_ORIGINAL_X86_GUEST_CONTINUES_TO_LDSO_SELF_MPROTECT_STAGE_IFUNC_NOT_TRACED")
    return 0

if __name__=="__main__":
    try:raise SystemExit(main(sys.argv))
    except (Refused,ValueError,KeyError,TypeError) as e:
        print("KERNIX_G0_REAL_ORIGINAL_MAIN_FEX_MPROTECT_NEXT_SOURCE_STAGE_FAIL_CLOSED: "+str(e),file=sys.stderr)
        raise SystemExit(1)
