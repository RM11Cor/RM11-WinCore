#!/usr/bin/env python3
"""Regression: original SHA-pinned FEX libc owner base != its RW PTLOAD.

The exact source GNU dl-linux x86 mmap9 on Linux ARM64 returns guest_base
0x804000000 for *entire* original libc image. Later source libc mmap9
of RW PT_LOAD covers guest address 0x8041ff000, which is image base
+0x1ff000, not image base. Do not confuse them when guarding exact original
libc prlimit64(302) after the three live kernel RELRO seals.

This independently classifies archived true source-run logs; it does NOT
execute prlimit or claim native guest stack output succeeded.
"""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path
class Rejected(ValueError): pass
def need(v,reason):
    if not v:raise Rejected(reason)
def line(raw,marker):
    matches=[r for r in raw.splitlines() if marker in r]
    need(len(matches)==1,"missing original FEX stage "+marker)
    return matches[0]
def classify(log,cpp):
    base=line(log,"KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_LIBC_MMAP9_LARGE_PRIVATE_RO_SOURCE_2118168_REQUEST")
    fourth=line(log,"KERNIX_G0_REAL_ORIGINAL_GNU_LIBC_FOURTH_FIXED_RW_MMAP_PTLOAD_OFFSET_SHIFT_SOURCE")
    denial=line(log,"KERNIX_G0_ORIGINAL_LIBC_PRLIMIT64_SOURCE_TRAP_PRECONDITION_REJECT")
    main=line(log,"KERNIX_G0_ORIGINAL_FEX_GNU_MAIN_PT_GNU_RELRO_LIVE_GUEST_SYSCALL10_KERNEL_RO_CHILD_WRITE_DENIED")
    ldso=line(log,"KERNIX_G0_ORIGINAL_FEX_GNU_LDSO_SELF_PT_GNU_RELRO_TWO_4K_NATIVE_KERNEL_RO_CHILD_SIGSEGV_BOTH_GUEST_RAX_SUCCESS")
    need(log.index(base)<log.index(fourth)<log.index(main)<log.index(ldso)<log.index(denial),
         "source x86 ELF libc owner must precede three ELF RELRO and prlimit guard")
    need("guest_base=804000000" in base and "FD100_OFFSET0_WX_SAFE_EOF_GUARD_PASS" in base,
         "original libc owner mapped base mismatch")
    need("base=8041ff000" in fourth and "0x1fe000_TO_VADDR_0x1ff000" in fourth,
         "original source libc fourth RW PTLOAD offset differs from owner ELF base")
    need("both_rights=r--p" in ldso and "two_real_child_sigsegv=1" in ldso,
         "original loader self RELRO didn't complete before prlimit")
    need("actual_host_mprotect_succeeded=1" in main,
         "source original main kernel protection absent")
    need(re.search(r"\bbase!=0x804000000ULL\b",cpp) is not None,
         "prlimit guard must accept whole original libc guest mmap base, not RW PTLOAD")
    need(re.search(r"\bbase!=0x8041ff000ULL\b",cpp) is None,
         "unsafe prlimit guard confuses libc RW PTLOAD guest address with owner base")
    need("OriginalLibcLargeReadonlyMap().Address()" in cpp,
         "source original libc owner pointer must come from current owner map")
    need("KERNIX_G0_ORIGINAL_LIBC_PRLIMIT64_SOURCE_TRAP_PRECONDITION_REJECT" in cpp,
         "fail-closed guest syscall diagnostic removed")
    need("OriginalLibcPrlimit64Calls!=0" in cpp,
         "duplicate original source prlimit bypassed")
    return {
       "schema":"kernix.g0.original-libc-owner-vs-RW-PTLOAD-prlimit64-base-source-regression.v1",
       "source_real_FEX_original_libc_owning_image_base":"0x804000000",
       "source_real_FEX_original_libc_RW_PTLOAD_guest_start":"0x8041ff000",
       "source_original_libc_RW_PTLOAD_relative_offset":"0x1ff000",
       "source_original_libc_RW_PTLOAD_file_offset":"0x1fe000",
       "source_guest_three_original_module_RELRO_native_pass_before_prlimit":True,
       "source_real_guest_prlimit64_precondition_originally_rejected":True,
       "corrected_current_FEX_source_guard_equals_image_owner_base":True,
       "original_guest_prlimit64_kernel_result_or_guest_output_proven":False,
       "original_guest_program_exit_zero_proven":False,
       "Android_Bionic_Wine_Proton_games_proven":False
    }
def negative(log,cpp):
    changes=[
      ("owner base",lambda a,b:(a.replace("guest_base=804000000","guest_base=8041ff000",1),b)),
      ("fourth RW PTLOAD guest address",lambda a,b:(a.replace("base=8041ff000","base=804000000",1),b)),
      ("ELF source shifted writable page",lambda a,b:(a.replace("0x1fe000_TO_VADDR_0x1ff000","0x1ff000_TO_VADDR_0x1ff000",1),b)),
      ("current guard accidentally uses RW PTLOAD",lambda a,b:(a,b.replace("base!=0x804000000ULL","base!=0x8041ff000ULL",1))),
      ("current guard removes source owner",lambda a,b:(a,b.replace("OriginalLibcLargeReadonlyMap().Address()","OriginalLibcLargeReadonlyMap().BytesHeld()",1))),
      ("post-main mprotect succeeded forged",lambda a,b:(a.replace("actual_host_mprotect_succeeded=1","actual_host_mprotect_succeeded=0",1),b)),
      ("ldso two page child write denial forged",lambda a,b:(a.replace("two_real_child_sigsegv=1","two_real_child_sigsegv=0",1),b)),
      ("duplicate guest syscall gate removed",lambda a,b:(a,b.replace("OriginalLibcPrlimit64Calls!=0","OriginalLibcPrlimit64Calls==0",1))),
    ]
    need(len(changes)==8,"source negatives missing")
    for i,(title,mutator) in enumerate(changes,1):
        a,b=mutator(log,cpp)
        need(a!=log or b!=cpp,"cannot mutate original FEX evidence for "+title)
        try:classify(a,b)
        except Rejected:
            print(f"KERNIX_G0_LIBC_PRLIMIT_IMAGE_BASE_RWPAGE_FORGERY_{i:02d}_REJECTED {title}")
        else:raise Rejected("incorrect original libc owner base accepted: "+title)
    return len(changes)
def main(argv):
    if len(argv)!=4 or argv[1]!="selftest":
        print("usage: script.py selftest FAILED_REAL_FEX_SOURCE_LOG ORIGINAL_FEX_CPP",file=sys.stderr)
        return 2
    log=Path(argv[2]).read_text(errors="replace")
    cpp=Path(argv[3]).read_text()
    result=classify(log,cpp)
    need(negative(log,cpp)==8,"not all false libc ownership claims rejected")
    print(json.dumps(result,indent=2,sort_keys=True))
    print("KERNIX_G0_REAL_ORIGINAL_LIBC_OWNER_BASE_804000000_NOT_RW_PTLOAD_8041FF000_PRLIMIT_GUARD_REGRESSION_PASS")
    return 0
if __name__=="__main__":
    try:raise SystemExit(main(sys.argv))
    except (Rejected,ValueError,KeyError,TypeError) as err:
        print("KERNIX_G0_LIBC_OWNER_BASE_VS_RWPTLOAD_GUARD_FAIL_CLOSED: "+str(err),file=sys.stderr)
        raise SystemExit(1)
