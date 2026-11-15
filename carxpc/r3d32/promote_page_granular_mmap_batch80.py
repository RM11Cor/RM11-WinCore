#!/usr/bin/env python3
"""R3D32: page-granular guest mmap writable proof + 80 independent preflight cases.

REAL REDMAGIC R3D31 result: 64/64 source-independent preflight passes, then
source-verified original GNU ELF/libc x86 syscall 32 getrandom(318) with
destination 0x734F9F8178, len=8, GRND_NONBLOCK. It was rejected because
GuestMappings stored one pessimistic region-wide writable bool. The GNU
ld.so reserved a large RO mapping, then MAP_FIXED-overlaid inner libc RW
pages. A guest address inside RW libc PT_LOAD must be tracked page by page.
This build changes the actual VM registry to reflect each 4K page and adds
16 independently logged nested-mmap/mprotect preflights (40+24+16=80), then
ONE original 512-x86-ELF syscall Wine bootstrap. This is not 80 executed
x86 syscalls or a fake guest Wine boot. Unknown syscalls fail closed.
"""
from pathlib import Path
import re,sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_page_granular_mmap_batch80.py /tmp/carxpc")
app=Path(sys.argv[1]);java=app/"app/src/main/java/com/r4/carxpc"
cpp=app/"app/src/main/cpp/carx_r3d4_first_syscall.cpp"
act=java/"R3D4ProbeActivity.java";main=java/"MainActivity.java"
gradle=app/"app/build.gradle";store=java/"R3D8JsonReportStore.java"
assert all(x.is_file() for x in (cpp,act,main,gradle,store))
mapping=Path("carxpc/r3d19/native/unified_guest_libc_abi.hpp").read_text()
assert all(x in mapping for x in (
  "std::unique_ptr<uint8_t[]> pageWritable",
  "bool update_writable_pages",
  "r.pageWritable[p]==0",
  "const bool write=update_writable_pages(base,rounded",
  "const bool read=update_readable_pages(base,rounded",
  "const bool write=update_writable_pages(addr,rounded",
  "const bool read=update_readable_pages(addr,rounded",
  "r.pageWritable.reset()",
  "r.pageReadable.reset()"))
assert "allPagesWritable" not in mapping
def one(s,a,n):
 c=s.count(a)
 assert c==1,("R3D32_SOURCE_PINNED_ANCHOR_CHANGED",a[:140],c)
 return s.replace(a,n,1)
def reone(s,p,n):
 s,k=re.subn(p,n,s,count=1)
 assert k==1,("R3D32_VERSION_SOURCE_CHANGED",p,k)
 return s
s=gradle.read_text()
s=reone(s,r"\bversionCode\s+59\b","versionCode 60")
s=reone(s,r"versionName\s+'[^']+'",
 "versionName '0.60-r3d32-batch80-page-precise-nested-fixed-map'")
gradle.write_text(s)
s=main.read_text()
s=one(s,"10 | R3D31 — فحص 64 حالة وWine دفعة واحدة",
      "10 | R3D32 — فحص 80 حالة وWine دفعة واحدة")
main.write_text(s)
s=store.read_text()
s=one(s,'"CarX_PC_R3D31_Batch64Random_Diagnostics_"',
      '"CarX_PC_R3D32_Batch80Memory_Diagnostics_"')
store.write_text(s)
s=cpp.read_text()
s=one(s,
'''#include "carxpc/r3d31/native/batch64_syscall_preflight.hpp"''',
'''#include "carxpc/r3d31/native/batch64_syscall_preflight.hpp"
#include "carxpc/r3d32/native/preflight16_guest_mmap_pages.hpp"''')
s=one(s,
'''    carx_r3d6::note("N45_COMBINED_64_INDEPENDENT_PREPARATION_CASES_PASS");
  }
  context->ExecuteThread(thread);''',
'''    carx_r3d6::note("N45_COMBINED_64_INDEPENDENT_PREPARATION_CASES_PASS");
    // Each scenario starts with a NEW 8-page original read-only reservation,
    // places RW libc-like pages inside it with MAP_FIXED, tests partial
    // mprotect/fixed overlays/cross-page writes, and unmaps before next.
    // Keep logging all 16 outcomes before stopping on multiple failures.
    const auto memory16=carx_r3d32::run_preflight16(
       [](const char* marker){carx_r3d6::note(marker);});
    if(!memory16.ready()){
       carx_r3d6::note("E_R3D32_GUEST_MMAP_PAGE_PREFLIGHT16_FAILED");
       ::_exit(191);
    }
    carx_r3d6::note("N49_COMBINED_80_INDEPENDENT_PREPARATION_CASES_PASS");
  }
  context->ExecuteThread(thread);''')
s=one(s,
'''        const auto misc=carx_r3d31::source_locked_dispatch(
           number,arg0,arg1,arg2,writeOwnedGuest);''',
'''        // Preserve a source witness of the exact original mapped buffer
        // metadata only, never random output bytes, and only for the real
        // libc source-verified getrandom(318) callback.
        if(number==carx_r3d31::kLinuxGetrandom){
          carx_r3d6::note(
             GuestMaps.owned_range(arg0,arg1)?
               "N50_X86_GETRANDOM_DEST_OWNED_BY_GUEST_MMAP":
               "E_R3D32_GETRANDOM_DEST_NOT_OWNED_BY_GUEST_MMAP");
          carx_r3d6::note(
             GuestMaps.owned_writable_range(arg0,arg1)?
               "N50_X86_GETRANDOM_DEST_PAGEWISE_WRITABLE":
               "E_R3D32_GETRANDOM_DEST_PAGEWISE_WRITE_DENIED");
        }
        const auto misc=carx_r3d31::source_locked_dispatch(
           number,arg0,arg1,arg2,writeOwnedGuest);''')
s=one(s,
'''            carx_r3d6::note("N46_GUEST_GETRANDOM_REAL_HOST_ENTROPY_NO_GUEST_PTR_FORWARD");''',
'''            carx_r3d6::note("N46_GUEST_GETRANDOM_REAL_HOST_ENTROPY_NO_GUEST_PTR_FORWARD");
            carx_r3d6::note("N50_GETRANDOM_GUEST_WRITABLE_MMAP_PER_PAGE_ABI_ACCEPTED");''')
assert all(x in s for x in (
"N49_COMBINED_80_INDEPENDENT_PREPARATION_CASES_PASS",
"N50_X86_GETRANDOM_DEST_PAGEWISE_WRITABLE",
"N50_GETRANDOM_GUEST_WRITABLE_MMAP_PER_PAGE_ABI_ACCEPTED",
"N22_BATCH_RETURN_R3D31_SOURCE_VERIFIED_RANDOM_CLOCK_TIME",
"N22_BATCH_RETURN_R3D30_GENERIC_ROOTFS_VFS_READLINK",
"N34_SOURCE_DOMAIN_VERIFIED_LIBC_FD100",
"context->ExecuteThread(thread)"))
cpp.write_text(s)
s=act.read_text()
s=one(s,
'''runCacheless.setText("تشغيل 07H — R3D31 Batch 64 + Wine 512");''',
'''runCacheless.setText("تشغيل 07H — R3D32 Batch 80 + Wine 512");''')
s=one(s,
'''r4.carx.r3d31.integrated-64-preflight-real-random-clock-fex512.v1''',
'''r4.carx.r3d32.integrated-80-preflight-page-mapped-real-fex512.v1''')
s=one(s,
'''07H_INTEGRATED_WINE_GNU_LDSO_LIBC_ROOTFS_BATCH64_RANDOM_CLOCK_FEX512''',
'''07H_INTEGRATED_WINE_GNU_LDSO_LIBC_ROOTFS_BATCH80_PAGE_MAPPED_FEX512''')
s=one(s,
'''07H_R3D31_BATCH64_UNIFIED_SOURCE_WINE_FEX512''',
'''07H_R3D32_BATCH80_UNIFIED_SOURCE_WINE_FEX512''')
s=one(s,
'''if(p.startsWith("E_BATCH_") || p.startsWith("E_R3D22_") ||
             p.startsWith("E_R3D25_") || p.startsWith("E_R3D27_") ||
             p.startsWith("E_R3D29_") || p.startsWith("E_R3D30_") ||
             p.startsWith("E_R3D31_"))
              stop=p;''',
'''if(p.startsWith("E_BATCH_") || p.startsWith("E_R3D22_") ||
             p.startsWith("E_R3D25_") || p.startsWith("E_R3D27_") ||
             p.startsWith("E_R3D29_") || p.startsWith("E_R3D30_") ||
             p.startsWith("E_R3D31_") || p.startsWith("E_R3D32_"))
              stop=p;''')
s=one(s,
'''        if(stop.startsWith("E_BATCH_UNSUPPORTED_NR_"))''',
'''        if(stop.startsWith("E_R3D31_SOURCE_LOCKED_MISC_ABI_UNSAFE_SHAPE_NR_"))
            return "BATCH_HALTED_UNSAFE_SOURCE_VERIFIED_LINUX_MISC_ABI_SHAPE";
        if(stop.startsWith("E_R3D32_GETRANDOM_DEST_PAGEWISE_WRITE_DENIED"))
            return "BATCH_HALTED_UNWRITABLE_GUEST_MMAP_PAGE";
        if(stop.startsWith("E_R3D32_GUEST_MMAP_PAGE_PREFLIGHT16_FAILED"))
            return "BATCH_HALTED_GUEST_MEMORY_PREFLIGHT_FAIL";
        if(stop.startsWith("E_BATCH_UNSUPPORTED_NR_"))''')
s=one(s,
'''        report.put("r3d31_preflight64_are_not_64_guest_syscalls",true);''',
'''        report.put("r3d31_preflight64_are_not_64_guest_syscalls",true);
        int memoryCases=0,memoryPassed=0,memoryFailed=0;
        for(int x=0;x<phases.length();x++){
          String p=phases.optString(x,"");
          if(p.contains("_R3D32_PREFLIGHT_MMAP_PAGE_CASE_")){
             memoryCases++;
             if(p.startsWith("N49_"))memoryPassed++;
             else memoryFailed++;
          }
        }
        report.put("r3d32_pagewise_mmap_preflight_scenarios",memoryCases);
        report.put("r3d32_pagewise_mmap_preflight_passed",memoryPassed);
        report.put("r3d32_pagewise_mmap_preflight_failed",memoryFailed);
        report.put("r3d32_combined_preflight_scenarios",
           readyTotal+extraTotal+memoryCases);
        report.put("r3d32_combined_preflight_passed",
           readyPassed+extraPassed+memoryPassed);
        report.put("r3d32_combined_preflight_all_passed",
           readyTotal+extraTotal+memoryCases==80 &&
           readyFails+extraFailed+memoryFailed==0 &&
           phases.toString().contains(
              "N49_COMBINED_80_INDEPENDENT_PREPARATION_CASES_PASS"));
        report.put("r3d32_getrandom_owned_guest_mmap_verified",
           phases.toString().contains(
              "N50_X86_GETRANDOM_DEST_OWNED_BY_GUEST_MMAP"));
        report.put("r3d32_getrandom_pagewise_mmap_writable_verified",
           phases.toString().contains(
              "N50_X86_GETRANDOM_DEST_PAGEWISE_WRITABLE"));
        report.put("r3d32_getrandom_source_verified_abi_returned",
           phases.toString().contains(
              "N50_GETRANDOM_GUEST_WRITABLE_MMAP_PER_PAGE_ABI_ACCEPTED") &&
           phases.toString().contains(
              "N22_BATCH_RETURN_R3D31_SOURCE_VERIFIED_RANDOM_CLOCK_TIME"));
        report.put("r3d32_guest_mmap_page_granularity_bytes",4096);
        report.put("r3d32_only_copy_random_bytes_to_owned_writable_guest_memory",true);
        report.put("r3d32_80_preflight_checks_are_not_real_guest_syscalls",true);''')
s=one(s,
'''        stages.put("win32_stage_automatically_started",false);''',
'''        stages.put("80_independent_preparation_cases_completed",
           phases.toString().contains(
              "N49_COMBINED_80_INDEPENDENT_PREPARATION_CASES_PASS"));
        stages.put("pagewise_guest_mmap_getrandom_source_verified",
           phases.toString().contains(
              "N50_GETRANDOM_GUEST_WRITABLE_MMAP_PER_PAGE_ABI_ACCEPTED"));
        stages.put("win32_stage_automatically_started",false);''')
s=one(s,
'''R3D31 expands the single launch from 40 rootfs preflight cases (all passed in R3D30 phone report) to 64 independent 40+24 preparation checks, recording EACH outcome, followed by one original x86 ELF-source-locked FEX/Wine Linux ABI batch up to 512 witnesses. Device R3D30 showed 32 source-verified ELF syscall callbacks, 31 bounded responses, then libc getrandom(318, writable guest anonymous mmap pointer, length 8, GRND_NONBLOCK=1). R3D31 derives its write permission from conservative tracked original guest mmap/protect state or the original bounded guest stack. Sources REAL Android kernel entropy into a separate local <=256-byte buffer, then only writes to verified guest writable region. No guest pointer passed directly to host. Five other original x86 Linux calls proactively implemented: clock_gettime, clock_getres, gettimeofday, time, sched_yield; previous six identity syscalls, Wine/libc filesystem, mmap, TLS, readlink, sealed RELRO retained. No claim that 64 preparation checks are executed x86 instructions. Full Wine process/Win64 PE/graphics/game startup is still gated and unproven.''',
'''R3D32 uses real R3D31 device evidence: 64/64 source-independent preflight successes and original x86 GNU/libc callbacks 32 observed, 31 accepted; getrandom318 on a genuine writable libc fixed-overlay guest mmap buffer was incorrectly rejected due to coarse parent RO reservation state. Fixed the ORIGINAL tracked guest mmap registry to record page-granular 4096-byte writable permissions across protected nested MAP_FIXED overlays and partial mprotect, failing closed on unowned, read-only or cross-boundary writes. Expanded the one-device-run 40 rootfs+24 syscall+16 independent page-write protection preflights = 80 tests before original source-verified FEX Wine boot up to 512 x86 Linux syscall witnesses. Real host getrandom uses only a local buffer and bounded verified write to guest mmap. The 80 preflight scenarios are NOT 80 original x86 syscalls; real FEX guest dispatch remains sequential and unknown unsafe shapes still stop. Full Linux guest process ABI, Wine, Windows PE, graphics and CarX boot remain unproven.''')
act.write_text(s)
print("R3D32_PINNED_PAGE_GRANULAR_SOURCE_AND_BATCH80_PROMOTION_PASS")
print("R3D32_GETRANDOM318_RW_FIXED_OVERLAY_TRACKED_PER_4K_GUEST_PAGE_PASS")
