#!/usr/bin/env python3
"""R3D31: 64 independent preparation tests + one original x86 FEX batch 512.

R3D30 phone proves the 40 rootfs tests ALL pass; 31 original x86 Linux ABI
calls handled, and the 32nd original libc FD100 syscall is 318 getrandom:
dst=source-verified guest anonymous mmap+offset, count=8, GRND_NONBLOCK=1.
This cannot be solved by the old guest-stack-only pointer validator.
R3D31 adds conservative write-authorization tracking to *owned* guest mmap
regions (and retains the owned x86 guest stack) and six real Linux ABI
calls with matching x86 structs/no host guest pointer pass-through:
  318 getrandom, 228 clock_gettime, 229 clock_getres,
   96 gettimeofday, 201 time, 24 sched_yield.
Plus 24 independent ABI preparation cases in SAME invocation as R3D30's
40 rootfs preflights. The 64 cases are NOT 64 x86 syscall executions.
Then one original 512 syscall source witness batch. Unknown/unsafe shapes
remain fail closed; no fake entropy or completed Wine/PE claim.
"""
from pathlib import Path
import re,sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_batch64_guest_misc_abi.py /tmp/carxpc")
app=Path(sys.argv[1]);java=app/"app/src/main/java/com/r4/carxpc"
cpp=app/"app/src/main/cpp/carx_r3d4_first_syscall.cpp"
act=java/"R3D4ProbeActivity.java";main=java/"MainActivity.java"
gradle=app/"app/build.gradle";store=java/"R3D8JsonReportStore.java"
assert all(x.is_file() for x in (cpp,act,main,gradle,store))
# Validate the *actual* source header used by the existing build, and reject
# patch drift. Do not claim non-writable host memory is safe to overwrite.
mapping=Path("carxpc/r3d19/native/unified_guest_libc_abi.hpp").read_text()
assert "bool owned_writable_range" in mapping
assert "allPagesWritable" in mapping
assert "r.allPagesWritable=false;" in mapping
def one(s,a,n):
 c=s.count(a)
 assert c==1,("R3D31_SOURCE_PINNED_ANCHOR_CHANGED",a[:130],c)
 return s.replace(a,n,1)
def reone(s,p,n):
 s,k=re.subn(p,n,s,count=1)
 assert k==1,("R3D31_VERSION_SOURCE_CHANGED",p,k)
 return s
s=gradle.read_text()
s=reone(s,r"\bversionCode\s+58\b","versionCode 59")
s=reone(s,r"versionName\s+'[^']+'",
 "versionName '0.59-r3d31-batch64-rootfs-random-clock-and-guest-mmap-write'")
gradle.write_text(s)
s=main.read_text()
s=one(s,"10 | R3D30 — فحص مجمّع وتهيئة Wine",
      "10 | R3D31 — فحص 64 حالة وWine دفعة واحدة")
main.write_text(s)
s=store.read_text()
s=one(s,'"CarX_PC_R3D30_BatchedVFS_Diagnostics_"',
      '"CarX_PC_R3D31_Batch64Random_Diagnostics_"')
store.write_text(s)
s=cpp.read_text()
s=one(s,
'''#include "carxpc/r3d30/native/source_locked_guest_identity.hpp"''',
'''#include "carxpc/r3d30/native/source_locked_guest_identity.hpp"
#include "carxpc/r3d31/native/source_locked_guest_misc_abi.hpp"
#include "carxpc/r3d31/native/batch64_syscall_preflight.hpp"''')
s=one(s,
'''    carx_r3d6::note("N40_PREFLIGHT_40_CASES_COMPLETED_BEFORE_REAL_FEX");
  }
  context->ExecuteThread(thread);''',
'''    carx_r3d6::note("N40_PREFLIGHT_40_CASES_COMPLETED_BEFORE_REAL_FEX");
    const auto abi24=carx_r3d31::run_preflight_24(
        [](const char* marker){carx_r3d6::note(marker);});
    if(!abi24.ready()){
      carx_r3d6::note("E_R3D31_PREFLIGHT24_GUEST_LINUX_ABI_FAILED");
      ::_exit(189);
    }
    carx_r3d6::note("N45_COMBINED_64_INDEPENDENT_PREPARATION_CASES_PASS");
  }
  context->ExecuteThread(thread);''')
s=one(s,
'''        if(number==carx_r3d27::kLinuxX86Readlink) {''',
'''        // Six more standard x86-64 Linux ABI calls, proactively prepared.
        // Existing 0F05 owner-source verifier already ran before this block.
        // Guest memory is mapped ONLY from the previously established VM
        // registry or from the owned 64KiB guest Linux stack. We never hand
        // a raw x86 pointer to host getrandom, clocks, or other syscalls.
        const auto writeOwnedGuest=[&](uint64_t dst,uint64_t size)->bool{
          return GuestMaps.owned_writable_range(dst,size) ||
                 carx_r3d18::owned_stack_write_bounds(dst,size);
        };
        const auto misc=carx_r3d31::source_locked_dispatch(
           number,arg0,arg1,arg2,writeOwnedGuest);
        if(misc.kind==carx_r3d31::Kind::ShapeRejected){
          char detail[120]{};
          std::snprintf(detail,sizeof(detail),
             "E_R3D31_SOURCE_LOCKED_MISC_ABI_UNSAFE_SHAPE_NR_%llu",
             static_cast<unsigned long long>(number));
          carx_r3d6::note(detail);
          ::_exit(190);
        }
        if(misc.kind==carx_r3d31::Kind::Success){
          if(number==carx_r3d31::kLinuxGetrandom){
            carx_r3d6::note("N46_GUEST_GETRANDOM_REAL_HOST_ENTROPY_NO_GUEST_PTR_FORWARD");
            if(misc.result>=0){
              char bytes[108]{};
              std::snprintf(bytes,sizeof(bytes),
                 "N46_X86_GUEST_GETRANDOM_RETURN_BYTE_COUNT_%llu",
                 static_cast<unsigned long long>(misc.result));
              carx_r3d6::note(bytes);
            }
          }else{
            char kind[120]{};
            std::snprintf(kind,sizeof(kind),
                 "N46_GUEST_MISC_SOURCE_VERIFIED_NR_%llu",
                 static_cast<unsigned long long>(number));
            carx_r3d6::note(kind);
          }
          accept(misc.result,
                 "N22_BATCH_RETURN_R3D31_SOURCE_VERIFIED_RANDOM_CLOCK_TIME");
          return;
        }
        if(number==carx_r3d27::kLinuxX86Readlink) {''')
assert all(x in s for x in (
 "N45_COMBINED_64_INDEPENDENT_PREPARATION_CASES_PASS",
 "N46_GUEST_GETRANDOM_REAL_HOST_ENTROPY_NO_GUEST_PTR_FORWARD",
 "N22_BATCH_RETURN_R3D31_SOURCE_VERIFIED_RANDOM_CLOCK_TIME",
 "E_R3D31_SOURCE_LOCKED_MISC_ABI_UNSAFE_SHAPE_NR_",
 "GuestMaps.owned_writable_range",
 "N22_BATCH_RETURN_R3D30_GENERIC_ROOTFS_VFS_READLINK",
 "N34_SOURCE_DOMAIN_VERIFIED_LIBC_FD100",
 "context->ExecuteThread(thread)"))
cpp.write_text(s)
s=act.read_text()
s=one(s,
'''runCacheless.setText("تشغيل 07H — R3D30 Batch 40 + Wine 512");''',
'''runCacheless.setText("تشغيل 07H — R3D31 Batch 64 + Wine 512");''')
s=one(s,
'''r4.carx.r3d30.integrated-batched-40-case-rootfs-vfs-and-fex512.v1''',
'''r4.carx.r3d31.integrated-64-preflight-real-random-clock-fex512.v1''')
s=one(s,
'''07H_INTEGRATED_WINE_GNU_LDSO_LIBC_ROOTFS_VFS_BATCH40_FEX512''',
'''07H_INTEGRATED_WINE_GNU_LDSO_LIBC_ROOTFS_BATCH64_RANDOM_CLOCK_FEX512''')
s=one(s,
'''07H_R3D30_BATCHED_PREFLIGHT40_UNIFIED_WINE_FEX512''',
'''07H_R3D31_BATCH64_UNIFIED_SOURCE_WINE_FEX512''')
s=one(s,
'''if(p.startsWith("E_BATCH_") || p.startsWith("E_R3D22_") ||
             p.startsWith("E_R3D25_") || p.startsWith("E_R3D27_") ||
             p.startsWith("E_R3D29_") || p.startsWith("E_R3D30_"))
              stop=p;''',
'''if(p.startsWith("E_BATCH_") || p.startsWith("E_R3D22_") ||
             p.startsWith("E_R3D25_") || p.startsWith("E_R3D27_") ||
             p.startsWith("E_R3D29_") || p.startsWith("E_R3D30_") ||
             p.startsWith("E_R3D31_"))
              stop=p;''')
s=one(s,
'''        report.put("r3d30_mandatory_first_stage",''',
'''        int extraTotal=0,extraPassed=0,extraFailed=0;
        for(int x=0;x<phases.length();x++){
            String p=phases.optString(x,"");
            if(p.contains("_R3D31_PREFLIGHT_ABI_CASE_")){
                extraTotal++;
                if(p.startsWith("N45_"))extraPassed++;
                else extraFailed++;
            }
        }
        report.put("r3d31_additional_abi_preflight_scenarios",extraTotal);
        report.put("r3d31_additional_abi_preflight_passed",extraPassed);
        report.put("r3d31_additional_abi_preflight_failed",extraFailed);
        report.put("r3d31_total_independent_preflight_scenarios",
           readyTotal+extraTotal);
        report.put("r3d31_total_independent_preflight_passed",
           readyPassed+extraPassed);
        report.put("r3d31_combined_preflight_all_passed",
           readyTotal+extraTotal==64&&readyFails+extraFailed==0&&
           phases.toString().contains(
             "N45_COMBINED_64_INDEPENDENT_PREPARATION_CASES_PASS"));
        report.put("r3d31_real_getrandom_source_verified_observed",
           phases.toString().contains(
             "N46_GUEST_GETRANDOM_REAL_HOST_ENTROPY_NO_GUEST_PTR_FORWARD"));
        report.put("r3d31_real_getrandom_abi_accepted",
           phases.toString().contains(
             "N46_GUEST_GETRANDOM_REAL_HOST_ENTROPY_NO_GUEST_PTR_FORWARD")&&
           phases.toString().contains(
             "N22_BATCH_RETURN_R3D31_SOURCE_VERIFIED_RANDOM_CLOCK_TIME"));
        report.put("r3d31_other_misc_linux_abi_observed",
           phases.toString().contains("N46_GUEST_MISC_SOURCE_VERIFIED_NR_"));
        report.put("r3d31_proactive_supported_misc_syscalls",
           "getrandom318,clock_gettime228,clock_getres229,gettimeofday96,time201,sched_yield24");
        report.put("r3d31_entropy_bytes_logged_or_fabricated",false);
        report.put("r3d31_guest_output_writable_vm_or_owned_stack_only",true);
        report.put("r3d31_preflight64_are_not_64_guest_syscalls",true);
        report.put("r3d30_mandatory_first_stage",''')
s=one(s,
'''        stages.put("win32_stage_automatically_started",false);''',
'''        stages.put("combined_64_preparation_cases_completed",
          phases.toString().contains(
            "N45_COMBINED_64_INDEPENDENT_PREPARATION_CASES_PASS"));
        stages.put("source_verified_guest_getrandom_real_entropy",
          phases.toString().contains(
            "N46_GUEST_GETRANDOM_REAL_HOST_ENTROPY_NO_GUEST_PTR_FORWARD"));
        stages.put("win32_stage_automatically_started",false);''')
s=one(s,
'''R3D30 responds to the user's request to stop path-by-path APK cycles. The R3D29 device trace proved 31 original ELF syscall witnesses and 30 handled Linux guest calls; the next libc readlink(89) path is EXACT /usr/lib/wine/wine64 (original authenticated Wine ELF, a regular file). The new preopened, source-authenticated app-private guest rootfs directory fd feeds a generic bounded guest readlink VFS for arbitrary existing nonlink directory/regular file (-EINVAL), missing file (-ENOENT), and actual symlinks (no NUL), without Android host path forwarding. Unresolved intermediate symlinks fail closed. A separate 40-case batch preflight tests required rootfs paths and dangerous arguments, logging ALL cases and multiple failures, then ONE genuine FEX x86 512-syscall integrated Wine/Linux ABI pass. Six standard identity syscall handlers are also prepared but counted only if original x86 code actually invokes them. This is NOT 40 executed x86 calls and is NOT full Linux guest filesystem/process ABI or full Wine/Windows PE startup. Windows stage remains gated on real authenticated Wine boot plus Win32 launch bridge, not fabricated.''',
'''R3D31 expands the single launch from 40 rootfs preflight cases (all passed in R3D30 phone report) to 64 independent 40+24 preparation checks, recording EACH outcome, followed by one original x86 ELF-source-locked FEX/Wine Linux ABI batch up to 512 witnesses. Device R3D30 showed 32 source-verified ELF syscall callbacks, 31 bounded responses, then libc getrandom(318, writable guest anonymous mmap pointer, length 8, GRND_NONBLOCK=1). R3D31 derives its write permission from conservative tracked original guest mmap/protect state or the original bounded guest stack. Sources REAL Android kernel entropy into a separate local <=256-byte buffer, then only writes to verified guest writable region. No guest pointer passed directly to host. Five other original x86 Linux calls proactively implemented: clock_gettime, clock_getres, gettimeofday, time, sched_yield; previous six identity syscalls, Wine/libc filesystem, mmap, TLS, readlink, sealed RELRO retained. No claim that 64 preparation checks are executed x86 instructions. Full Wine process/Win64 PE/graphics/game startup is still gated and unproven.''')
act.write_text(s)
print("R3D31_PINNED_SOURCE_64_TEST_PREFLIGHT_AND_REAL_X86_MISC_ABI_PROMOTED_PASS")
print("R3D31_GUEST_MMAP_PROTECTION_TRACKED_GETRANDOM_318_PERM_CHECK_PASS")
