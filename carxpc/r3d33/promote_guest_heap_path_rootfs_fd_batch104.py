#!/usr/bin/env python3
"""R3D33: real guest heap/mmap openat path; 104 independent batch preflights.

R3D32 phone 80/80, 35 original ELF source witnesses, 34 handled;
source-verified getrandom(318) accepted (8 REAL kernel random bytes), then
libc brk(12) query+growth. Original GNU ld.so openat(257) index34 has
path ptr 0x7382E00310 in the newly committed guest BRK region, not stack.
The old stack-only R3D16 reader fails with exit118. R3D33 generalizes
guest C string reading across source-owned committed brk and page-permitted
guest mmap and 64KiB guest stack, no host pointer pass-through. For safe
O_RDONLY|O_CLOEXEC openat, resolves under preopened source-authenticated
guest rootfs, returning real ENOENT or tracked FD101..116. Handles
read/pread64/fstat/lseek/close on those files via bounded local I/O and
guest x86 ABI conversion; refuses symlink traversal and new FD executable
mmap until original ELF/source-to-RX provenance can be established.
Adds 24 independent reader/heap checks to 80 existing = 104 preparation
cases, then one real original x86/FEX/Wine callback batch 512. No fake
successful Wine/PE boot, no unverified host filesystem access.
"""
from pathlib import Path
import re,sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_guest_heap_path_rootfs_fd_batch104.py /tmp/carxpc")
app=Path(sys.argv[1]);java=app/"app/src/main/java/com/r4/carxpc"
cpp=app/"app/src/main/cpp/carx_r3d4_first_syscall.cpp"
act=java/"R3D4ProbeActivity.java";main=java/"MainActivity.java"
gradle=app/"app/build.gradle";store=java/"R3D8JsonReportStore.java"
assert all(x.is_file() for x in (cpp,act,main,gradle,store))
map_code=Path("carxpc/r3d19/native/unified_guest_libc_abi.hpp").read_text()
assert all(x in map_code for x in (
 "std::unique_ptr<uint8_t[]> pageReadable",
 "bool owned_readable_range",
 "bool owned_writable_range",
 "update_readable_pages",
 "r.pageReadable.reset()"))
def one(s,a,n):
 c=s.count(a)
 assert c==1,("R3D33_PINNED_SOURCE_ANCHOR_CHANGED",a[:150],c)
 return s.replace(a,n,1)
def reone(s,p,n):
 s,k=re.subn(p,n,s,count=1)
 assert k==1,("R3D33_VERSION_SOURCE_CHANGED",p,k)
 return s
s=gradle.read_text()
s=reone(s,r"\bversionCode\s+60\b","versionCode 61")
s=reone(s,r"versionName\s+'[^']+'",
 "versionName '0.61-r3d33-batch104-vm-path-rootfs-readonly-fds'")
gradle.write_text(s)
s=main.read_text()
s=one(s,"10 | R3D32 — فحص 80 حالة وWine دفعة واحدة",
      "10 | R3D33 — فحص 104 حالات ومسارات Wine")
main.write_text(s)
s=store.read_text()
s=one(s,'"CarX_PC_R3D32_Batch80Memory_Diagnostics_"',
      '"CarX_PC_R3D33_Batch104GuestPaths_Diagnostics_"')
store.write_text(s)
s=cpp.read_text()
s=one(s,
'''#include "carxpc/r3d32/native/preflight16_guest_mmap_pages.hpp"''',
'''#include "carxpc/r3d32/native/preflight16_guest_mmap_pages.hpp"
#include "carxpc/r3d33/native/owned_guest_path_and_vfs.hpp"
#include "carxpc/r3d33/native/preflight24_guest_vm_paths.hpp"''')
s=one(s,
'''  int GuestRootfsDirFD{-1};''',
'''  int GuestRootfsDirFD{-1};
  carx_r3d33::ReadOnlyFiles GuestReadOnlyFiles{};''')
# Extend original R3D16 source-verified openat read from the STACK ONLY
# to precisely known guest-owned regions: 64K stack, committed brk, and
# the new R3D33 pagewise-readable GuestMappings.
s=one(s,
'''        if(carx_r3d16::capture_guest_stack_ascii_path(arg1,guestPath)) {''',
'''        const auto guestOwnedRead=[](uint64_t p,uint64_t n,
            const auto& map,uint64_t brkBase,uint64_t brkEnd)->bool{
           return carx_r3d18::owned_stack_write_bounds(p,n) ||
                  carx_r3d33::brk_readable(p,n,brkBase,brkEnd) ||
                  map.owned_readable_range(p,n);
        };
        const auto captured=carx_r3d33::capture_guest_owned_path(
          arg1,[&](uint64_t p,uint64_t n){
             return guestOwnedRead(p,n,GuestMaps,BRKBase,GuestBrkCurrent);
          });
        if(captured.status==carx_r3d33::PathStatus::Okay) {
          std::memcpy(guestPath,captured.path,sizeof(guestPath));
          if(carx_r3d33::brk_readable(
               arg1,captured.size+1,BRKBase,GuestBrkCurrent))
             carx_r3d6::note("N54_GUEST_OPENAT_PATH_PROVEN_OWNED_BRK");
          else if(GuestMaps.owned_readable_range(arg1,captured.size+1))
             carx_r3d6::note("N54_GUEST_OPENAT_PATH_PROVEN_OWNED_MMAP");
          else
             carx_r3d6::note("N54_GUEST_OPENAT_PATH_PROVEN_OWNED_STACK");''')
s=one(s,
'''            carx_r3d6::note("E_BATCH_GUEST_PATH_CAPTURED_NEEDS_VFS");
            ::_exit(117);''',
'''            if(Mode==4 && Seen>=4){
              const auto found=GuestReadOnlyFiles.open_guest_file(
                  GuestRootfsDirFD,guestPath);
              if(found.state!=carx_r3d33::OpenState::Resolved){
                 char condition[128]{};
                 std::snprintf(condition,sizeof(condition),
                     "E_R3D33_GUEST_ROOTFS_OPENAT_UNSAFE_STATE_%d",
                     int(found.state));
                 carx_r3d6::note(condition);
                 ::_exit(192);
              }
              if(found.value==-ENOENT)
                 carx_r3d6::note("N54_GUEST_ROOTFS_SOURCE_BOUND_REAL_ENOENT");
              else if(found.value>=101)
                 carx_r3d6::note("N54_GUEST_ROOTFS_READONLY_VIRTUAL_FD_ALLOCATED");
              else
                 carx_r3d6::note("N54_GUEST_ROOTFS_BOUNDED_REAL_NEG_ERRNO");
              state.gregs[FEXCore::X86State::REG_RAX]=uint64_t(found.value);
              state.rip=newRIP;
              ++Seen;
              carx_r3d6::note(
                   "N22_BATCH_RETURN_R3D33_GUEST_ROOTFS_GENERAL_OPENAT");
              return;
            }
            carx_r3d6::note("E_BATCH_GUEST_PATH_CAPTURED_NEEDS_VFS");
            ::_exit(117);''')
# Systematic single Linux ABI dispatch for all opened guest files without
# claiming additional executable source. The original process has already
# source-verified each x86 opcode and mapped all writable guest pages.
s=one(s,
'''          return GuestMaps.owned_writable_range(dst,size) ||
                 carx_r3d18::owned_stack_write_bounds(dst,size);''',
'''          return GuestMaps.owned_writable_range(dst,size) ||
                 carx_r3d18::owned_stack_write_bounds(dst,size) ||
                 carx_r3d33::brk_readable(dst,size,BRKBase,GuestBrkCurrent);''')
s=one(s,
'''        const auto misc=carx_r3d31::source_locked_dispatch(
           number,arg0,arg1,arg2,writeOwnedGuest);''',
'''        // Genuine source-witnessed read-only guest file operations using
        // ONLY fd101..116 allocated by the verified app-private guest
        // rootfs directory walker. POSIX return values are source derived,
        // all host I/O goes through a small local buffer, not guest pointers.
        if(GuestReadOnlyFiles.owns(arg0)){
           int64_t outcome=0;
           switch(number){
             case 0: // read
               if(arg2>4096){
                 carx_r3d6::note("E_R3D33_GUEST_VIRTUAL_READ_EXCEEDS_BOUNDED_BUFFER");
                 ::_exit(193);
               }
               outcome=GuestReadOnlyFiles.read_guest(
                        arg0,arg1,arg2,writeOwnedGuest);break;
             case 17: // pread64: offset is R10
               if(arg2>4096){
                 carx_r3d6::note("E_R3D33_GUEST_VIRTUAL_PREAD_EXCEEDS_BOUNDED_BUFFER");
                 ::_exit(193);
               }
               outcome=GuestReadOnlyFiles.pread_guest(
                        arg0,arg1,arg2,arg3,writeOwnedGuest);break;
             case 5: // Linux x86_64 struct stat 144 bytes
               outcome=GuestReadOnlyFiles.fstat_guest(
                        arg0,arg1,writeOwnedGuest);break;
             case 8: // lseek
               outcome=GuestReadOnlyFiles.lseek_guest(
                        arg0,arg1,arg2);break;
             case 3: // close
               outcome=GuestReadOnlyFiles.close_guest(arg0);break;
             default:
               carx_r3d6::note(
                 "E_R3D33_GUEST_READONLY_VIRTUAL_FD_SYSCALL_UNSUPPORTED");
               ::_exit(194);
           }
           carx_r3d6::note("N55_GUEST_ROOTFS_GENERIC_FILE_OP_SOURCE_VERIFIED");
           accept(outcome,
              "N22_BATCH_RETURN_R3D33_ROOTFS_FD_READ_PREAD_STAT_SEEK_CLOSE");
           return;
        }
        if(number==9 && GuestReadOnlyFiles.owns(arg4)){
          carx_r3d6::note(
              "E_R3D33_ROOTFS_FD_MMAP_REQUIRES_NEW_ELF_SOURCE_PROVENANCE");
          ::_exit(195);
        }
        const auto misc=carx_r3d31::source_locked_dispatch(
           number,arg0,arg1,arg2,writeOwnedGuest);''')
# Add 24 independent tests BEFORE starting the original ELF guest execution.
s=one(s,
'''    carx_r3d6::note("N49_COMBINED_80_INDEPENDENT_PREPARATION_CASES_PASS");
  }
  context->ExecuteThread(thread);''',
'''    carx_r3d6::note("N49_COMBINED_80_INDEPENDENT_PREPARATION_CASES_PASS");
    const auto vmPaths=carx_r3d33::run_preflight24(
        [](const char* marker){carx_r3d6::note(marker);});
    if(!vmPaths.ready()){
      carx_r3d6::note("E_R3D33_GUEST_VM_PATH_PREFLIGHT24_FAILED");
      ::_exit(196);
    }
    carx_r3d6::note("N53_COMBINED_104_INDEPENDENT_PREPARATION_CASES_PASS");
  }
  context->ExecuteThread(thread);''')
assert all(q in s for q in (
  "N53_COMBINED_104_INDEPENDENT_PREPARATION_CASES_PASS",
  "N54_GUEST_OPENAT_PATH_PROVEN_OWNED_BRK",
  "N22_BATCH_RETURN_R3D33_GUEST_ROOTFS_GENERAL_OPENAT",
  "N22_BATCH_RETURN_R3D33_ROOTFS_FD_READ_PREAD_STAT_SEEK_CLOSE",
  "N22_BATCH_RETURN_R3D31_SOURCE_VERIFIED_RANDOM_CLOCK_TIME",
  "N50_GETRANDOM_GUEST_WRITABLE_MMAP_PER_PAGE_ABI_ACCEPTED",
  "N34_SOURCE_DOMAIN_VERIFIED_LIBC_FD100",
  "context->ExecuteThread(thread)"))
cpp.write_text(s)
s=act.read_text()
s=one(s,
'''runCacheless.setText("تشغيل 07H — R3D32 Batch 80 + Wine 512");''',
'''runCacheless.setText("تشغيل 07H — R3D33 Batch 104 + Wine 512");''')
s=one(s,
'''r4.carx.r3d32.integrated-80-preflight-page-mapped-real-fex512.v1''',
'''r4.carx.r3d33.integrated-104-preflight-owned-vm-rootfs-vfs-fex512.v1''')
s=one(s,
'''07H_INTEGRATED_WINE_GNU_LDSO_LIBC_ROOTFS_BATCH80_PAGE_MAPPED_FEX512''',
'''07H_INTEGRATED_WINE_GNU_LDSO_LIBC_ROOTFS_BATCH104_VM_PATH_FEX512''')
s=one(s,
'''07H_R3D32_BATCH80_UNIFIED_SOURCE_WINE_FEX512''',
'''07H_R3D33_BATCH104_UNIFIED_SOURCE_WINE_FEX512''')
s=one(s,
'''p.startsWith("E_R3D31_") || p.startsWith("E_R3D32_"))
              stop=p;''',
'''p.startsWith("E_R3D31_") || p.startsWith("E_R3D32_") ||
             p.startsWith("E_R3D33_"))
              stop=p;''')
s=one(s,
'''        if(stop.startsWith("E_BATCH_UNSUPPORTED_NR_"))''',
'''        if(stop.startsWith("E_R3D33_GUEST_ROOTFS_OPENAT_UNSAFE_STATE_"))
            return "BATCH_HALTED_GUEST_ROOTFS_OPENAT_CONFINE_UNSUPPORTED";
        if(stop.startsWith("E_R3D33_GUEST_VM_PATH_PREFLIGHT24_FAILED"))
            return "BATCH_HALTED_GUEST_VM_PATH_PREFLIGHT_FAILURE";
        if(stop.startsWith("E_R3D33_ROOTFS_FD_MMAP_REQUIRES_NEW_ELF_SOURCE_PROVENANCE"))
            return "BATCH_HALTED_NEW_ELF_IMAGE_SOURCE_PROVENANCE_UNPROVEN";
        if(stop.startsWith("E_R3D33_"))
            return "BATCH_HALTED_UNSUPPORTED_VERIFIED_ROOTFS_FILE_ABI";
        if(stop.startsWith("E_BATCH_UNSUPPORTED_NR_"))''')
s=one(s,
'''        report.put("r3d32_80_preflight_checks_are_not_real_guest_syscalls",true);''',
'''        report.put("r3d32_80_preflight_checks_are_not_real_guest_syscalls",true);
        int pathCases=0,pathPass=0,pathFail=0;
        for(int x=0;x<phases.length();x++){
          String entry=phases.optString(x,"");
          if(entry.contains("_R3D33_GUEST_VM_PATH_CASE_")){
            pathCases++;
            if(entry.startsWith("N53_"))pathPass++;
            else pathFail++;
          }
        }
        report.put("r3d33_guest_vm_path_preflight_count",pathCases);
        report.put("r3d33_guest_vm_path_preflight_passed",pathPass);
        report.put("r3d33_guest_vm_path_preflight_failed",pathFail);
        report.put("r3d33_combined_preflight_count",
          readyTotal+extraTotal+memoryCases+pathCases);
        report.put("r3d33_combined_preflight_passed",
          readyPassed+extraPassed+memoryPassed+pathPass);
        report.put("r3d33_104_preflight_complete",
          readyTotal+extraTotal+memoryCases+pathCases==104 &&
          readyFails+extraFailed+memoryFailed+pathFail==0 &&
          phases.toString().contains(
             "N53_COMBINED_104_INDEPENDENT_PREPARATION_CASES_PASS"));
        report.put("r3d33_guest_brk_openat_path_source_owned",
          phases.toString().contains(
             "N54_GUEST_OPENAT_PATH_PROVEN_OWNED_BRK"));
        report.put("r3d33_guest_mmap_openat_path_source_owned",
          phases.toString().contains(
             "N54_GUEST_OPENAT_PATH_PROVEN_OWNED_MMAP"));
        report.put("r3d33_rootfs_general_openat_original_syscall_handled",
          phases.toString().contains(
             "N22_BATCH_RETURN_R3D33_GUEST_ROOTFS_GENERAL_OPENAT"));
        report.put("r3d33_guest_rootfs_virtual_file_operations_handled",
          phases.toString().contains(
             "N22_BATCH_RETURN_R3D33_ROOTFS_FD_READ_PREAD_STAT_SEEK_CLOSE"));
        report.put("r3d33_guest_rootfs_no_unverified_host_file_forwarding",true);
        report.put("r3d33_guest_rootfs_symlink_traversal_fail_closed",true);
        report.put("r3d33_guest_fd_executable_mmap_requires_elf_source_proof",true);
        report.put("r3d33_104_preflight_cases_are_not_104_x86_syscalls",true);''')
s=one(s,
'''        stages.put("win32_stage_automatically_started",false);''',
'''        stages.put("104_preparation_cases_completed",
          phases.toString().contains(
             "N53_COMBINED_104_INDEPENDENT_PREPARATION_CASES_PASS"));
        stages.put("source_verified_guest_brk_path_read",
          phases.toString().contains(
             "N54_GUEST_OPENAT_PATH_PROVEN_OWNED_BRK"));
        stages.put("verified_rootfs_openat_executed",
          phases.toString().contains(
             "N22_BATCH_RETURN_R3D33_GUEST_ROOTFS_GENERAL_OPENAT"));
        stages.put("win32_stage_automatically_started",false);''')
s=one(s,
'''R3D32 uses real R3D31 device evidence: 64/64 source-independent preflight successes and original x86 GNU/libc callbacks 32 observed, 31 accepted; getrandom318 on a genuine writable libc fixed-overlay guest mmap buffer was incorrectly rejected due to coarse parent RO reservation state. Fixed the ORIGINAL tracked guest mmap registry to record page-granular 4096-byte writable permissions across protected nested MAP_FIXED overlays and partial mprotect, failing closed on unowned, read-only or cross-boundary writes. Expanded the one-device-run 40 rootfs+24 syscall+16 independent page-write protection preflights = 80 tests before original source-verified FEX Wine boot up to 512 x86 Linux syscall witnesses. Real host getrandom uses only a local buffer and bounded verified write to guest mmap. The 80 preflight scenarios are NOT 80 original x86 syscalls; real FEX guest dispatch remains sequential and unknown unsafe shapes still stop. Full Linux guest process ABI, Wine, Windows PE, graphics and CarX boot remain unproven.''',
'''R3D33 uses real R3D32 phone evidence: 80/80 independent preparation checks; x86 source witness index31 real getrandom318 returned 8 bytes, index32 and33 libc brk12 succeeded, then index34 GNU ld.so openat257 path 0x7382E00310 belongs to committed guest brk, NOT the old R3D16-only 64KiB guest stack, causing safe exit118. The new reader validates each byte against source-owned committed guest brk, per-4KiB mmap read rights, or mapped guest stack; it cannot access arbitrary host memory. Rootfs guest openat is confined to app-private source-validated rootfd, O_NOFOLLOW component walker, no unknown symlinks or guest pointer passthrough. It can return real -ENOENT for absent paths or a guest virtual fd101..116 for installed read-only files, with bounded read/pread64/fstat(144B)/lseek/close. It deliberately refuses mmap executable source from new guest files until ELF source-provenance is constructed. Adds 24 independent path/heap cases to prior 80 preflights for total 104 before one real original FEX 512-syscall Wine Linux bootstrap. 104 cases are NOT 104 executed x86 syscalls; full Wine/Linux process bootstrap, Windows PE, graphics/game startup remain unproven.''')
act.write_text(s)
print("R3D33_GUEST_BRK_AND_PAGEWISE_MMAP_PATH_ROOTFS_FD_PROMOTION_SOURCE_PINNED_PASS")
print("R3D33_104_INDEPENDENT_CASES_AND_ONE_FEX_512_GUEST_BATCH_PROTECTED")
