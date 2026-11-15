#!/usr/bin/env python3
"""R3D23 fixes FEX missing RX libc executable-range callback in unified 07H.

Source-pinned FEXCore Decoder::CheckRangeExecutable asks QueryGuestExecutableRange
for EACH x86 instruction byte. R3D22 proves a #PF execution fault at guest
libc RX address after 19 handled Linux syscalls. Legacy handler exposed Wine
and ld.so only, returning {0,0,false} for libc. Register dynamic RX guest
memory in the very SAME existing FEX syscall handler and revoke stale VMA
entries when map/protection changes. Keep the same 512-syscall single report.
No host W+X, unchecked executable address, bypass or fake Wine boot.
"""
from pathlib import Path
import re,sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_guest_executable_vma.py /tmp/carxpc")
app=Path(sys.argv[1]);java=app/"app/src/main/java/com/r4/carxpc"
cpp=app/"app/src/main/cpp/carx_r3d4_first_syscall.cpp"
act=java/"R3D4ProbeActivity.java"; main=java/"MainActivity.java"
gradle=app/"app/build.gradle";store=java/"R3D8JsonReportStore.java"
assert all(x.is_file() for x in (cpp,act,main,gradle,store))
def one(s,a,b):
 c=s.count(a)
 assert c==1,("R3D23_SOURCE_LOCK_ANCHOR_CHANGED",a[:140],c)
 return s.replace(a,b,1)
def reone(s,p,n):
 s,k=re.subn(p,n,s,count=1)
 assert k==1,("R3D23_VERSION_ANCHOR_CHANGED",p,k)
 return s

s=gradle.read_text()
s=reone(s,r"\bversionCode\s+50\b","versionCode 51")
s=reone(s,r"versionName\s+'[^']+'",
  "versionName '0.51-r3d23-source-locked-dynamic-fex-libc-executable-vma'")
gradle.write_text(s)
s=main.read_text()
s=one(s,"10 | R3D22 — إقلاع Wine الموحّد وتشخيص رجوع FEX",
      "10 | R3D23 — إصلاح تنفيذ libc داخل محرك Wine الموحّد")
main.write_text(s)
s=store.read_text()
s=one(s,'"CarX_PC_R3D22_FEXReturn_Diagnostics_"',
      '"CarX_PC_R3D23_FEXExecLibc_Diagnostics_"')
store.write_text(s)

s=cpp.read_text()
s=one(s,
'''#include "carxpc/r3d22/native/postexecute_guest_snapshot.hpp"''',
'''#include "carxpc/r3d22/native/postexecute_guest_snapshot.hpp"
#include "carxpc/r3d23/native/bounded_guest_executable_vma.hpp"''')
s=one(s,
'''  carx_r3d19::GuestMappings GuestMaps{};''',
'''  carx_r3d19::GuestMappings GuestMaps{};
  carx_r3d23::BoundedExecVMAs ExecVMAs{};
  bool DynamicExecQueryLogged{false};''')
# This is the actual upstream pinned FEXCore decoder's authoritative
# executable region query, not a host-executable mapping permission bypass.
s=one(s,
'''    if (address>=LdsoBase && address-LdsoBase<LdsoLength)
      return {LdsoBase,LdsoLength,false};
    return {0,0,false};
  }
  std::optional<FEXCore::ExecutableFileSectionInfo>''',
'''    if (address>=LdsoBase && address-LdsoBase<LdsoLength)
      return {LdsoBase,LdsoLength,false};
    if(Mode==4) {
      const auto vma=ExecVMAs.find(address);
      if(vma.length) {
        if(!DynamicExecQueryLogged){
          DynamicExecQueryLogged=true;
          carx_r3d6::note("N32_FEX_DYNAMIC_RX_EXECUTABLE_VMA_QUERY_ACCEPTED");
          char trace[120]{};
          std::snprintf(trace,sizeof(trace),"N32_FEX_DYNAMIC_RX_TARGET_%016llX",
             static_cast<unsigned long long>(address));
          carx_r3d6::note(trace);
          std::snprintf(trace,sizeof(trace),"N32_FEX_DYNAMIC_RX_REGION_BASE_%016llX",
             static_cast<unsigned long long>(vma.base));
          carx_r3d6::note(trace);
          std::snprintf(trace,sizeof(trace),"N32_FEX_DYNAMIC_RX_REGION_SIZE_%016llX",
             static_cast<unsigned long long>(vma.length));
          carx_r3d6::note(trace);
        }
        return {vma.base,vma.length,false};
      }
    }
    return {0,0,false};
  }
  std::optional<FEXCore::ExecutableFileSectionInfo>''')
# Register RX only after the host mmap succeeded and a managed guest mapping
# exists. On any map, erase stale overlaps with read/write/unmapped memory.
s=one(s,
'''          std::snprintf(msg,sizeof(msg),"N28_MMAP_GUEST_ADDRESS_%016llX",''',
'''          uint64_t trackedMapLength=0;
          if(!carx_r3d19::checked_round_page(arg1,trackedMapLength) ||
             !ExecVMAs.replace_permissions(uint64_t(mapped),
                trackedMapLength,(arg2&PROT_EXEC)!=0)) {
            carx_r3d6::note("E_R3D23_MMAP_RX_VMA_REGISTRATION_FAILED");
            ::_exit(161);
          }
          if((arg2&PROT_EXEC)!=0) {
            carx_r3d6::note("N32_GUEST_LIBC_RX_MMAP_REGISTERED_FOR_FEX");
          }
          std::snprintf(msg,sizeof(msg),"N28_MMAP_GUEST_ADDRESS_%016llX",''')
s=one(s,
'''          accept(0,"N22_BATCH_RETURN_R3D19_MPROTECT_OWNED_GUEST");''',
'''          uint64_t trackedProtectLength=0;
          if(!carx_r3d19::checked_round_page(arg1,trackedProtectLength) ||
             !ExecVMAs.replace_permissions(arg0,trackedProtectLength,
                                           (arg2&PROT_EXEC)!=0)) {
            carx_r3d6::note("E_R3D23_MPROTECT_RX_VMA_REGISTRATION_FAILED");
            ::_exit(162);
          }
          accept(0,"N22_BATCH_RETURN_R3D19_MPROTECT_OWNED_GUEST");''')
s=one(s,
'''          accept(0,"N22_BATCH_RETURN_R3D19_MUNMAP_OWNED_GUEST");''',
'''          uint64_t trackedUnmapLength=0;
          if(!carx_r3d19::checked_round_page(arg1,trackedUnmapLength) ||
             !ExecVMAs.replace_permissions(arg0,trackedUnmapLength,false)) {
            carx_r3d6::note("E_R3D23_MUNMAP_RX_VMA_REVOKE_FAILED");
            ::_exit(163);
          }
          accept(0,"N22_BATCH_RETURN_R3D19_MUNMAP_OWNED_GUEST");''')
assert all(x in s for x in [
 "N32_FEX_DYNAMIC_RX_EXECUTABLE_VMA_QUERY_ACCEPTED",
 "N32_GUEST_LIBC_RX_MMAP_REGISTERED_FOR_FEX",
 "E_R3D23_MMAP_RX_VMA_REGISTRATION_FAILED",
 "N22_BATCH_RETURN_R3D21_RSEQ_NEG_ENOSYS",
 "E_R3D22_FEX_EXECUTE_RETURN_NO_NEW_X86_SYSCALL",
 "context->ExecuteThread(thread)",
 "return {vma.base,vma.length,false};"])
cpp.write_text(s)

s=act.read_text()
s=one(s,
'''runCacheless.setText("تشغيل 07H — R3D22 Wine + FEX Return Trace");''',
'''runCacheless.setText("تشغيل 07H — R3D23 Wine + FEX Exec libc");''')
s=one(s,'"r4.carx.r3d22.integrated-wine-fex-return-provenance.v1"',
      '"r4.carx.r3d23.integrated-wine-fex-libc-executable-vma.v1"')
s=one(s,'"07H_INTEGRATED_WINE_GNU_LDSO_LINUX_ABI_TLS_THREADS_FEX_RETURN"',
      '"07H_INTEGRATED_WINE_GNU_LDSO_LINUX_ABI_TLS_THREADS_FEX_LIBC_EXEC"')
s=one(s,'"07H_R3D22_UNIFIED_WINE_FEX_RETURN_BATCH_512"',
      '"07H_R3D23_UNIFIED_WINE_FEX_LIBC_EXEC_BATCH_512"')
s=one(s,
'''        report.put("r3d22_guest_rip_may_be_stale_after_jit",true);''',
'''        report.put("r3d22_guest_rip_may_be_stale_after_jit",true);
        report.put("r3d23_fex_dynamic_executable_vma_code_integrated",true);
        report.put("r3d23_rx_guest_libc_mmap_registered",
          phases.toString().contains("N32_GUEST_LIBC_RX_MMAP_REGISTERED_FOR_FEX"));
        report.put("r3d23_fex_dynamic_rx_query_accepted",
          phases.toString().contains(
            "N32_FEX_DYNAMIC_RX_EXECUTABLE_VMA_QUERY_ACCEPTED"));
        report.put("r3d23_no_untracked_guest_address_executable",true);
        report.put("r3d23_first_dynamic_rx_guest_target_verified_from_runtime",
          phases.toString().contains("N32_FEX_DYNAMIC_RX_TARGET_"));''')
s=one(s,
'''        stages.put("fex_return_requires_diagnosis",phases.toString().contains(
           "E_R3D22_FEX_EXECUTE_RETURN_NO_NEW_X86_SYSCALL"));''',
'''        stages.put("fex_return_requires_diagnosis",phases.toString().contains(
           "E_R3D22_FEX_EXECUTE_RETURN_NO_NEW_X86_SYSCALL"));
        stages.put("fex_libc_rx_region_registered",phases.toString().contains(
           "N32_GUEST_LIBC_RX_MMAP_REGISTERED_FOR_FEX"));
        stages.put("fex_dynamic_rx_decoder_query_accepted",phases.toString().contains(
           "N32_FEX_DYNAMIC_RX_EXECUTABLE_VMA_QUERY_ACCEPTED"));''')
s=one(s,
'''R3D22 preserves the same unified 512-source-witnessed R3D19-R3D21 guest Linux/Wine loader, now diagnosing a post-rseq -ENOSYS FEX ExecuteThread return without a twentieth original x86 syscall. Captures postexecute x86 CPUState RIP/RAX/RSP/FS and FEX synchronous fault flags read-only; reported RIP/fault fields MAY BE STALE and do not alone establish cause. No extra syscalls are faked or forwarded and no unverified restart occurs. The 19 acknowledged calls were not Wine boot; complete Linux VFS, signals, futex and Wine/PE/DXVK/game remain unproven.''',
'''R3D23 repairs the unified FEX x86 decoder executable range callback for RX guest libc mmap segments. R3D22 last guest RIP was within libc RX mapping and had SIGSEGV/SEGV_ACCERR/#PF instruction-fetch bit 0x15, while the original handler only exposed Wine+ld.so ranges. R3D23 reports bounded, source-locked dynamic guest RX VMAs from successful mmap and mprotect; revokes execute upon non-RX map, mprotect and munmap. Unknown/unmapped guest pointers still fail closed; no host W+X or fake syscall success. Result must be verified on ARM64; full Wine/PE/graphics still unproven.''')
act.write_text(s)
print("R3D23_FEX_DYNAMIC_LIBC_GUEST_RX_QUERY_INTEGRATED_WINE_BOOTSTRAP_PASS")
print("R3D23_REGISTER_ONLY_SUCCESSFUL_KERNEL_VMA_AND_REVOKE_ON_PROT_CHANGE_PASS")
