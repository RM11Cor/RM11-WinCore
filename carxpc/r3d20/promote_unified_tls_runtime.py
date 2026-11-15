#!/usr/bin/env python3
"""R3D20: extend the SAME unified 07H Wine Linux ABI bootstrap with guest TLS.

The source-verified original x86 arch_prctl(158) sets FEX guest CPUState
fs_cached/gs_cached; guest FS base must lie within our own mmap-managed
guest range. Never alter Android host TLS. All previous bounded libc and VM
syscalls remain in one 512-witness run, plus grouped machine-readable report.
Full Wine/PE boot remains separately unproven.
"""
from pathlib import Path
import re,sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_unified_tls_runtime.py /tmp/carxpc")
app=Path(sys.argv[1]);java=app/"app/src/main/java/com/r4/carxpc"
cpp=app/"app/src/main/cpp/carx_r3d4_first_syscall.cpp"
act=java/"R3D4ProbeActivity.java";service=java/"R3D4ProbeService.java"
main=java/"MainActivity.java";gradle=app/"app/build.gradle"
store=java/"R3D8JsonReportStore.java"
assert all(x.is_file() for x in (cpp,act,service,main,gradle,store))
def one(s,a,b):
 n=s.count(a)
 assert n==1,("R3D20_PINNED_SOURCE_ANCHOR_CHANGED",a[:110],n)
 return s.replace(a,b,1)
def reone(s,p,new):
 s,n=re.subn(p,new,s,count=1)
 assert n==1,("R3D20_REGEX_ANCHOR_CHANGED",p,n)
 return s

s=gradle.read_text()
s=reone(s,r"\bversionCode\s+47\b","versionCode 48")
s=reone(s,r"versionName\s+'[^']+'",
    "versionName '0.48-r3d20-unified-wine-linux-abi-guest-tls'")
gradle.write_text(s)
s=main.read_text()
s=one(s,"10 | R3D19 — منظومة Linux ABI المجمّعة لإقلاع Wine",
      "10 | R3D20 — محرك Wine Linux ABI الموحّد وTLS")
main.write_text(s)
s=store.read_text()
s=one(s,'"CarX_PC_R3D19_UnifiedWineBoot_Diagnostics_"',
      '"CarX_PC_R3D20_UnifiedWineTLS_Diagnostics_"')
store.write_text(s)

s=cpp.read_text()
s=one(s,
'''#include "carxpc/r3d19/native/unified_guest_libc_abi.hpp"''',
'''#include "carxpc/r3d19/native/unified_guest_libc_abi.hpp"
#include "carxpc/r3d20/native/guest_fs_gs_tls.hpp"''')
# Place TLS inside integrated ABI dispatch, not a separate one-syscall probe.
anchor=r'''        if(number==17 && arg0==libcFd && LibcGuestOpen) { // pread64'''
inject=r'''        if(number==158) { // Linux x86-64 arch_prctl TLS
          const auto ownsGuest=[this](uint64_t address,uint64_t length) {
            return GuestMaps.owned_range(address,length);
          };
          const auto answer=carx_r3d20::dispatch_arch_prctl(
              state,arg0,arg1,ownsGuest);
          if(!answer.recognized) {
            carx_r3d6::note("E_R3D20_ARCH_PRCTL_CONTROL_UNSUPPORTED");
            ::_exit(141);
          }
          if(answer.returnValue!=0) {
            carx_r3d6::note("E_R3D20_ARCH_PRCTL_GUEST_BASE_OR_POINTER_UNSAFE");
            ::_exit(142);
          }
          if(answer.fsChanged) {
            if(state.fs_cached!=arg1) {
              carx_r3d6::note("E_R3D20_FEX_GUEST_FS_CPUSTATE_MISMATCH");
              ::_exit(143);
            }
            std::snprintf(msg,sizeof(msg),
              "N29_ARCH_SET_FS_GUEST_BASE_%016llX",
              static_cast<unsigned long long>(state.fs_cached));
            carx_r3d6::note(msg);
            carx_r3d6::note("N29_FEX_GUEST_FS_BASE_OWNED_VM_VERIFIED");
            accept(0,"N22_BATCH_RETURN_R3D20_ARCH_SET_FS_GUEST_CPUSTATE");
            return;
          }
          if(answer.gsChanged) {
            carx_r3d6::note("N29_FEX_GUEST_GS_BASE_OWNED_VM_VERIFIED");
            accept(0,"N22_BATCH_RETURN_R3D20_ARCH_SET_GS_GUEST_CPUSTATE");
            return;
          }
          accept(0,"N22_BATCH_RETURN_R3D20_ARCH_GET_FS_GS_GUEST_CPUSTATE");
          return;
        }
'''
s=one(s,anchor,inject+anchor)
assert all(x in s for x in [
 "N29_FEX_GUEST_FS_BASE_OWNED_VM_VERIFIED",
 "N22_BATCH_RETURN_R3D20_ARCH_SET_FS_GUEST_CPUSTATE",
 "GuestMaps.owned_range(address,length)",
 "N22_BATCH_RETURN_R3D19_MMAP_OWNED_GUEST",
 "N22_BATCH_RETURN_R3D19_PREAD64_REAL_LIBC",
 "context->ExecuteThread(thread)"])
cpp.write_text(s)

s=act.read_text()
s=one(s,
'''runCacheless.setText("تشغيل 07H — R3D19 Linux ABI + Wine Bootstrap");''',
'''runCacheless.setText("تشغيل 07H — R3D20 Wine ABI + TLS موحّد");''')
s=one(s,'"r4.carx.r3d19.integrated-wine-linux-abi-bootstrap.v1"',
      '"r4.carx.r3d20.integrated-wine-linux-abi-guest-tls.v1"')
s=one(s,'"07H_INTEGRATED_WINE_GNU_LDSO_LINUX_ABI_BOOTSTRAP"',
      '"07H_INTEGRATED_WINE_GNU_LDSO_LINUX_ABI_TLS"')
s=one(s,'"07H_R3D19_INTEGRATED_WINE_BOOTSTRAP_BATCH_512"',
      '"07H_R3D20_UNIFIED_WINE_GUEST_TLS_BATCH_512"')
s=one(s,'''        report.put("r3d19_original_wine_loader_progress_only",true);''',
'''        report.put("r3d19_original_wine_loader_progress_only",true);
        final boolean tlsFsSet=phases.toString().contains(
          "N22_BATCH_RETURN_R3D20_ARCH_SET_FS_GUEST_CPUSTATE") &&
          phases.toString().contains("N29_FEX_GUEST_FS_BASE_OWNED_VM_VERIFIED");
        report.put("r3d20_guest_fs_tls_initialized",tlsFsSet);
        report.put("r3d20_guest_tls_arch_prctl_via_fex_cpustate",true);
        String fsBase=null;
        int maps=0, reads=0;
        for(int i=0;i<phases.length();++i){
          String v=phases.optString(i,"");
          if(v.startsWith("N29_ARCH_SET_FS_GUEST_BASE_"))
            fsBase=v.substring("N29_ARCH_SET_FS_GUEST_BASE_".length());
          if(v.equals("N22_BATCH_RETURN_R3D19_MMAP_OWNED_GUEST"))maps++;
          if(v.equals("N22_BATCH_RETURN_R3D19_PREAD64_REAL_LIBC"))reads++;
        }
        if(tlsFsSet && (fsBase==null || !fsBase.matches("[0-9A-F]{16}")))
          return "R3D20_REJECTED_TLS_PROVENANCE_INCOMPLETE";
        report.put("r3d20_guest_fs_base_hex",fsBase==null?"UNSET":fsBase);
        JSONObject stages=new JSONObject();
        stages.put("guest_rootfs_verified",phases.toString().contains(
          "J3_ROOTFS_PRESENT"));
        stages.put("original_wine_and_ldso_verified",phases.toString().contains(
          "J5_WINE_SHA256_VERIFIED") && phases.toString().contains(
          "J6_LDSO_SHA256_VERIFIED"));
        stages.put("guest_libc_opened",phases.toString().contains(
          "N22_BATCH_RETURN_OPENAT_LIBC_FD100"));
        stages.put("guest_libc_first_read832",readLibcVerified);
        stages.put("libc_pread64_count",reads);
        stages.put("libc_mmap_count",maps);
        stages.put("guest_tls_fs_base_initialized",tlsFsSet);
        stages.put("full_linux_process_abi",false);
        stages.put("wine_process_booted",false);
        stages.put("win64_pe_started",false);
        stages.put("graphics_started",false);
        report.put("r3d20_unified_bootstrap_stages",stages);''')
# old R3D18 property was stale even after R3D19 implemented fstat+mmap.
s=one(s,'''            report.put("batch_libc_fstat_mmap_implemented",false);''',
'''            report.put("batch_libc_fstat_mmap_implemented",
                currentProbeMode==4 &&
                phases.toString().contains(
                  "N22_BATCH_RETURN_R3D19_FSTAT_X64_144") &&
                phases.toString().contains(
                  "N22_BATCH_RETURN_R3D19_MMAP_OWNED_GUEST"));''')
s=one(s,
'''R3D19 integrated one-APK source-locked diagnostic bootstrap: authentic GNU ld.so x86 Linux syscall journal up to 512 witnesses; bounded rootfs libc guest FD100 read and pread64 R10, x86 fstat, owned private mmap/protection/unmapping, brk heap growth and lseek. All unsupported or unsafe requests stop in child process. This does not implement the whole Linux rootfs VFS, process/thread/signal/TLS system, all Wine dependencies, full Wine boot, Windows PE, DXVK, Vulkan or game launch.''',
'''R3D20 integrates FEX x86 guest TLS arch_prctl ARCH_SET_FS/GS, GET_FS/GS with R3D19 source-locked Linux ABI and 512-event journal in one APK. Linux FS/GS bases update guest CPUState only and require owned guest mapped memory; host ARM64 TLS stays untouched. Unknown/unsafe operations stop with journal. This is not complete Linux process/thread/signal/VFS, Wine or Windows PE boot, DXVK, Vulkan or CarX gameplay.''')
act.write_text(s)
print("R3D20_UNIFIED_WINE_LINUX_ABI_FEX_GUEST_TLS_SOURCE_PROMOTION_PASS")
print("R3D20_X86_FS_BASE_STATE_IS_NOT_HOST_ARM64_TLS_AND_NO_UNKNOWN_HOST_FORWARDING")
