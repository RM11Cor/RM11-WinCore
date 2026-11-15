#!/usr/bin/env python3
"""R3D30: replace path-by-path guest readlink fixes with a source-rootfs VFS,
a 40-case independent *preflight* matrix, six preimplemented identity
syscalls, and one retained 512-source-witness live x86 FEX/Wine run.

The 40-case batch runs independently of dependent guest syscalls. It collects
multiple errors before deciding whether to start FEX. It is NOT 40 executed
guest calls. The authentic guest then runs sequentially, with unknown x86
syscalls or unresolved guest symlinks fail-closed. No fake Linux success, no
host forwarding, and NO claim of full Wine/Windows PE/game boot.
"""
from pathlib import Path
import re,sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_batched_rootfs_vfs.py /tmp/carxpc")
app=Path(sys.argv[1]);java=app/"app/src/main/java/com/r4/carxpc"
cpp=app/"app/src/main/cpp/carx_r3d4_first_syscall.cpp"
service=java/"R3D4ProbeService.java";act=java/"R3D4ProbeActivity.java"
main=java/"MainActivity.java";gradle=app/"app/build.gradle"
store=java/"R3D8JsonReportStore.java"
assert all(x.is_file() for x in (cpp,service,act,main,gradle,store))
def one(s,a,n):
 count=s.count(a)
 assert count==1,("R3D30_PINNED_SOURCE_ANCHOR_CHANGED",a[:150],count)
 return s.replace(a,n,1)
def reone(s,pattern,repl):
 s,n=re.subn(pattern,repl,s,count=1)
 assert n==1,("R3D30_REGEX_SOURCE_ANCHOR_CHANGED",pattern,n)
 return s
s=gradle.read_text()
s=reone(s,r"\bversionCode\s+57\b","versionCode 58")
s=reone(s,r"versionName\s+'[^']+'",
 "versionName '0.58-r3d30-batched-40-case-rootfs-vfs-and-identity'")
gradle.write_text(s)
s=main.read_text()
s=one(s,"10 | R3D29 — معالجة مجلدات Wine للضيف",
      "10 | R3D30 — فحص مجمّع وتهيئة Wine")
main.write_text(s)
s=store.read_text()
s=one(s,'"CarX_PC_R3D29_WineUsrPaths_Diagnostics_"',
      '"CarX_PC_R3D30_BatchedVFS_Diagnostics_"')
store.write_text(s)

# Open a source-installed, Android app-private guest rootfs directory once.
# JNI receives only a verified open *directory fd*, no path string pointer
# or unchecked Android/host arbitrary path. Close it in existing finally.
s=service.read_text()
s=one(s,
'''        long sessionNonce, int traceFd, int progressFd, int probeMode,
        int libcReadonlyFd);''',
'''        long sessionNonce, int traceFd, int progressFd, int probeMode,
        int libcReadonlyFd,int guestRootfsDirectoryFd);''')
s=one(s,
'''            int libcReadonlyFd = -1;''',
'''            int libcReadonlyFd = -1;
            int guestRootfsDirectoryFd = -1;''')
s=one(s,
'''                    phase("J3D_R3D17_LIBC_ROOTFS_READONLY_FD_VERIFIED");''',
'''                    phase("J3D_R3D17_LIBC_ROOTFS_READONLY_FD_VERIFIED");
                    final Path isolatedRoot=root.toRealPath();
                    if(!Files.isDirectory(isolatedRoot,LinkOption.NOFOLLOW_LINKS)
                       || Files.isSymbolicLink(isolatedRoot)){
                        phase("E_R3D30_UNTRUSTED_SOURCE_ROOTFS_DIRECTORY");
                        return;
                    }
                    final ParcelFileDescriptor readOnlyGuestRoot=
                      ParcelFileDescriptor.open(isolatedRoot.toFile(),
                                               ParcelFileDescriptor.MODE_READ_ONLY);
                    guestRootfsDirectoryFd=readOnlyGuestRoot.detachFd();
                    readOnlyGuestRoot.close();
                    phase("J40_APP_PRIVATE_GUEST_ROOTFS_DIRECTORY_FD_READY");''')
s=one(s,
'''                    plan.stackRSP, nonce, rawFd, progressFd, probeMode,
                    libcReadonlyFd);''',
'''                    plan.stackRSP, nonce, rawFd, progressFd, probeMode,
                    libcReadonlyFd,guestRootfsDirectoryFd);''')
s=one(s,
'''                if (libcReadonlyFd >= 0) {''',
'''                if (guestRootfsDirectoryFd >= 0) {
                    try { ParcelFileDescriptor.adoptFd(guestRootfsDirectoryFd).close(); }
                    catch (Throwable ignored) {}
                }
                if (libcReadonlyFd >= 0) {''')
service.write_text(s)

s=cpp.read_text()
s=one(s,
'''#include "carxpc/r3d29/native/source_verified_usr_components.hpp"''',
'''#include "carxpc/r3d29/native/source_verified_usr_components.hpp"
#include "carxpc/r3d30/native/guest_rootfs_readlink.hpp"
#include "carxpc/r3d30/native/batch_preflight.hpp"
#include "carxpc/r3d30/native/source_locked_guest_identity.hpp"''')
s=one(s,
'''int traceFd,uint64_t nonce,uint64_t brkBase,int mode,int libcFd)''',
'''int traceFd,uint64_t nonce,uint64_t brkBase,int mode,int libcFd,
                      int guestRootfsDirFd)''')
s=one(s,
'''BRKBase(brkBase),Mode(mode),LibcHostFD(libcFd) {''',
'''BRKBase(brkBase),Mode(mode),LibcHostFD(libcFd),
    GuestRootfsDirFD(guestRootfsDirFd) {''')
s=one(s,
'''  int LibcHostFD{-1};''',
'''  int LibcHostFD{-1};
  int GuestRootfsDirFD{-1};''')
s=one(s,
'''    traceFd,nonce,brkHeap.base(),mode,libcFd};''',
'''    traceFd,nonce,brkHeap.base(),mode,libcFd,guestRootfsDirFd};''')
# These two wrappers are the JNI source-pinned launch and worker entry.
# Match their precise signatures, not arbitrary occurrences of "libcFd".
s,n=re.subn(
 r"(int traceFd,uint64_t nonce,int mode,int libcFd)(,\s*std::string\s*&\s*\w+\s*\)\s*\{)",
 r"\1,int guestRootfsDirFd\2",s)
assert n==1,("R3D30_LAUNCH_WRAPPER_SIGNATURE",n)
s,n=re.subn(
 r"(uint64_t rsp,int traceFd,uint64_t nonce,int mode,int libcFd)(,\s*std::string\s*&\s*\w+\s*\)\s*\{)",
 r"\1,int guestRootfsDirFd\2",s)
assert n==1,("R3D30_RUN_WRAPPER_SIGNATURE",n)
s=one(s,
'''we,le,ldso,wine,traceFd,nonce,mode,libcFd,message)){''',
'''we,le,ldso,wine,traceFd,nonce,mode,libcFd,
             guestRootfsDirFd,message)){''')
s=one(s,
'''jint progressFd,jint probeMode,jint libcReadonlyFd){''',
'''jint progressFd,jint probeMode,jint libcReadonlyFd,
  jint guestRootfsDirectoryFd){''')
s=one(s,
'''int(traceFd),uint64_t(nonce),int(probeMode),
                             int(libcReadonlyFd),msg);''',
'''int(traceFd),uint64_t(nonce),int(probeMode),
                             int(libcReadonlyFd),
                             int(guestRootfsDirectoryFd),msg);''')

# Independent, pre-FEX readiness suite (40 cases) logs ALL test results even
# when more than one mandatory rootfs path is broken. No witness is added:
# these are metadata/preflight tests, not alleged x86 syscall executions.
s=one(s,
'''  context->ExecuteThread(thread);''',
'''  if(mode==4){
    const auto preflight=carx_r3d30::run_matrix(
      guestRootfsDirFd,[](const char* marker){carx_r3d6::note(marker);});
    if(!preflight.ready()){
      carx_r3d6::note("E_R3D30_PREFLIGHT_MANDATORY_ROOTFS_CASES_FAILED");
      ::_exit(185);
    }
    carx_r3d6::note("N40_PREFLIGHT_40_CASES_COMPLETED_BEFORE_REAL_FEX");
  }
  context->ExecuteThread(thread);''')
# Proactively handle six standard isolated-worker Linux ABI identity calls
# if the authentic guest reaches them. They are NOT synthetic guest witnesses
# or claims of actual execution until recorded from original ELF callbacks.
s=one(s,
'''        if(number==carx_r3d27::kLinuxX86Readlink) {''',
'''        // Source-locked x86 identity ABI: six standard no-pointer syscalls.
        const carx_r3d30::GuestIdentity identity{
          uint64_t(::getpid()),uint64_t(::syscall(SYS_gettid)),
          uint64_t(::getuid()),uint64_t(::getgid())};
        const auto idResult=carx_r3d30::handle_identity(number,identity);
        if(idResult.handled){
          char identityLog[128]{};
          std::snprintf(identityLog,sizeof(identityLog),
               "N41_X86_GUEST_IDENTITY_NR_%llu_VALUE_%llu",
               static_cast<unsigned long long>(number),
               static_cast<unsigned long long>(idResult.value));
          carx_r3d6::note(identityLog);
          accept(static_cast<int64_t>(idResult.value),
                "N22_BATCH_RETURN_R3D30_SOURCE_LOCKED_GUEST_IDENTITY");
          return;
        }
        if(number==carx_r3d27::kLinuxX86Readlink) {''')
# Generic metadata-driven VFS, BEFORE the old per-path shims. These are
# retained as procfs overlays and fallback only for uncommon guest paths.
s=one(s,
'''          const auto wineDir=carx_r3d29::query_readlink_non_symlink(
              observed,arg1,arg2,stackLow,stackHigh,
              PresealedWineVerified);''',
'''          // /proc and /proc/... remain guest-process procfs overlays.
          // Everything else is inspected INSIDE the original installed Wine
          // rootfs via a verified pre-opened directory FD. No host /usr path.
          const bool guestProcfs=std::strcmp(observed,"/proc")==0 ||
              std::strncmp(observed,"/proc/",6)==0;
          if(!guestProcfs){
            const auto file=carx_r3d30::resolve_readlink(
                 GuestRootfsDirFD,observed,arg1,arg2,stackLow,stackHigh);
            if(file.status==carx_r3d30::Status::Resolved){
              carx_r3d6::note("N42_GUEST_ROOTFS_REAL_FILE_TYPE_DISPATCH");
              if(file.value==-int64_t(EINVAL))
                carx_r3d6::note("N42_ROOTFS_REGULAR_OR_DIRECTORY_READLINK_EINVAL");
              else if(file.value==-int64_t(ENOENT))
                carx_r3d6::note("N42_ROOTFS_MISSING_FILE_READLINK_ENOENT");
              else if(file.value>=0)
                carx_r3d6::note("N42_ROOTFS_TRUE_SYMLINK_CONTENT_RETURNED");
              accept(file.value,"N22_BATCH_RETURN_R3D30_GENERIC_ROOTFS_VFS_READLINK");
              return;
            }
            if(file.status==carx_r3d30::Status::IntermediateSymlink){
              carx_r3d6::note("E_R3D30_ROOTFS_INTERMEDIATE_SYMLINK_NEEDS_VIRTUAL_RESOLUTION");
              ::_exit(186);
            }
            carx_r3d6::note("E_R3D30_GUEST_ROOTFS_VFS_UNVERIFIED_OR_UNOWNED");
            ::_exit(187);
          }
          const auto wineDir=carx_r3d29::query_readlink_non_symlink(
              observed,arg1,arg2,stackLow,stackHigh,
              PresealedWineVerified);''')
assert all(x in s for x in (
 'N40_PREFLIGHT_40_CASES_COMPLETED_BEFORE_REAL_FEX',
 'N22_BATCH_RETURN_R3D30_GENERIC_ROOTFS_VFS_READLINK',
 'N22_BATCH_RETURN_R3D30_SOURCE_LOCKED_GUEST_IDENTITY',
 'E_R3D30_ROOTFS_INTERMEDIATE_SYMLINK_NEEDS_VIRTUAL_RESOLUTION',
 'N34_SOURCE_DOMAIN_VERIFIED_LIBC_FD100',
 'N22_BATCH_RETURN_R3D26_PRLIMIT64_OWNED_GUEST_STACK',
 'context->ExecuteThread(thread)'))
cpp.write_text(s)

s=act.read_text()
s=one(s,
'''runCacheless.setText("تشغيل 07H — R3D29 Wine + /usr readlink");''',
'''runCacheless.setText("تشغيل 07H — R3D30 Batch 40 + Wine 512");''')
s=one(s,
'''r4.carx.r3d29.integrated-guest-wine-usr-directory-readlink.v1''',
'''r4.carx.r3d30.integrated-batched-40-case-rootfs-vfs-and-fex512.v1''')
s=one(s,
'''07H_INTEGRATED_WINE_GNU_LDSO_LIBC_WINE_USR_DIRECTORY_READLINK''',
'''07H_INTEGRATED_WINE_GNU_LDSO_LIBC_ROOTFS_VFS_BATCH40_FEX512''')
s=one(s,
'''07H_R3D29_UNIFIED_WINE_GUEST_USR_READLINK_BATCH_512''',
'''07H_R3D30_BATCHED_PREFLIGHT40_UNIFIED_WINE_FEX512''')
s=one(s,
'''if(p.startsWith("E_BATCH_") || p.startsWith("E_R3D22_") ||
             p.startsWith("E_R3D25_") || p.startsWith("E_R3D27_") ||
             p.startsWith("E_R3D29_"))
              stop=p;''',
'''if(p.startsWith("E_BATCH_") || p.startsWith("E_R3D22_") ||
             p.startsWith("E_R3D25_") || p.startsWith("E_R3D27_") ||
             p.startsWith("E_R3D29_") || p.startsWith("E_R3D30_"))
              stop=p;''')
s=one(s,
'''        report.put("r3d29_guest_host_path_readlink_forwarded",false);''',
'''        report.put("r3d29_guest_host_path_readlink_forwarded",false);
        int readyTotal=0,readyPassed=0,readyFails=0,readyOptional=0;
        for(int x=0;x<phases.length();x++){
            String p=phases.optString(x,"");
            if(p.contains("_R3D30_PREFLIGHT_CASE_")){
                readyTotal++;
                if(p.startsWith("N40_"))readyPassed++;
                else if(p.startsWith("E_"))readyFails++;
                else if(p.startsWith("W40_"))readyOptional++;
            }
        }
        report.put("r3d30_preflight_scenario_count",readyTotal);
        report.put("r3d30_preflight_scenario_passed",readyPassed);
        report.put("r3d30_preflight_mandatory_failures",readyFails);
        report.put("r3d30_preflight_optional_unavailable",readyOptional);
        report.put("r3d30_preflight_ready_for_authentic_fex",
          readyTotal==40&&readyFails==0&&
          phases.toString().contains(
             "N40_PREFLIGHT_40_CASES_COMPLETED_BEFORE_REAL_FEX"));
        report.put("r3d30_generic_rootfs_vfs_readlink_handled",
          phases.toString().contains(
             "N22_BATCH_RETURN_R3D30_GENERIC_ROOTFS_VFS_READLINK"));
        report.put("r3d30_guest_identity_dispatch_handled",
          phases.toString().contains(
             "N22_BATCH_RETURN_R3D30_SOURCE_LOCKED_GUEST_IDENTITY"));
        report.put("r3d30_prepared_guest_identity_syscalls",
          "getpid39,getuid102,getgid104,geteuid107,getegid108,gettid186");
        report.put("r3d30_mandatory_first_stage",
          "AUTHENTIC_WINE_LINUX_BOOTSTRAP_REQUIRED");
        report.put("r3d30_win32_auto_stage_eligible",
          phases.toString().contains(
             "N43_REAL_WINE_LINUX_BOOT_COMPLETED") &&
          phases.toString().contains(
             "N43_WIN32_PE_LAUNCH_BRIDGE_READY"));
        report.put("r3d30_win32_auto_stage_unimplemented_until_real_boot",true);
        report.put("r3d30_preflight_scenarios_not_real_guest_syscalls",true);
        report.put("r3d30_guest_paths_passed_to_host_kernel_without_rootfs_confinement",false);''')
s=one(s,
'''        stages.put("guest_wine_rootfs_usr_directory_readlink_nonlink",
          phases.toString().contains(
            "N38_EXACT_ORIGINAL_GUEST_READLINK_USR_DIRECTORY") &&
          phases.toString().contains(
            "N22_BATCH_RETURN_R3D29_WINE_USR_DIR_NEG_EINVAL"));''',
'''        stages.put("guest_wine_rootfs_usr_directory_readlink_nonlink",
          phases.toString().contains(
            "N38_EXACT_ORIGINAL_GUEST_READLINK_USR_DIRECTORY") &&
          phases.toString().contains(
            "N22_BATCH_RETURN_R3D29_WINE_USR_DIR_NEG_EINVAL"));
        stages.put("batch_40_preflight_cases_executed",
          phases.toString().contains(
            "N40_PREFLIGHT_40_CASES_COMPLETED_BEFORE_REAL_FEX"));
        stages.put("guest_rootfs_vfs_generalized_readlink_source_executed",
          phases.toString().contains(
            "N22_BATCH_RETURN_R3D30_GENERIC_ROOTFS_VFS_READLINK"));
        stages.put("win32_stage_automatically_started",false);''')
s=one(s,
'''R3D29 preserves all R3D28 source-verified 28 original GNU/ELF/libc x86 syscall records and 27 accepted Linux guest responses. In actual R3D28 phone trace readlink nr89 at index27 was source-authenticated libc, guest path hex 2F757372 = /usr. Existing Wine guest launch contract has SHA-verified /usr/lib/wine/wine64 ELF, with fixed guest directory chain root, /usr, /usr/lib, /usr/lib/wine. For these ONLY, readlink returns Linux -EINVAL without copying any output bytes; host paths never read or returned. Unknown paths still fail closed with bounded hex witness. Prior /proc links and Wine/ldso source PTLOAD protection retained in the ONE 512-event batch. A full guest filesystem, Linux process ABI, Wine, Win64 PE, graphics and game boot remain unproven.''',
'''R3D30 responds to the user's request to stop path-by-path APK cycles. The R3D29 device trace proved 31 original ELF syscall witnesses and 30 handled Linux guest calls; the next libc readlink(89) path is EXACT /usr/lib/wine/wine64 (original authenticated Wine ELF, a regular file). The new preopened, source-authenticated app-private guest rootfs directory fd feeds a generic bounded guest readlink VFS for arbitrary existing nonlink directory/regular file (-EINVAL), missing file (-ENOENT), and actual symlinks (no NUL), without Android host path forwarding. Unresolved intermediate symlinks fail closed. A separate 40-case batch preflight tests required rootfs paths and dangerous arguments, logging ALL cases and multiple failures, then ONE genuine FEX x86 512-syscall integrated Wine/Linux ABI pass. Six standard identity syscall handlers are also prepared but counted only if original x86 code actually invokes them. This is NOT 40 executed x86 calls and is NOT full Linux guest filesystem/process ABI or full Wine/Windows PE startup. Windows stage remains gated on real authenticated Wine boot plus Win32 launch bridge, not fabricated.'')
act.write_text(s)
print("R3D30_BATCH_40_PREFLIGHT_AND_GENERIC_ROOTFS_VFS_SOURCE_PATCH_PASS")
print("R3D30_6_PREPARED_IDENTITY_SYSCALLS_512_REAL_WITNESS_BUDGET_PASS")
print("R3D30_AUTO_WIN32_GATE_REQUIRES_REAL_FULL_WINE_BOOT_UNIMPLEMENTED")
