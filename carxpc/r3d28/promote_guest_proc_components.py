#!/usr/bin/env python3
"""R3D28: progress original source-verified libc readlink path components.

Real R3D27 phone source evidence: GNU+libc 24 calls, 23 safely handled, then
the x86 guest libc readlink(89) pathname verified as EXACT ASCII "/proc",
reported with N36...HEX_PREFIX_2F70726F63. It is a directory and the
correct Linux result is -EINVAL, not arbitrary successful guest symlink.
Also support closely-related /proc/self symlink to the isolated guest worker
PID, /proc/<thispid> nonlink directory, and /proc/<thispid>/exe link to
source-authenticated guest Wine binary (never Android /proc/self/exe).
Previous /proc/self/exe handling retained. Unknown paths still fail closed
with bounded hex evidence. Preserve ONE 512-syscall integrated Linux ABI
and proper native/Java journaling; do not claim full Wine/Windows/graphics.
"""
from pathlib import Path
import re,sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_guest_proc_components.py /tmp/carxpc")
app=Path(sys.argv[1]);java=app/"app/src/main/java/com/r4/carxpc"
cpp=app/"app/src/main/cpp/carx_r3d4_first_syscall.cpp"
act=java/"R3D4ProbeActivity.java";main=java/"MainActivity.java"
gradle=app/"app/build.gradle";store=java/"R3D8JsonReportStore.java"
assert all(x.is_file() for x in (cpp,act,main,gradle,store))
def one(s,a,n):
 c=s.count(a)
 assert c==1,("R3D28_SOURCE_LOCK_ANCHOR_CHANGED",a[:145],c)
 return s.replace(a,n,1)
def reone(s,p,n):
 s,k=re.subn(p,n,s,count=1)
 assert k==1,("R3D28_VERSION_SOURCE_CHANGED",p,k)
 return s
s=gradle.read_text()
s=reone(s,r"\bversionCode\s+55\b","versionCode 56")
s=reone(s,r"versionName\s+'[^']+'",
 "versionName '0.56-r3d28-bounded-guest-procfs-directory-and-self-links'")
gradle.write_text(s)
s=main.read_text()
s=one(s,"10 | R3D27 — قراءة روابط نظام Linux للضيف",
      "10 | R3D28 — معالجة مسارات procfs للضيف")
main.write_text(s)
s=store.read_text()
s=one(s,'"CarX_PC_R3D27_GuestReadlink_Diagnostics_"',
      '"CarX_PC_R3D28_ProcfsComponents_Diagnostics_"')
store.write_text(s)
s=cpp.read_text()
s=one(s,
'''#include "carxpc/r3d27/native/verified_guest_readlink.hpp"''',
'''#include "carxpc/r3d27/native/verified_guest_readlink.hpp"
#include "carxpc/r3d28/native/verified_guest_procfs_components.hpp"''')
s=one(s,
'''          // A path is logged only as a bounded hex prefix on failure.
          // Do NOT print raw host file names, and never pass guest pathname
          // to the host kernel as a readlink() request.
          if(std::strcmp(observed,carx_r3d27::kGuestProcSelfExe)!=0) {''',
'''          // The original R3D27 trace proved the exact source guest string
          // /proc, a DIRECTORY. Linux readlink must return negative EINVAL
          // without modifying the output buffer. /proc/self is a symlink,
          // not a directory, so virtualize the isolated worker's *own* PID.
          // All entries are fixed guest-only paths, never host readlink calls.
          const uint64_t stackLow=carx_r3d16::kStackTop -
                                  carx_r3d16::kStackSize;
          const uint64_t stackHigh=carx_r3d16::kStackTop;
          const uint64_t isolatedWorkerPid=uint64_t(::getpid());
          const auto procfs=carx_r3d28::resolve_known_procfs_component(
              observed,arg1,arg2,stackLow,stackHigh,isolatedWorkerPid);
          if(procfs.kind==carx_r3d28::Kind::InvalidGuestDestination) {
            carx_r3d6::note("E_R3D28_READLINK_UNOWNED_GUEST_OUTPUT");
            ::_exit(180);
          }
          if(procfs.kind==carx_r3d28::Kind::DirectoryNotSymlink){
            carx_r3d6::note("N37_SOURCE_VERIFIED_PROCFS_GUEST_DIRECTORY_NOT_SYMLINK");
            char witness[104]{};
            std::snprintf(witness,sizeof(witness),
                 "N37_GUEST_READLINK_DIRECTORY_PID_%llu",
                 static_cast<unsigned long long>(isolatedWorkerPid));
            carx_r3d6::note(witness);
            accept(-int64_t(EINVAL),
                "N22_BATCH_RETURN_R3D28_PROCFS_DIR_NEG_EINVAL");
            return;
          }
          if(procfs.kind==carx_r3d28::Kind::SelfPidSymlink){
            carx_r3d6::note("N37_SOURCE_VERIFIED_PROC_SELF_PID_SYMLINK");
            accept(procfs.guestReturn,
                "N22_BATCH_RETURN_R3D28_PROC_SELF_GUEST_PID_SYMLINK");
            return;
          }
          if(procfs.kind==carx_r3d28::Kind::ProcessExeSymlink){
            carx_r3d6::note("N37_SOURCE_VERIFIED_PROC_GUEST_PID_EXE_SYMLINK");
            carx_r3d6::note("N37_GUEST_PID_EXE_TARGET_USR_LIB_WINE_WINE64");
            accept(procfs.guestReturn,
                "N22_BATCH_RETURN_R3D28_PROC_GUEST_PID_EXE_SYMLINK");
            return;
          }
          // A path is logged only as a bounded hex prefix on failure.
          // Do NOT print raw host file names, and never pass guest pathname
          // to the host kernel as a readlink() request.
          if(std::strcmp(observed,carx_r3d27::kGuestProcSelfExe)!=0) {''')
assert all(x in s for x in (
 "N37_SOURCE_VERIFIED_PROCFS_GUEST_DIRECTORY_NOT_SYMLINK",
 "N22_BATCH_RETURN_R3D28_PROCFS_DIR_NEG_EINVAL",
 "N22_BATCH_RETURN_R3D28_PROC_SELF_GUEST_PID_SYMLINK",
 "N22_BATCH_RETURN_R3D28_PROC_GUEST_PID_EXE_SYMLINK",
 "N22_BATCH_RETURN_R3D27_GUEST_PROC_SELF_EXE_READLINK",
 "N22_BATCH_RETURN_R3D26_PRLIMIT64_OWNED_GUEST_STACK",
 "N34_SOURCE_DOMAIN_VERIFIED_LIBC_FD100",
 "E_R3D27_READLINK_UNSUPPORTED_GUEST_SYMLINK",
 "context->ExecuteThread(thread)"))
cpp.write_text(s)
s=act.read_text()
s=one(s,
'''runCacheless.setText("تشغيل 07H — R3D27 Wine + Guest readlink");''',
'''runCacheless.setText("تشغيل 07H — R3D28 Wine + procfs readlink");''')
s=one(s,
'''r4.carx.r3d27.integrated-wine-libc-guest-proc-self-exe-readlink.v1''',
'''r4.carx.r3d28.integrated-guest-procfs-component-readlink.v1''')
s=one(s,
'''07H_INTEGRATED_WINE_GNU_LDSO_LIBC_GUEST_PROC_SELF_EXE_READLINK''',
'''07H_INTEGRATED_WINE_GNU_LDSO_LIBC_PROCFS_COMPONENT_READLINK''')
s=one(s,
'''07H_R3D27_UNIFIED_WINE_GUEST_READLINK_BATCH_512''',
'''07H_R3D28_UNIFIED_WINE_GUEST_PROCFS_READLINK_BATCH_512''')
# R3D27's E_R3D27 marker is already detected in the phase scan; previously
# Java returned misleading "BATCH_INCOMPLETE" because it had no status case.
# Keep native failure path and treat it as an explicit guarded source stop.
s=one(s,
'''        if(stop.startsWith("E_BATCH_UNSUPPORTED_NR_"))''',
'''        if(stop.equals("E_R3D27_READLINK_UNSUPPORTED_GUEST_SYMLINK"))
            return "BATCH_HALTED_AT_UNSUPPORTED_SOURCE_VERIFIED_GUEST_READLINK_PATH";
        if(stop.equals("E_R3D27_READLINK_GUEST_STACK_PATH_UNREADABLE"))
            return "BATCH_HALTED_AT_UNREADABLE_GUEST_READLINK_PATH";
        if(stop.equals("E_R3D28_READLINK_UNOWNED_GUEST_OUTPUT"))
            return "BATCH_REJECTED_GUEST_READLINK_UNOWNED_DESTINATION";
        if(stop.startsWith("E_BATCH_UNSUPPORTED_NR_"))''')
s=one(s,
'''        report.put("r3d27_guest_readlink_never_returns_host_executable_path",true);''',
'''        report.put("r3d27_guest_readlink_never_returns_host_executable_path",true);
        report.put("r3d28_guest_proc_directory_readlink_negative_einval",
          phases.toString().contains(
            "N22_BATCH_RETURN_R3D28_PROCFS_DIR_NEG_EINVAL"));
        report.put("r3d28_guest_proc_self_pid_link_handled",
          phases.toString().contains(
            "N22_BATCH_RETURN_R3D28_PROC_SELF_GUEST_PID_SYMLINK"));
        report.put("r3d28_guest_proc_pid_exe_link_handled",
          phases.toString().contains(
            "N22_BATCH_RETURN_R3D28_PROC_GUEST_PID_EXE_SYMLINK"));
        report.put("r3d28_unknown_guest_path_host_forwarded",false);
        report.put("r3d28_guest_procfs_scope",
          "EXACT_PROC_DIRECTORY_AND_CURRENT_ISOLATED_WORKER_SELF_PID_EXE_ONLY");''')
s=one(s,
'''        stages.put("guest_proc_self_exe_readlink_result_copied",
          phases.toString().contains(
           "N22_BATCH_RETURN_R3D27_GUEST_PROC_SELF_EXE_READLINK"));''',
'''        stages.put("guest_proc_self_exe_readlink_result_copied",
          phases.toString().contains(
           "N22_BATCH_RETURN_R3D27_GUEST_PROC_SELF_EXE_READLINK"));
        stages.put("guest_proc_directory_not_symlink_einval",
          phases.toString().contains(
            "N22_BATCH_RETURN_R3D28_PROCFS_DIR_NEG_EINVAL"));
        stages.put("guest_proc_self_pid_readlink",
          phases.toString().contains(
            "N22_BATCH_RETURN_R3D28_PROC_SELF_GUEST_PID_SYMLINK"));
        stages.put("guest_proc_pid_exe_readlink",
          phases.toString().contains(
            "N22_BATCH_RETURN_R3D28_PROC_GUEST_PID_EXE_SYMLINK"));''')
s=one(s,
'''R3D27 preserves R3D26 true multi-ELF original x86 syscall evidence and 23 accepted guest ABI responses. Actual R3D26 phone trace showed original libc FD100 nr89 readlink(path=0x6FFFFFF0A0, buffer=0x6FFFFFF8C0, bufsiz=1023) next. Guest pathname text was NOT in prior report and is captured live from the already-installed bounded writable x86 stack. Only if the exact text equals /proc/self/exe does guest procfs return source-verified original Wine executable path /usr/lib/wine/wine64 (R3C23 GUEST_EXECFN), NO terminating NUL, response exact byte count. Unknown links log bounded hex source and fail closed; zero guest pointer forwarding to host. Preserves single 512-witness Wine/Linux ABI batch with source-checked JNI and postexecute fault trace. Full Wine/PE/graphics/game startup remain unproven.''',
'''R3D28 preserves all 24 original x86 GNU+libc syscall source witness records and 23 accepted responses proven by R3D27. The R3D27 device report decoded the exact readlink nr89 source-owned path HEX 2F70726F63 as /proc, a guest procfs DIRECTORY not symlink; correct Linux return is -EINVAL without writing output, not success or a host filesystem path. R3D28 safely supports this directory and bounded related /proc/self symlink to the actual isolated worker PID, /proc/<pid> directory, /proc/<pid>/exe original SHA-authenticated guest Wine execfn; legacy /proc/self/exe unchanged. Any other path still fails closed with hex source. All guest readlink output is in the mapped 64 KiB x86 guest stack, never from host readlink or host executable. Java now describes unsupported verified guest readlink explicitly, not generic child exit. Preserves one 512-witness Wine/FEX/Linux ABI batch; full Wine/Win64 PE/graphics/game remain unproven.''')
act.write_text(s)
print("R3D28_PROC_DIR_NEG_EINVAL_AND_SELF_PROC_PID_SOURCE_VERIFIED_PROMOTION_PASS")
print("R3D28_ONE_UNIFIED_512_GUEST_ABI_BATCH_NO_HOST_READLINK_FORWARDING")
