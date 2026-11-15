#!/usr/bin/env python3
"""R3D27: source-verified original libc x86_64 readlink(89) guest procfs.

Original R3D26 on-device 07H: 24 original 0F05 source witnesses; 23 safely
handled including nr302 prlimit64, then original verified libc FD100 calls
readlink(89), guest path 0x6FFFFFF0A0, writable guest 64KiB stack buffer
0x6FFFFFF8C0, bufsiz=1023, stops - unsupported. File text is not included
in R3D26 diagnostics, so do not assume what is at that pointer.
Capture bounded ASCII path live from source-owned guest stack.
ONLY if it equals /proc/self/exe, return the original authenticated
WineLinuxProcessLaunchContract guest execfn /usr/lib/wine/wine64.
No trailing NUL on readlink, only exact count. Unknown pathname fail-closed
with a source-witnessed path hex prefix for the next diagnostic.
NEVER forward guest readlink pointers to Android host, never reveal host exe.
Keep all R3D19-26 Linux ABI and source journal in ONE 07H APK batch.
"""
from pathlib import Path
import re,sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_guest_proc_readlink.py /tmp/carxpc")
app=Path(sys.argv[1]);java=app/"app/src/main/java/com/r4/carxpc"
cpp=app/"app/src/main/cpp/carx_r3d4_first_syscall.cpp"
act=java/"R3D4ProbeActivity.java";main=java/"MainActivity.java"
gradle=app/"app/build.gradle";store=java/"R3D8JsonReportStore.java"
assert all(x.is_file() for x in (cpp,act,main,gradle,store))
def one(s,a,n):
 c=s.count(a)
 assert c==1,("R3D27_SOURCE_LOCK_CHANGED",a[:150],c)
 return s.replace(a,n,1)
def reone(s,p,n):
 s,k=re.subn(p,n,s,count=1)
 assert k==1,("R3D27_VERSION_CHANGED",p,k)
 return s
s=gradle.read_text()
s=reone(s,r"\bversionCode\s+54\b","versionCode 55")
s=reone(s,r"versionName\s+'[^']+'",
 "versionName '0.55-r3d27-owned-guest-proc-self-exe-readlink'")
gradle.write_text(s)
s=main.read_text()
s=one(s,"10 | R3D26 — حد مكدس Wine ومصادر ELF الموحّدة",
      "10 | R3D27 — قراءة روابط نظام Linux للضيف")
main.write_text(s)
s=store.read_text()
s=one(s,'"CarX_PC_R3D26_StackPrlimit_Diagnostics_"',
      '"CarX_PC_R3D27_GuestReadlink_Diagnostics_"')
store.write_text(s)

s=cpp.read_text()
s=one(s,
'''#include "carxpc/r3d26/native/guest_stack_prlimit64.hpp"''',
'''#include "carxpc/r3d26/native/guest_stack_prlimit64.hpp"
#include "carxpc/r3d27/native/verified_guest_readlink.hpp"''')
# NOTE: R3D26 prlimit block is already inside Mode==4 (verified JNI scope).
# Insertion before its closing brace preserves original Linux ABI mode <=3.
s=one(s,
'''        accept(0,"N22_BATCH_RETURN_R3D26_PRLIMIT64_OWNED_GUEST_STACK");
        return;
        }
      }
      std::snprintf(msg,sizeof(msg),"E_BATCH_UNSUPPORTED_NR_%llu",''',
'''        accept(0,"N22_BATCH_RETURN_R3D26_PRLIMIT64_OWNED_GUEST_STACK");
        return;
        }
        if(number==carx_r3d27::kLinuxX86Readlink) {
          char observed[256]{};
          if(!carx_r3d16::capture_guest_stack_ascii_path(arg0,observed)){
            carx_r3d6::note("E_R3D27_READLINK_GUEST_STACK_PATH_UNREADABLE");
            ::_exit(177);
          }
          // A path is logged only as a bounded hex prefix on failure.
          // Do NOT print raw host file names, and never pass guest pathname
          // to the host kernel as a readlink() request.
          if(std::strcmp(observed,carx_r3d27::kGuestProcSelfExe)!=0) {
            char hex[129]{};
            const size_t n=std::min<size_t>(std::strlen(observed),48);
            constexpr char digits[]="0123456789ABCDEF";
            for(size_t k=0;k<n;++k){
              const auto c=static_cast<unsigned char>(observed[k]);
              hex[k*2]=digits[c>>4];
              hex[k*2+1]=digits[c&15];
            }
            char detail[180]{};
            std::snprintf(detail,sizeof(detail),
                 "N36_READLINK_UNKNOWN_GUEST_PATH_HEX_PREFIX_%s",hex);
            carx_r3d6::note(detail);
            carx_r3d6::note("E_R3D27_READLINK_UNSUPPORTED_GUEST_SYMLINK");
            ::_exit(178);
          }
          const uint64_t lower=carx_r3d16::kStackTop -
                               carx_r3d16::kStackSize;
          const uint64_t upper=carx_r3d16::kStackTop;
          const auto link=carx_r3d27::write_source_bound_proc_self_exe(
             observed,arg1,arg2,lower,upper);
          if(link.code!=carx_r3d27::Status::Success){
            carx_r3d6::note("E_R3D27_READLINK_WRITABLE_GUEST_STACK_DENIED");
            ::_exit(179);
          }
          carx_r3d6::note("N36_SOURCE_OWNED_READLINK_PROC_SELF_EXE_VERIFIED");
          carx_r3d6::note("N36_GUEST_SYMLINK_TARGET_USR_LIB_WINE_WINE64");
          char detail[128]{};
          std::snprintf(detail,sizeof(detail),
            "N36_GUEST_READLINK_RETURN_LENGTH_%llu",
             static_cast<unsigned long long>(link.bytes));
          carx_r3d6::note(detail);
          accept(static_cast<int64_t>(link.bytes),
                 "N22_BATCH_RETURN_R3D27_GUEST_PROC_SELF_EXE_READLINK");
          return;
        }
      }
      std::snprintf(msg,sizeof(msg),"E_BATCH_UNSUPPORTED_NR_%llu",''')
assert all(x in s for x in [
 "N36_SOURCE_OWNED_READLINK_PROC_SELF_EXE_VERIFIED",
 "N22_BATCH_RETURN_R3D27_GUEST_PROC_SELF_EXE_READLINK",
 "E_R3D27_READLINK_UNSUPPORTED_GUEST_SYMLINK",
 "N34_SOURCE_DOMAIN_VERIFIED_LIBC_FD100",
 "N22_BATCH_RETURN_R3D26_PRLIMIT64_OWNED_GUEST_STACK",
 "N22_BATCH_RETURN_R3D24_PRESEALED_WINE_ELF_MPROTECT",
 "context->ExecuteThread(thread)"])
cpp.write_text(s)

s=act.read_text()
s=one(s,
'''runCacheless.setText("تشغيل 07H — R3D26 Wine + Guest prlimit64");''',
'''runCacheless.setText("تشغيل 07H — R3D27 Wine + Guest readlink");''')
s=one(s,
'''r4.carx.r3d26.integrated-wine-source-journal-guest-prlimit64.v1''',
'''r4.carx.r3d27.integrated-wine-libc-guest-proc-self-exe-readlink.v1''')
s=one(s,
'''07H_INTEGRATED_WINE_GNU_LDSO_LIBC_SOURCE_GUEST_STACK_PRLIMIT64''',
'''07H_INTEGRATED_WINE_GNU_LDSO_LIBC_GUEST_PROC_SELF_EXE_READLINK''')
s=one(s,
'''07H_R3D26_UNIFIED_WINE_GUEST_STACK_PRLIMIT64_BATCH_512''',
'''07H_R3D27_UNIFIED_WINE_GUEST_READLINK_BATCH_512''')
s=one(s,
'''if(p.startsWith("E_BATCH_") || p.startsWith("E_R3D22_") ||
             p.startsWith("E_R3D25_")) stop=p;''',
'''if(p.startsWith("E_BATCH_") || p.startsWith("E_R3D22_") ||
             p.startsWith("E_R3D25_") || p.startsWith("E_R3D27_"))
              stop=p;''')
s=one(s,
'''        report.put("r3d26_multisource_journal_validation_enabled",true);''',
'''        report.put("r3d26_multisource_journal_validation_enabled",true);
        report.put("r3d27_native_readlink_89_guard_present",true);
        report.put("r3d27_guest_proc_self_exe_verified",
          phases.toString().contains(
            "N36_SOURCE_OWNED_READLINK_PROC_SELF_EXE_VERIFIED"));
        report.put("r3d27_guest_proc_self_exe_readlink_accepted",
          phases.toString().contains(
            "N22_BATCH_RETURN_R3D27_GUEST_PROC_SELF_EXE_READLINK"));
        report.put("r3d27_guest_unknown_readlink_path_recorded",
          phases.toString().contains(
            "N36_READLINK_UNKNOWN_GUEST_PATH_HEX_PREFIX_"));
        report.put("r3d27_guest_readlink_no_host_path_forwarding",true);
        report.put("r3d27_guest_readlink_never_returns_host_executable_path",true);''')
s=one(s,
'''        stages.put("prlimit64_rlimit_stack_owned_guest_result",
          phases.toString().contains(
           "N22_BATCH_RETURN_R3D26_PRLIMIT64_OWNED_GUEST_STACK"));''',
'''        stages.put("prlimit64_rlimit_stack_owned_guest_result",
          phases.toString().contains(
           "N22_BATCH_RETURN_R3D26_PRLIMIT64_OWNED_GUEST_STACK"));
        stages.put("guest_proc_self_exe_readlink_source_verified",
          phases.toString().contains(
           "N36_SOURCE_OWNED_READLINK_PROC_SELF_EXE_VERIFIED"));
        stages.put("guest_proc_self_exe_readlink_result_copied",
          phases.toString().contains(
           "N22_BATCH_RETURN_R3D27_GUEST_PROC_SELF_EXE_READLINK"));''')
s=one(s,
'''R3D26 preserves R3D25 native source-verified GNU/Wine/libc x86 syscalls and all 22 handled calls. Real R3D25 device result proved original libc FD100 syscall 302 prlimit64(pid=0, resource=3 RLIMIT_STACK, new=null, old=owned guest stack); stopped as unsupported (113). Old Java wire validator wrongly expected only GNU ld.so and labelled this valid libc record source failure. R3D26 repairs Java per-record source domain validation and handles ONLY read-only guest RLIMIT_STACK into the installed writable 64KiB guest stack, capped by existing host resource limits, without host limit mutation or guest pointer forwarding. Diagnostic guest stack cannot auto-grow; full Linux ABI, Wine, Win64 PE/graphics/game remain unproven.''',
'''R3D27 preserves R3D26 true multi-ELF original x86 syscall evidence and 23 accepted guest ABI responses. Actual R3D26 phone trace showed original libc FD100 nr89 readlink(path=0x6FFFFFF0A0, buffer=0x6FFFFFF8C0, bufsiz=1023) next. Guest pathname text was NOT in prior report and is captured live from the already-installed bounded writable x86 stack. Only if the exact text equals /proc/self/exe does guest procfs return source-verified original Wine executable path /usr/lib/wine/wine64 (R3C23 GUEST_EXECFN), NO terminating NUL, response exact byte count. Unknown links log bounded hex source and fail closed; zero guest pointer forwarding to host. Preserves single 512-witness Wine/Linux ABI batch with source-checked JNI and postexecute fault trace. Full Wine/PE/graphics/game startup remain unproven.''')
act.write_text(s)
print("R3D27_SOURCE_VERIFIED_GUEST_PROC_SELF_EXE_READLINK_PATCH_PASS")
print("R3D27_LINK_UNKNOWN_PATH_HEX_DIAGNOSTIC_AND_NO_HOST_SYSCALL_FORWARDING_PASS")
