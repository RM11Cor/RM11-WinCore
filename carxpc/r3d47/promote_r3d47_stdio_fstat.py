#!/usr/bin/env python3
"""R3D47: actual original Wine glibc x86 fstat5(fd1) stdio ABI bridge.

R3D46 phone passed 104 preflight, 79 of 80 original guest x86 Linux calls
and exited safely on original libc syscall fstat(5), guestFd1 stdout,
guest stat144 destination 0x6FFFFFFA10 in owned 64KiB guest stack.
No SIGSEGV occurred in that run. The prior R3D45 100-callback crash was
on a different envp-dependent Wine code path, not declared permanently fixed.
"""
from pathlib import Path
import sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_r3d47_stdio_fstat.py /tmp/carxpc")
app=Path(sys.argv[1])/"app"
cpp=app/"src/main/cpp/carx_r3d4_first_syscall.cpp"
act=app/"src/main/java/com/r4/carxpc/R3D4ProbeActivity.java"
store=app/"src/main/java/com/r4/carxpc/R3D8JsonReportStore.java"
main=app/"src/main/java/com/r4/carxpc/MainActivity.java"
gradle=app/"build.gradle"
assert all(p.is_file() for p in (cpp,act,store,main,gradle))
def one(s,old,new):
 n=s.count(old)
 assert n==1,("R3D47_SOURCE_DRIFT",old[:140],n)
 return s.replace(old,new,1)
s=cpp.read_text()
s=one(s,'#include "carxpc/r3d45/native/source_verified_newfstatat262.hpp"',
'''#include "carxpc/r3d45/native/source_verified_newfstatat262.hpp"
#include "carxpc/r3d47/native/verified_attached_stdio_fstat.hpp"''')
s=one(s,'''        // R3D45: R3D44 device observed source-verified x86_64 libc''',
'''        // R3D47: device verified libc x86 Linux fstat(5), guest fd1,
        // into owned 144-byte guest stack at 0x6FFFFFFA10 at index79.
        // Existing R3D19 fstat accepts only the virtual libc fd100.
        // Here ONLY already-attached standard fds 0..2 are queried by
        // real kernel metadata fstat, never arbitrary host forwarding.
        if(number==carx_r3d47::kX86Fstat &&
           arg0<=carx_r3d47::kGuestStdErr) {
          const auto stdio=carx_r3d47::handle_attached_stdio_fstat(
              number,arg0,arg1,
              [&](uint64_t p,uint64_t n)->bool{
                return carx_r3d18::owned_stack_write_bounds(p,n) ||
                  carx_r3d33::brk_readable(p,n,BRKBase,GuestBrkCurrent) ||
                  GuestMaps.owned_writable_range(p,n);
              });
          char marker[140]{};
          std::snprintf(marker,sizeof(marker),
             "N80_R3D47_STDIO_FSTAT_FD_%llu_REASON_%u_RET_%lld",
             static_cast<unsigned long long>(arg0),
             static_cast<unsigned>(stdio.reason),
             static_cast<long long>(stdio.value));
          carx_r3d6::note(marker);
          if(!stdio.handled) {
            carx_r3d6::note("E_R3D47_STDIO_FSTAT_UNSAFE_GUEST_BUFFER_OR_HOST_STATE");
            ::_exit(212);
          }
          if(stdio.value==0) {
            char modeMarker[126]{};
            std::snprintf(modeMarker,sizeof(modeMarker),
               "N81_R3D47_REAL_STDIO_FSTAT_X86_STAT144_MODE_%u",
               static_cast<unsigned>(stdio.mode));
            carx_r3d6::note(modeMarker);
          } else {
            carx_r3d6::note("N81_R3D47_CLOSED_STDIO_REAL_EBADF");
          }
          accept(stdio.value,"N22_BATCH_RETURN_R3D47_REAL_STDIO_FSTAT144");
          return;
        }
        // R3D45: R3D44 device observed source-verified x86_64 libc''')
assert all(x in s for x in (
  "N80_R3D47_STDIO_FSTAT_FD_",
  "N22_BATCH_RETURN_R3D47_REAL_STDIO_FSTAT144",
  "N22_BATCH_RETURN_R3D45_SOURCE_VERIFIED_LIBC_NEWFSTATAT262",
  "N22_BATCH_RETURN_R3D19_FSTAT_X64_144"))
cpp.write_text(s)
s=act.read_text()
s=one(s,"r4.carx.r3d46.guest-home-user-env-fex512.v1",
        "r4.carx.r3d47.source-verified-stdio-fstat144-fex512.v1")
s=one(s,"07H_R3D46_GUEST_HOME_ENV_AUTHENTIC_FEX512",
        "07H_R3D47_STDIO_FSTAT5_AUTHENTIC_FEX512")
s=one(s,"07H_R3D46_GUEST_HOME_ENV_WINE_FEX512",
        "07H_R3D47_STDIO_FSTAT5_WINE_FEX512")
s=one(s,"R3D46 HOME env + Wine 512",
        "R3D47 stdio fstat + Wine 512")
s=one(s,
'''        report.put("r3d46_native_sigsegv_prevention_not_claimed",true);''',
'''        report.put("r3d46_native_sigsegv_prevention_not_claimed",true);
        report.put("r3d47_apk_runtime_identity",
           "R3D47_v71_REAL_NATIVE_STDOUT_FSTAT_GUEST_X64_STAT144");
        report.put("r3d47_stdio_fstat_source_callback_observed",
           phases.toString().contains("N80_R3D47_STDIO_FSTAT_FD_"));
        report.put("r3d47_real_stdio_guest_stat144_written",
           phases.toString().contains("N81_R3D47_REAL_STDIO_FSTAT_X86_STAT144_MODE_"));
        report.put("r3d47_real_closed_stdio_ebadf",
           phases.toString().contains("N81_R3D47_CLOSED_STDIO_REAL_EBADF"));
        report.put("r3d47_unknown_guest_descriptors_forwarded",false);''')
act.write_text(s)
s=store.read_text()
s=one(s,"CarX_PC_R3D46_GuestHOME_Diagnostics_",
        "CarX_PC_R3D47_StdioFstat_Diagnostics_")
store.write_text(s)
s=main.read_text()
s=one(s,"10 | R3D46 — تصحيح HOME وUSER على Wine",
        "10 | R3D47 — فحص stdout الأصلي داخل Wine")
main.write_text(s)
s=gradle.read_text()
s=one(s,"versionCode 70","versionCode 71")
s=one(s,"0.70-r3d46-guest-home-env-null-crash",
        "0.71-r3d47-stdio-fstat144-real")
gradle.write_text(s)
print("R3D47_REAL_ATTACHED_STDIO_FSTAT5_GUEST_X64_STAT144_CALLBACK_BRIDGE_INTEGRATED")
print("R3D47_GUEST_STDIO_ONLY_NO_ARBITRARY_FD_HOST_KERNEL_FORWARD")
