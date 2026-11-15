#!/usr/bin/env python3
"""R3D48: handle the exact original x86 ioctl(16, TCGETS) seen at R3D47 index80.

R3D47 phone evidence: original x86 fstat(5, fd1) at index79 returned real
metadata and copied x86 stat144 into owned guest stack. The next original
libc syscall was ioctl(16, fd1, 0x5401, 0x6FFFFFF970). TCGETS is the Linux
kernel UAPI terminal-get request; its asm-generic/x86 termios payload is
36 bytes (four u32 flags, one line byte, nineteen control bytes).
Only inherited standard fds 0..2 and exact TCGETS are admitted. Host ioctl
uses a local native buffer; never pass a guest pointer, unknown fd or request.
"""
from pathlib import Path
import sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_r3d48_stdio_tcgets.py /tmp/carxpc")
app=Path(sys.argv[1])/"app"
cpp=app/"src/main/cpp/carx_r3d4_first_syscall.cpp"
act=app/"src/main/java/com/r4/carxpc/R3D4ProbeActivity.java"
store=app/"src/main/java/com/r4/carxpc/R3D8JsonReportStore.java"
main=app/"src/main/java/com/r4/carxpc/MainActivity.java"
gradle=app/"build.gradle"
assert all(p.is_file() for p in (cpp,act,store,main,gradle))
def one(s,old,new):
 n=s.count(old)
 assert n==1,("R3D48_SOURCE_DRIFT",old[:160],n)
 return s.replace(old,new,1)
s=cpp.read_text()
s=one(s,'#include "carxpc/r3d47/native/verified_attached_stdio_fstat.hpp"',
'''#include "carxpc/r3d47/native/verified_attached_stdio_fstat.hpp"
#include "carxpc/r3d48/native/verified_attached_stdio_tcgets.hpp"''')
s=one(s,'''        // R3D47: device verified libc x86 Linux fstat(5), guest fd1,''',
'''        // R3D48: R3D47 device's next authentic x86 callback was
        // ioctl(16, guest fd1, TCGETS=0x5401, guest termios36 ptr).
        // Admit ONLY attached stdio descriptors and this read-only query.
        // The native ioctl receives a local 36-byte kernel ABI buffer, never
        // a guest pointer. Non-TTY streams return their actual -ENOTTY.
        if(number==carx_r3d48::kX86Ioctl &&
           arg0<=carx_r3d48::kGuestStdErr &&
           arg1==carx_r3d48::kLinuxTcgets) {
          const auto stdio=carx_r3d48::handle_attached_stdio_tcgets(
              number,arg0,arg1,arg2,
              [&](uint64_t p,uint64_t n)->bool{
                return carx_r3d18::owned_stack_write_bounds(p,n) ||
                  carx_r3d33::brk_readable(p,n,BRKBase,GuestBrkCurrent) ||
                  GuestMaps.owned_writable_range(p,n);
              });
          char marker[144]{};
          std::snprintf(marker,sizeof(marker),
             "N82_R3D48_STDIO_IOCTL_TCGETS_FD_%llu_REASON_%u_RET_%lld",
             static_cast<unsigned long long>(arg0),
             static_cast<unsigned>(stdio.reason),
             static_cast<long long>(stdio.value));
          carx_r3d6::note(marker);
          if(!stdio.handled) {
            carx_r3d6::note("E_R3D48_STDIO_IOCTL_TCGETS_UNSAFE_GUEST_BUFFER_OR_HOST_STATE");
            ::_exit(213);
          }
          if(stdio.value==0) {
            carx_r3d6::note("N83_R3D48_REAL_TCGETS_KERNEL_TERMIOS36_COPIED");
          } else {
            char errorMarker[120]{};
            std::snprintf(errorMarker,sizeof(errorMarker),
               "N83_R3D48_REAL_TCGETS_NEGATIVE_ERRNO_RETURNED_%d",
               stdio.hostErrno);
            carx_r3d6::note(errorMarker);
          }
          accept(stdio.value,"N22_BATCH_RETURN_R3D48_STDIO_IOCTL_TCGETS_KERNEL_ABI");
          return;
        }
        // R3D47: device verified libc x86 Linux fstat(5), guest fd1,''')
assert all(x in s for x in (
 "N82_R3D48_STDIO_IOCTL_TCGETS_FD_",
 "N22_BATCH_RETURN_R3D48_STDIO_IOCTL_TCGETS_KERNEL_ABI",
 "N22_BATCH_RETURN_R3D47_REAL_STDIO_FSTAT144"))
cpp.write_text(s)
s=act.read_text()
s=one(s,"r4.carx.r3d47.source-verified-stdio-fstat144-fex512.v1",
        "r4.carx.r3d48.source-verified-stdio-ioctl-tcgets36-fex512.v1")
s=one(s,"07H_R3D47_STDIO_FSTAT5_AUTHENTIC_FEX512",
        "07H_R3D48_STDIO_IOCTL_TCGETS_AUTHENTIC_FEX512")
s=one(s,"07H_R3D47_STDIO_FSTAT5_WINE_FEX512",
        "07H_R3D48_STDIO_IOCTL_TCGETS_WINE_FEX512")
s=one(s,"R3D47 stdio fstat + Wine 512",
        "R3D48 stdio TCGETS ioctl + Wine 512")
s=one(s,
'''        report.put("r3d47_unknown_guest_descriptors_forwarded",false);''',
'''        report.put("r3d47_unknown_guest_descriptors_forwarded",false);
        report.put("r3d48_apk_runtime_identity",
           "R3D48_v72_REAL_STDIO_TCGETS_KERNEL_TERMIOS36");
        report.put("r3d48_stdio_ioctl_tcgets_source_callback_observed",
           phases.toString().contains("N82_R3D48_STDIO_IOCTL_TCGETS_FD_"));
        report.put("r3d48_real_tcgets_guest_kernel_termios36_copied",
           phases.toString().contains("N83_R3D48_REAL_TCGETS_KERNEL_TERMIOS36_COPIED"));
        report.put("r3d48_real_tcgets_negative_errno_returned",
           phases.toString().contains("N83_R3D48_REAL_TCGETS_NEGATIVE_ERRNO_RETURNED_"));
        report.put("r3d48_unapproved_ioctl_requests_forwarded",false);
        report.put("r3d48_unknown_guest_descriptors_forwarded",false);
        report.put("r3d48_guest_pointer_forwarded_to_host_ioctl",false);''')
act.write_text(s)
s=store.read_text()
s=one(s,"CarX_PC_R3D47_StdioFstat_Diagnostics_",
        "CarX_PC_R3D48_StdioIoctl_Diagnostics_")
store.write_text(s)
s=main.read_text()
s=one(s,"10 | R3D47 — فحص stdout الأصلي داخل Wine",
        "10 | R3D48 — ioctl الطرفية للخرج القياسي")
main.write_text(s)
s=gradle.read_text()
s=one(s,"versionCode 71","versionCode 72")
s=one(s,"0.71-r3d47-stdio-fstat144-real",
        "0.72-r3d48-stdio-ioctl-tcgets")
gradle.write_text(s)
print("R3D48_EXACT_X86_IOCTL16_TCGETS_ATTACHED_STDIO_ABI_INTEGRATED")
print("R3D48_KERNEL_TCGETS_USES_LOCAL_NATIVE_TERMios36_NO_GUEST_PTR_FORWARD")
