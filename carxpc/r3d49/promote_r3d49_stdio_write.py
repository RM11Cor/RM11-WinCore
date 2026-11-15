#!/usr/bin/env python3
"""R3D49: continue the exact original FEX callback after R3D48 TCGETS.

R3D48 phone evidence: callback index80 was ioctl(16, fd1, TCGETS=0x5401);
the isolated worker returned the real -ENOTTY for its non-TTY stdout.
The next source-verified original libc callback, index81, was
write(1, guest_buffer=0x7095A02340, count=37).

Admit only x86 write(1) to already-attached stdout. Validate the complete
source buffer against the owned guest stack, committed brk, or pagewise
readable GuestMappings; copy it to a 4KiB-bounded local buffer; call host
write(1, local, count); return the actual byte count or negative errno.
Never pass a guest pointer or arbitrary guest descriptor to the host kernel.
"""
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: promote_r3d49_stdio_write.py /tmp/carxpc")

app = Path(sys.argv[1]) / "app"
cpp = app / "src/main/cpp/carx_r3d4_first_syscall.cpp"
act = app / "src/main/java/com/r4/carxpc/R3D4ProbeActivity.java"
store = app / "src/main/java/com/r4/carxpc/R3D8JsonReportStore.java"
main = app / "src/main/java/com/r4/carxpc/MainActivity.java"
gradle = app / "build.gradle"
assert all(p.is_file() for p in (cpp, act, store, main, gradle))

def one(s, old, new):
    n = s.count(old)
    assert n == 1, ("R3D49_SOURCE_DRIFT", old[:160], n)
    return s.replace(old, new, 1)

s = cpp.read_text()
s = one(s,
    '#include "carxpc/r3d48/native/verified_attached_stdio_tcgets.hpp"',
    '''#include "carxpc/r3d48/native/verified_attached_stdio_tcgets.hpp"
#include "carxpc/r3d49/native/verified_attached_stdio_write.hpp"''')

anchor = """        // R3D48: R3D47 device's next authentic x86 callback was"""
write_handler = """        // R3D49: R3D48 device's next authentic original libc callback was
        // write(1, guest buffer 0x7095A02340, 37 bytes), source-verified at
        // callback index81. Read only fully owned stack/brk/readable mmap.
        // Copy into a local bounded buffer before host write(1); never pass
        // the guest pointer or any non-stdout descriptor to the host kernel.
        if(number==carx_r3d49::kX86Write &&
           arg0==carx_r3d49::kGuestStdOut) {
          const auto output=carx_r3d49::handle_attached_stdout_write(
              number,arg0,arg1,arg2,
              [&](uint64_t p,uint64_t n)->bool{
                return carx_r3d18::owned_stack_write_bounds(p,n) ||
                  carx_r3d33::brk_readable(p,n,BRKBase,GuestBrkCurrent) ||
                  GuestMaps.owned_readable_range(p,n);
              });
          char marker[144]{};
          std::snprintf(marker,sizeof(marker),
             "N84_R3D49_STDIO_WRITE_FD_1_REASON_%u_RET_%lld",
             static_cast<unsigned>(output.reason),
             static_cast<long long>(output.value));
          carx_r3d6::note(marker);
          if(!output.handled) {
            carx_r3d6::note("E_R3D49_STDIO_WRITE_UNOWNED_OR_OVERSIZED_GUEST_BUFFER");
            ::_exit(214);
          }
          if(output.bytesCopied) {
            char copyMarker[96]{};
            std::snprintf(copyMarker,sizeof(copyMarker),
               "N85_R3D49_STDIO_WRITE_LOCAL_COPY_BYTES_%u",
               output.bytesCopied);
            carx_r3d6::note(copyMarker);
          }
          if(output.hostErrno>0) {
            char errorMarker[112]{};
            std::snprintf(errorMarker,sizeof(errorMarker),
               "N86_R3D49_STDIO_WRITE_REAL_NEGATIVE_ERRNO_%d",
               output.hostErrno);
            carx_r3d6::note(errorMarker);
          } else {
            char returnMarker[112]{};
            std::snprintf(returnMarker,sizeof(returnMarker),
               "N86_R3D49_STDIO_WRITE_REAL_RETURN_%lld",
               static_cast<long long>(output.value));
            carx_r3d6::note(returnMarker);
          }
          accept(output.value,"N22_BATCH_RETURN_R3D49_STDIO_WRITE1_OWNED_COPY");
          return;
        }
"""
s = one(s, anchor, write_handler + anchor)
assert "N22_BATCH_RETURN_R3D49_STDIO_WRITE1_OWNED_COPY" in s
assert "GuestMaps.owned_readable_range(p,n)" in s
cpp.write_text(s)

s = act.read_text()
s = one(s,
    "r4.carx.r3d48.source-verified-stdio-ioctl-tcgets36-fex512.v1",
    "r4.carx.r3d49.source-verified-stdio-write-owned-copy-fex512.v1")
s = one(s,
    "07H_R3D48_STDIO_IOCTL_TCGETS_AUTHENTIC_FEX512",
    "07H_R3D49_STDIO_WRITE_AUTHENTIC_FEX512")
s = one(s,
    "07H_R3D48_STDIO_IOCTL_TCGETS_WINE_FEX512",
    "07H_R3D49_STDIO_WRITE_WINE_FEX512")
s = one(s,
    "R3D48 stdio TCGETS ioctl + Wine 512",
    "R3D49 stdio write(1) + Wine 512")
s = one(s,
    '''        report.put("r3d48_guest_pointer_forwarded_to_host_ioctl",false);''',
    '''        report.put("r3d48_guest_pointer_forwarded_to_host_ioctl",false);
        report.put("r3d49_apk_runtime_identity",
           "R3D49_v73_REAL_STDIO_WRITE_OWNED_LOCAL_COPY");
        report.put("r3d49_stdio_write_source_callback_observed",
           phases.toString().contains("N84_R3D49_STDIO_WRITE_FD_1_"));
        report.put("r3d49_guest_stdio_write_buffer_validated_and_copied",
           phases.toString().contains("N85_R3D49_STDIO_WRITE_LOCAL_COPY_BYTES_"));
        report.put("r3d49_real_stdio_write_returned",
           phases.toString().contains("N86_R3D49_STDIO_WRITE_REAL_RETURN_"));
        report.put("r3d49_real_stdio_write_negative_errno_returned",
           phases.toString().contains("N86_R3D49_STDIO_WRITE_REAL_NEGATIVE_ERRNO_"));
        report.put("r3d49_guest_pointer_forwarded_to_host_write",false);
        report.put("r3d49_unknown_guest_descriptors_forwarded",false);''')
act.write_text(s)

s = store.read_text()
s = one(s,
    "CarX_PC_R3D48_StdioIoctl_Diagnostics_",
    "CarX_PC_R3D49_StdioWrite_Diagnostics_")
store.write_text(s)

s = main.read_text()
s = one(s,
    "10 | R3D48 — ioctl الطرفية للخرج القياسي",
    "10 | R3D49 — كتابة stdout الآمنة داخل Wine")
main.write_text(s)

s = gradle.read_text()
s = one(s, "versionCode 72", "versionCode 73")
s = one(s,
    "0.72-r3d48-stdio-ioctl-tcgets",
    "0.73-r3d49-stdio-write")
gradle.write_text(s)

print("R3D49_SOURCE_VERIFIED_STDOUT_WRITE1_BOUNDED_LOCAL_COPY_INTEGRATED")
print("R3D49_GUEST_READ_OWNERSHIP_STACK_COMMITTED_BRK_OR_READABLE_MMAP_ONLY")
print("R3D49_NO_GUEST_POINTER_OR_UNKNOWN_DESCRIPTOR_HOST_FORWARDING")
