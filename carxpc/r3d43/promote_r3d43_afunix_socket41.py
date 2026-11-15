#!/usr/bin/env python3
"""R3D43: real AF_UNIX socket syscall41 and virtual guest FD117-124 in genuine FEX JNI."""
from pathlib import Path
import sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_r3d43_afunix_socket41.py /tmp/carxpc")
app=Path(sys.argv[1])/"app"
cpp=app/"src/main/cpp/carx_r3d4_first_syscall.cpp"
act=app/"src/main/java/com/r4/carxpc/R3D4ProbeActivity.java"
store=app/"src/main/java/com/r4/carxpc/R3D8JsonReportStore.java"
main=app/"src/main/java/com/r4/carxpc/MainActivity.java"
gradle=app/"build.gradle"
assert all(p.is_file() for p in (cpp,act,store,main,gradle))
def once(s,old,new):
 n=s.count(old)
 assert n==1,("R3D43_SOURCE_DRIFT",old[:130],n)
 return s.replace(old,new,1)

s=cpp.read_text()
s=once(s,
'#include "carxpc/r3d42/native/source_locked_faccessat2.hpp"',
'''#include "carxpc/r3d42/native/source_locked_faccessat2.hpp"
#include "carxpc/r3d43/native/source_locked_afunix_socket_vfd.hpp"''')
s=once(s,
'''  carx_r3d33::ReadOnlyFiles GuestReadOnlyFiles{};''',
'''  carx_r3d33::ReadOnlyFiles GuestReadOnlyFiles{};
  // Native ownership of Unix sockets is distinct from virtual RootFS files.
  carx_r3d43::OwnedUnixSockets GuestUnixSockets{};''')
s=once(s,
'''        const auto misc=carx_r3d31::source_locked_dispatch(
           number,arg0,arg1,arg2,writeOwnedGuest);''',
'''        // R3D43: genuine libc callback index80 socket(41,AF_UNIX,
        // SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0). Create a real
        // native AF_UNIX socket with validated constants but publish
        // only guest fd117..124, never a raw native fd or guest pointer.
        if(number==carx_r3d43::kX86Socket ||
           (number==carx_r3d43::kX86Close && GuestUnixSockets.owns(arg0))) {
          const auto result=GuestUnixSockets.dispatch(
            number,arg0,arg1,arg2);
          if(!result.handled) {
            char reasonMark[130]{};
            std::snprintf(reasonMark,sizeof(reasonMark),
               "E_R3D43_GUEST_UNIX_SOCKET_UNSUPPORTED_REASON_%u",
               static_cast<unsigned>(result.reason));
            carx_r3d6::note(reasonMark);
            ::_exit(207);
          }
          if(number==carx_r3d43::kX86Socket) {
            char detailMark[140]{};
            std::snprintf(detailMark,sizeof(detailMark),
               "N67_R3D43_AF_UNIX_SOCKET_DOMAIN_%llu_TYPE_%llu_PROTO_%llu",
               static_cast<unsigned long long>(arg0),
               static_cast<unsigned long long>(arg1),
               static_cast<unsigned long long>(arg2));
            carx_r3d6::note(detailMark);
            if(result.value>=carx_r3d43::kFirstGuestFd) {
              char fdMark[110]{};
              std::snprintf(fdMark,sizeof(fdMark),
                 "N68_R3D43_REAL_AF_UNIX_STREAM_NATIVE_SOCKET_GUEST_VFD_%llu",
                 static_cast<unsigned long long>(result.value));
              carx_r3d6::note(fdMark);
            }
          } else {
            carx_r3d6::note("N69_R3D43_AF_UNIX_VIRTUAL_SOCKET_GUEST_CLOSE");
          }
          accept(result.value,
             "N22_BATCH_RETURN_R3D43_SOURCE_LOCKED_AF_UNIX_SOCKET41");
          return;
        }
        const auto misc=carx_r3d31::source_locked_dispatch(
           number,arg0,arg1,arg2,writeOwnedGuest);''')
assert all(x in s for x in (
 "N68_R3D43_REAL_AF_UNIX_STREAM_NATIVE_SOCKET_GUEST_VFD_",
 "N22_BATCH_RETURN_R3D43_SOURCE_LOCKED_AF_UNIX_SOCKET41",
 "N22_BATCH_RETURN_R3D42_SOURCE_LOCKED_FACCESSAT2_F_OK",
 "context->ExecuteThread(thread)"))
cpp.write_text(s)

s=act.read_text()
s=once(s,"r4.carx.r3d42.faccessat2-source-locked-rootfs-fex512.v1",
        "r4.carx.r3d43.afunix-socket-native-vfd-fex512.v1")
s=once(s,"07H_R3D42_FACCESSAT2_GUEST_ROOTFS_AUTHENTIC_FEX512",
        "07H_R3D43_AFUNIX_SOCKET_NATIVE_VFD_AUTHENTIC_FEX512")
s=once(s,"07H_R3D42_FACCESSAT2_WINE_FEX512",
        "07H_R3D43_AFUNIX_SOCKET_WINE_FEX512")
s=once(s,"R3D42 faccessat2 + Wine 512",
        "R3D43 AF_UNIX socket + Wine 512")
s=once(s,
'''        report.put("r3d42_apk_runtime_identity","R3D42_v66_GUEST_FACCESSAT2_FOK_AT_EACCESS");''',
'''        report.put("r3d42_apk_runtime_identity","R3D42_v66_GUEST_FACCESSAT2_FOK_AT_EACCESS");
        report.put("r3d43_apk_runtime_identity","R3D43_v67_REAL_AF_UNIX_STREAM_NATIVE_VFD117");
        report.put("r3d43_native_unix_socket41_observed",
          phases.toString().contains("N67_R3D43_AF_UNIX_SOCKET_DOMAIN_"));
        report.put("r3d43_native_unix_socket41_allocated",
          phases.toString().contains("N68_R3D43_REAL_AF_UNIX_STREAM_NATIVE_SOCKET_GUEST_VFD_"));
        report.put("r3d43_socket_fd117_no_guest_host_fd_passthrough",true);
        report.put("r3d43_socket_connect_not_implemented",true);''')
act.write_text(s)

s=store.read_text()
s=once(s,"CarX_PC_R3D42_Faccessat2_Diagnostics_",
        "CarX_PC_R3D43_AFUnixSocket_Diagnostics_")
store.write_text(s)
s=main.read_text()
s=once(s,"10 | R3D42 — فحص وصول Wine لملفات RootFS",
        "10 | R3D43 — مقبس Unix الخاص بـ Wine")
main.write_text(s)
s=gradle.read_text()
s=once(s,"versionCode 66","versionCode 67")
s=once(s,"0.66-r3d42-guest-faccessat2-fok",
        "0.67-r3d43-afunix-native-socket-vfd")
gradle.write_text(s)
print("R3D43_SOURCE_LOCKED_LIBC_AFUNIX_SOCKET41_REAL_NATIVE_SOCKET_GUEST_VFD117_INTEGRATED")
print("R3D43_SOURCE_OWNED_FD117_124_NO_UNVERIFIED_GUEST_SOCKET_CONNECT")
