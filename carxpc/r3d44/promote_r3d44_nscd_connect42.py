#!/usr/bin/env python3
"""R3D44: authentic libc connect(42) scoped to verified missing NSCD endpoint."""
from pathlib import Path
import sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_r3d44_nscd_connect42.py /tmp/carxpc")
app=Path(sys.argv[1])/"app"
cpp=app/"src/main/cpp/carx_r3d4_first_syscall.cpp"
act=app/"src/main/java/com/r4/carxpc/R3D4ProbeActivity.java"
store=app/"src/main/java/com/r4/carxpc/R3D8JsonReportStore.java"
main=app/"src/main/java/com/r4/carxpc/MainActivity.java"
gradle=app/"build.gradle"
assert all(p.is_file() for p in (cpp,act,store,main,gradle))
def once(s,old,new):
 n=s.count(old)
 assert n==1,("R3D44_SOURCE_DRIFT",old[:140],n)
 return s.replace(old,new,1)

s=cpp.read_text()
s=once(s,'#include "carxpc/r3d43/native/source_locked_afunix_socket_vfd.hpp"',
'''#include "carxpc/r3d43/native/source_locked_afunix_socket_vfd.hpp"
#include "carxpc/r3d44/native/source_verified_nscd_connect.hpp"''')
s=once(s,
'''        // R3D43: genuine libc callback index80 socket(41,AF_UNIX,''',
'''        // R3D44: index81 source-verified glibc connect42, fd117,
        // pointer to owned guest stack, x86 sockaddr_un length 110.
        // Do NOT forward guest sockaddr/host path. Only return -ENOENT
        // once a jailed, app-private RootFS lookup proves the exact
        // glibc NSCD endpoint (/var/run/nscd/socket) is missing.
        if(number==carx_r3d44::kX86Connect) {
          if(Mode!=4 || Seen<4) {
            carx_r3d6::note("E_R3D44_CONNECT_WRONG_GUEST_WITNESS_MODE");
            ::_exit(208);
          }
          const auto connect=carx_r3d44::source_verified_nscd_connect(
            number,arg0,arg1,arg2,GuestRootfsDirFD,GuestUnixSockets,
            [&](uint64_t p,uint64_t n)->bool{
              return carx_r3d18::owned_stack_write_bounds(p,n) ||
                carx_r3d33::brk_readable(p,n,BRKBase,GuestBrkCurrent) ||
                GuestMaps.owned_readable_range(p,n);
            });
          char argsMark[128]{};
          std::snprintf(argsMark,sizeof(argsMark),
            "N70_R3D44_SOURCE_LOCKED_CONNECT_GUEST_FD_%llu_LENGTH_%llu",
            static_cast<unsigned long long>(arg0),
            static_cast<unsigned long long>(arg2));
          carx_r3d6::note(argsMark);
          if(connect.pathLength>0) {
            char pathMark[190]{};
            carx_r3d44::path_hex_marker(connect,pathMark);
            carx_r3d6::note(pathMark);
          }
          if(!connect.handled) {
            char rejectedMark[130]{};
            std::snprintf(rejectedMark,sizeof(rejectedMark),
              "E_R3D44_CONNECT_NOT_SOURCE_VERIFIED_NSCD_REASON_%u",
              static_cast<unsigned>(connect.reason));
            carx_r3d6::note(rejectedMark);
            ::_exit(209);
          }
          if(connect.value==-ENOENT)
            carx_r3d6::note("N72_R3D44_GUEST_ROOTFS_NSCD_SOCKET_CONFIRMED_ABSENT_ENOENT");
          else
            carx_r3d6::note("N72_R3D44_GUEST_ROOTFS_NSCD_PARENT_NOT_DIRECTORY_ENOTDIR");
          accept(connect.value,
             "N22_BATCH_RETURN_R3D44_SOURCE_VERIFIED_LIBC_NSCD_CONNECT42");
          return;
        }
        // R3D43: genuine libc callback index80 socket(41,AF_UNIX,''')
assert all(x in s for x in ("N72_R3D44_GUEST_ROOTFS_NSCD_SOCKET_CONFIRMED_ABSENT_ENOENT",
 "N22_BATCH_RETURN_R3D44_SOURCE_VERIFIED_LIBC_NSCD_CONNECT42",
 "N68_R3D43_REAL_AF_UNIX_STREAM_NATIVE_SOCKET_GUEST_VFD_",
 "context->ExecuteThread(thread)"))
cpp.write_text(s)

s=act.read_text()
s=once(s,"r4.carx.r3d43.afunix-socket-native-vfd-fex512.v1",
        "r4.carx.r3d44.source-verified-glibc-nscd-connect-fex512.v1")
s=once(s,"07H_R3D43_AFUNIX_SOCKET_NATIVE_VFD_AUTHENTIC_FEX512",
        "07H_R3D44_NSCD_CONNECT42_AUTHENTIC_FEX512")
s=once(s,"07H_R3D43_AFUNIX_SOCKET_WINE_FEX512",
        "07H_R3D44_NSCD_CONNECT42_WINE_FEX512")
s=once(s,"R3D43 AF_UNIX socket + Wine 512",
        "R3D44 NSCD connect + Wine 512")
s=once(s,
'''        report.put("r3d43_apk_runtime_identity","R3D43_v67_REAL_AF_UNIX_STREAM_NATIVE_VFD117");''',
'''        report.put("r3d43_apk_runtime_identity","R3D43_v67_REAL_AF_UNIX_STREAM_NATIVE_VFD117");
        report.put("r3d44_apk_runtime_identity","R3D44_v68_ROOTFS_PROVEN_NSCD_CONNECT42");
        report.put("r3d44_original_libc_connect42_observed",
          phases.toString().contains("N70_R3D44_SOURCE_LOCKED_CONNECT_GUEST_FD_"));
        report.put("r3d44_guest_unix_sockaddr_path_source_captured",
          phases.toString().contains("N71_R3D44_SOCKADDR_GUEST_PATH_HEX_"));
        report.put("r3d44_nscd_socket_absent_verified_by_rootfs",
          phases.toString().contains("N72_R3D44_GUEST_ROOTFS_NSCD_SOCKET_CONFIRMED_ABSENT_ENOENT"));
        report.put("r3d44_nscd_connect_guest_enoent_reply",
          phases.toString().contains("N22_BATCH_RETURN_R3D44_SOURCE_VERIFIED_LIBC_NSCD_CONNECT42"));
        report.put("r3d44_unknown_socket_paths_host_forwarded",false);
        report.put("r3d44_wineserver_connect_implemented",false);''')
act.write_text(s)
s=store.read_text()
s=once(s,"CarX_PC_R3D43_AFUnixSocket_Diagnostics_",
        "CarX_PC_R3D44_NSCDConnect_Diagnostics_")
store.write_text(s)
s=main.read_text()
s=once(s,"10 | R3D43 — مقبس Unix الخاص بـ Wine",
        "10 | R3D44 — اتصال NSCD المقيد لـ Wine")
main.write_text(s)
s=gradle.read_text()
s=once(s,"versionCode 67","versionCode 68")
s=once(s,"0.67-r3d43-afunix-native-socket-vfd",
        "0.68-r3d44-nscd-source-verified-connect")
gradle.write_text(s)
print("R3D44_SOURCE_VERIFIED_LIBC_CONNECT42_GUEST_SOCKADDR_NSCD_ROOTFS_ABSENT_INSTALLED")
print("R3D44_NO_GUEST_POINTER_TO_ANDROID_CONNECT_NO_FAKE_SUCCESS")
