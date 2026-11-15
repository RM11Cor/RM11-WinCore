#!/usr/bin/env python3
"""R3D45: original libc x86 newfstatat262 with trusted guest path and rootfs."""
from pathlib import Path
import sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_r3d45_newfstatat262.py /tmp/carxpc")
app=Path(sys.argv[1])/"app"
cpp=app/"src/main/cpp/carx_r3d4_first_syscall.cpp"
act=app/"src/main/java/com/r4/carxpc/R3D4ProbeActivity.java"
store=app/"src/main/java/com/r4/carxpc/R3D8JsonReportStore.java"
main=app/"src/main/java/com/r4/carxpc/MainActivity.java"
gradle=app/"build.gradle"
assert all(p.is_file() for p in (cpp,act,store,main,gradle))
def once(s,old,new):
 n=s.count(old)
 assert n==1,("R3D45_SOURCE_DRIFT",old[:140],n)
 return s.replace(old,new,1)
s=cpp.read_text()
s=once(s,'#include "carxpc/r3d44/native/source_verified_nscd_connect.hpp"',
'''#include "carxpc/r3d44/native/source_verified_nscd_connect.hpp"
#include "carxpc/r3d45/native/source_verified_newfstatat262.hpp"''')
s=once(s,
'''        // R3D44: index81 source-verified glibc connect42, fd117,''',
'''        // R3D45: R3D44 device observed source-verified x86_64 libc
        // newfstatat(262) callback index86 after two successful NSCD
        // connects returning -ENOENT, with dirfd AT_FDCWD (0xffffff9c),
        // path from mapped libc and 144-byte stat dest in owned stack.
        // File lookup stays within app-private rootfd, with in-rootfs
        // symlink resolution. No raw guest pointer or path to Android.
        if(number==carx_r3d45::kNewfstatat) {
          if(Mode!=4 || Seen<4) {
            carx_r3d6::note("E_R3D45_NEWFSTATAT_WRONG_WITNESS_MODE");
            ::_exit(210);
          }
          const auto st=carx_r3d45::source_verified_newfstatat(
            number,arg0,arg1,arg2,arg3,GuestRootfsDirFD,
            [&](uint64_t p,uint64_t n)->bool{
              return carx_r3d18::owned_stack_write_bounds(p,n) ||
                carx_r3d33::brk_readable(p,n,BRKBase,GuestBrkCurrent) ||
                GuestMaps.owned_readable_range(p,n);
            },
            [&](uint64_t p,uint64_t n)->bool{
              return carx_r3d18::owned_stack_write_bounds(p,n) ||
                carx_r3d33::brk_readable(p,n,BRKBase,GuestBrkCurrent) ||
                GuestMaps.owned_writable_range(p,n);
            });
          char argsMark[146]{};
          std::snprintf(argsMark,sizeof(argsMark),
             "N73_R3D45_SOURCE_LOCKED_NEWFSTATAT_DIRFD_%llu_FLAGS_%llu",
             static_cast<unsigned long long>(arg0),
             static_cast<unsigned long long>(arg3));
          carx_r3d6::note(argsMark);
          if(st.guestPath.status==carx_r3d33::PathStatus::Okay) {
             char pathMark[166]{};
             carx_r3d45::path_hex_marker(st.guestPath,pathMark);
             carx_r3d6::note(pathMark);
          }
          if(!st.handled) {
             char reasonMark[132]{};
             std::snprintf(reasonMark,sizeof(reasonMark),
               "E_R3D45_NEWFSTATAT_UNSAFE_REASON_%u",
               static_cast<unsigned>(st.reason));
             carx_r3d6::note(reasonMark);
             ::_exit(211);
          }
          if(st.value==0)
             carx_r3d6::note("N75_R3D45_OWNED_GUEST_STAT144_WRITTEN");
          else {
             char negativeMark[136]{};
             std::snprintf(negativeMark,sizeof(negativeMark),
               "N75_R3D45_ROOTFS_REAL_NEG_ERRNO_%llu",
               static_cast<unsigned long long>(-st.value));
             carx_r3d6::note(negativeMark);
          }
          accept(st.value,
             "N22_BATCH_RETURN_R3D45_SOURCE_VERIFIED_LIBC_NEWFSTATAT262");
          return;
        }
        // R3D44: index81 source-verified glibc connect42, fd117,''')
assert all(x in s for x in (
 "N75_R3D45_OWNED_GUEST_STAT144_WRITTEN",
 "N22_BATCH_RETURN_R3D45_SOURCE_VERIFIED_LIBC_NEWFSTATAT262",
 "N22_BATCH_RETURN_R3D44_SOURCE_VERIFIED_LIBC_NSCD_CONNECT42",
 "context->ExecuteThread(thread)"))
cpp.write_text(s)
s=act.read_text()
s=once(s,"r4.carx.r3d44.source-verified-glibc-nscd-connect-fex512.v1",
        "r4.carx.r3d45.source-owned-glibc-newfstatat-fex512.v1")
s=once(s,"07H_R3D44_NSCD_CONNECT42_AUTHENTIC_FEX512",
        "07H_R3D45_NEWFSTATAT262_AUTHENTIC_FEX512")
s=once(s,"07H_R3D44_NSCD_CONNECT42_WINE_FEX512",
        "07H_R3D45_NEWFSTATAT262_WINE_FEX512")
s=once(s,"R3D44 NSCD connect + Wine 512",
        "R3D45 newfstatat + Wine 512")
s=once(s,
'''        report.put("r3d44_apk_runtime_identity","R3D44_v68_ROOTFS_PROVEN_NSCD_CONNECT42");''',
'''        report.put("r3d44_apk_runtime_identity","R3D44_v68_ROOTFS_PROVEN_NSCD_CONNECT42");
        report.put("r3d45_apk_runtime_identity","R3D45_v69_SOURCE_VERIFIED_LIBC_NEWFSTATAT262");
        report.put("r3d45_newfstatat262_observed",
          phases.toString().contains("N73_R3D45_SOURCE_LOCKED_NEWFSTATAT_DIRFD_"));
        report.put("r3d45_guest_stat_path_source_captured",
          phases.toString().contains("N74_R3D45_GUEST_FSTATAT_PATH_HEX_"));
        report.put("r3d45_newfstatat_guest_stat144_written",
          phases.toString().contains("N75_R3D45_OWNED_GUEST_STAT144_WRITTEN"));
        report.put("r3d45_newfstatat_guest_rootfs_negative_errno",
          phases.toString().contains("N75_R3D45_ROOTFS_REAL_NEG_ERRNO_"));
        report.put("r3d45_newfstatat_source_locked_reply",
          phases.toString().contains("N22_BATCH_RETURN_R3D45_SOURCE_VERIFIED_LIBC_NEWFSTATAT262"));
        report.put("r3d45_unknown_guest_paths_host_forwarded",false);''')
act.write_text(s)
s=store.read_text()
s=once(s,"CarX_PC_R3D44_NSCDConnect_Diagnostics_",
        "CarX_PC_R3D45_Newfstatat_Diagnostics_")
store.write_text(s)
s=main.read_text()
s=once(s,"10 | R3D44 — اتصال NSCD المقيد لـ Wine",
        "10 | R3D45 — فحص ملفات Wine (newfstatat)")
main.write_text(s)
s=gradle.read_text()
s=once(s,"versionCode 68","versionCode 69")
s=once(s,"0.68-r3d44-nscd-source-verified-connect",
        "0.69-r3d45-source-locked-newfstatat262")
gradle.write_text(s)
print("R3D45_SOURCE_OWNED_LIBC_NEWFSTATAT262_X86_STAT144_APP_ROOTFS_INTEGRATED")
print("R3D45_ABSOLUTE_PATH_AT_FDCWD_FLAGS0_NO_HOST_POINTER_FORWARD")
