#!/usr/bin/env python3
"""R3D42: real x86 FEX guest faccessat2(439) F_OK AT_EACCESS rooted metadata."""
from pathlib import Path
import sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_r3d42_faccessat2.py /tmp/carxpc")
app=Path(sys.argv[1])/"app"
cpp=app/"src/main/cpp/carx_r3d4_first_syscall.cpp"
act=app/"src/main/java/com/r4/carxpc/R3D4ProbeActivity.java"
store=app/"src/main/java/com/r4/carxpc/R3D8JsonReportStore.java"
main=app/"src/main/java/com/r4/carxpc/MainActivity.java"
gradle=app/"build.gradle"
assert all(p.is_file() for p in (cpp,act,store,main,gradle))
def once(s,old,new):
 n=s.count(old)
 assert n==1,("R3D42_SOURCE_DRIFT",old[:130],n)
 return s.replace(old,new,1)

s=cpp.read_text()
s=once(s,
'#include "carxpc/r3d40/native/verified_rootfs_mmap_source.hpp"',
'''#include "carxpc/r3d40/native/verified_rootfs_mmap_source.hpp"
#include "carxpc/r3d42/native/source_locked_faccessat2.hpp"''')
s=once(s,
'''        const auto misc=carx_r3d31::source_locked_dispatch(
            number,arg0,arg1,arg2,writeOwnedGuest);''',
'''        // R3D42: Observed genuine FEX x86_64 glibc syscall 439 at index66
        // after Wine libunwind/liblzma ELF source loading. The 4th x86
        // argument FLAGS is R10=arg3, NOT the guest pointer or host FD.
        if(number==carx_r3d42::kX64Faccessat2) {
          if(Mode!=4 || Seen<4) {
            carx_r3d6::note("E_R3D42_FACCESSAT2_WRONG_WITNESS_MODE");
            ::_exit(205);
          }
          const auto access=carx_r3d42::source_verified_faccessat2(
            number,arg0,arg1,arg2,arg3,GuestRootfsDirFD,
            [&](uint64_t p,uint64_t n)->bool{
              return carx_r3d18::owned_stack_write_bounds(p,n) ||
                carx_r3d33::brk_readable(p,n,BRKBase,GuestBrkCurrent) ||
                GuestMaps.owned_readable_range(p,n);
            });
          char argsMark[124]{};
          std::snprintf(argsMark,sizeof(argsMark),
            "N64_R3D42_FACCESSAT2_MODE_%llu_FLAGS_%llu",
            static_cast<unsigned long long>(arg2),
            static_cast<unsigned long long>(arg3));
          carx_r3d6::note(argsMark);
          if(access.path.status==carx_r3d33::PathStatus::Okay) {
            char pathMark[144]{};
            carx_r3d42::path_hex_marker(access.path,pathMark);
            carx_r3d6::note(pathMark);
          }
          if(!access.handled) {
            char reasonMark[132]{};
            std::snprintf(reasonMark,sizeof(reasonMark),
              "E_R3D42_FACCESSAT2_UNSUPPORTED_REASON_%u",
              static_cast<unsigned>(access.reason));
            carx_r3d6::note(reasonMark);
            ::_exit(206);
          }
          if(access.value==0) {
            carx_r3d6::note("N66_R3D42_FACCESSAT2_FOK_GUEST_ROOTFS_EXISTS");
          } else {
            char negativeMark[132]{};
            std::snprintf(negativeMark,sizeof(negativeMark),
              "N66_R3D42_FACCESSAT2_FOK_GUEST_NEG_ERRNO_%llu",
              static_cast<unsigned long long>(-access.value));
            carx_r3d6::note(negativeMark);
          }
          accept(access.value,
            "N22_BATCH_RETURN_R3D42_SOURCE_LOCKED_FACCESSAT2_F_OK");
          return;
        }
        const auto misc=carx_r3d31::source_locked_dispatch(
            number,arg0,arg1,arg2,writeOwnedGuest);''')
assert all(x in s for x in ("N66_R3D42_FACCESSAT2_FOK_GUEST_ROOTFS_EXISTS",
"N22_BATCH_RETURN_R3D42_SOURCE_LOCKED_FACCESSAT2_F_OK",
"N63_R3D41_CONFINED_GUEST_SYMLINK_FD_",
"context->ExecuteThread(thread)"))
cpp.write_text(s)

s=act.read_text()
s=once(s,"r4.carx.r3d41.confined-guest-rootfs-symlink-wine-fex512.v1",
        "r4.carx.r3d42.faccessat2-source-locked-rootfs-fex512.v1")
s=once(s,"07H_R3D41_GUEST_ROOTFS_SYMLINK_AUTHENTIC_FEX512",
        "07H_R3D42_FACCESSAT2_GUEST_ROOTFS_AUTHENTIC_FEX512")
s=once(s,"07H_R3D41_SYMLINK_ELF_MMAP_FEX512",
        "07H_R3D42_FACCESSAT2_WINE_FEX512")
s=once(s,"R3D41 Symlink RootFS + Wine 512","R3D42 faccessat2 + Wine 512")
s=once(s,
'''        report.put("r3d41_apk_runtime_identity","R3D41_v65_GUEST_ROOTFD_NOFOLLOW_SYMLINK");''',
'''        report.put("r3d41_apk_runtime_identity","R3D41_v65_GUEST_ROOTFD_NOFOLLOW_SYMLINK");
        report.put("r3d42_apk_runtime_identity","R3D42_v66_GUEST_FACCESSAT2_FOK_AT_EACCESS");
        report.put("r3d42_faccessat2_source_verified_observed",
          phases.toString().contains("N64_R3D42_FACCESSAT2_MODE_"));
        report.put("r3d42_faccessat2_fok_returned",
          phases.toString().contains("N22_BATCH_RETURN_R3D42_SOURCE_LOCKED_FACCESSAT2_F_OK"));
        report.put("r3d42_faccessat2_guest_path_source_captured",
          phases.toString().contains("N65_R3D42_FACCESSAT2_GUEST_PATH_HEX_"));
        report.put("r3d42_faccessat2_unsafe_semantics_rejected",
          phases.toString().contains("E_R3D42_FACCESSAT2_UNSUPPORTED_REASON_"));
        report.put("r3d42_no_unverified_guest_path_host_forward",true);''')
act.write_text(s)

s=store.read_text()
s=once(s,"CarX_PC_R3D41_SymlinkRootfs_Diagnostics_",
        "CarX_PC_R3D42_Faccessat2_Diagnostics_")
store.write_text(s)
s=main.read_text()
s=once(s,"10 | R3D41 — ربط روابط RootFS الآمنة",
        "10 | R3D42 — فحص وصول Wine لملفات RootFS")
main.write_text(s)
s=gradle.read_text()
s=once(s,"versionCode 65","versionCode 66")
s=once(s,"0.65-r3d41-guest-symlink-rootfd",
        "0.66-r3d42-guest-faccessat2-fok")
gradle.write_text(s)
print("R3D42_REAL_FEX_X86_64_GLIBC_FACCESSAT2_439_F_OK_SOURCE_LOCKED_INSTALLED")
print("R3D42_AT_EACCESS_ORIGINAL_ARG3_PATH_BOUNDED_ROOTFD_SYMLINK_SAFE")
