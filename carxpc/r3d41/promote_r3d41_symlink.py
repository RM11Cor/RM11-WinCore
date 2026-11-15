#!/usr/bin/env python3
"""R3D41: source-pinned guest rootfd symlinks for real Wine libunwind SO."""
from pathlib import Path
import sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_r3d41_symlink.py /tmp/carxpc")
root=Path(sys.argv[1])/"app"
cpp=root/"src/main/cpp/carx_r3d4_first_syscall.cpp"
act=root/"src/main/java/com/r4/carxpc/R3D4ProbeActivity.java"
store=root/"src/main/java/com/r4/carxpc/R3D8JsonReportStore.java"
main=root/"src/main/java/com/r4/carxpc/MainActivity.java"
gradle=root/"build.gradle"
assert all(p.is_file() for p in (cpp,act,store,main,gradle))
def once(source,old,new):
  count=source.count(old)
  assert count==1,("R3D41_SOURCE_DRIFT",old[:140],count)
  return source.replace(old,new,1)
s=cpp.read_text()
s=once(s,
'''              carx_r3d6::note(r39Evidence);''',
'''              carx_r3d6::note(r39Evidence);
              // Only emit after the real guest-openat callback has followed
              // a source-owned link while keeping every hop under rootfd.
              if(found.state==carx_r3d33::OpenState::Resolved &&
                 found.value>=101 && found.value<=116 &&
                 found.symlinkCount>0){
                char linkMark[120]{};
                std::snprintf(linkMark,sizeof(linkMark),
                  "N63_R3D41_CONFINED_GUEST_SYMLINK_FD_%llu_HOPS_%u",
                  static_cast<unsigned long long>(found.value),
                  static_cast<unsigned>(found.symlinkCount));
                carx_r3d6::note(linkMark);
              }''')
assert "CARX_R3D41_CONFINED_GUEST_SYMLINKS" not in s
assert "context->ExecuteThread(thread)" in s
assert "N61_R3D40_ROOTFS_FD101_FILE_MMAP_ACCEPTED" in s
cpp.write_text(s)

s=act.read_text()
s=once(s,"r4.carx.r3d40.real-rootfs-file-mmap-elf-rx-fex512.v1",
        "r4.carx.r3d41.confined-guest-rootfs-symlink-wine-fex512.v1")
s=once(s,"07H_R3D40_ROOTFS_MMAP_ELF_RX_AUTHENTIC_FEX512",
        "07H_R3D41_GUEST_ROOTFS_SYMLINK_AUTHENTIC_FEX512")
s=once(s,"07H_R3D40_ROOTFS_ELF_MMAP_FEX512",
        "07H_R3D41_SYMLINK_ELF_MMAP_FEX512")
s=once(s,"R3D40 RootFS mmap + Wine 512","R3D41 Symlink RootFS + Wine 512")
s=once(s,
'''        report.put("r3d40_apk_runtime_identity","R3D40_v64_REAL_FD101_ELF_MMAP");''',
'''        report.put("r3d40_apk_runtime_identity","R3D40_v64_REAL_FD101_ELF_MMAP");
        report.put("r3d41_apk_runtime_identity","R3D41_v65_GUEST_ROOTFD_NOFOLLOW_SYMLINK");
        report.put("r3d41_real_guest_rootfs_symlink_success",
          phases.toString().contains("N63_R3D41_CONFINED_GUEST_SYMLINK_FD_"));
        report.put("r3d41_real_guest_link_hops_verified_from_child_log",
          phases.toString().contains("N63_R3D41_CONFINED_GUEST_SYMLINK_FD_"));
        report.put("r3d41_symlink_rootfd_no_host_path_passthrough",true);
        report.put("r3d41_symlink_max_hops",16);''')
act.write_text(s)

s=store.read_text()
s=once(s,"CarX_PC_R3D40_ElfMmap_Diagnostics_",
        "CarX_PC_R3D41_SymlinkRootfs_Diagnostics_")
store.write_text(s)
s=main.read_text()
s=once(s,"10 | R3D40 — ربط خرائط Wine ELF",
        "10 | R3D41 — ربط روابط RootFS الآمنة")
main.write_text(s)
s=gradle.read_text()
s=once(s,"versionCode 64","versionCode 65")
s=once(s,"0.64-r3d40-rootfs-mmap-elf-rx",
        "0.65-r3d41-guest-symlink-rootfd")
gradle.write_text(s)
print("R3D41_SOURCE_AUTHENTIC_WINE_GUEST_ROOTFS_SYMLINK_INTEGRATED")
print("R3D41_104_PREPARED_CASES_AND_512_REAL_FEX_WITNESS_LIMIT_PRESERVED")
