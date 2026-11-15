#!/usr/bin/env python3
"""R3D39: uniquely identify the built original JNI/FEX guest runtime and VFS result."""
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: promote_r3d39_trace.py /tmp/carxpc")
app=Path(sys.argv[1])
root=app/"app/src/main"
cpp=root/"cpp/carx_r3d4_first_syscall.cpp"
activity=root/"java/com/r4/carxpc/R3D4ProbeActivity.java"
main=root/"java/com/r4/carxpc/MainActivity.java"
report_store=root/"java/com/r4/carxpc/R3D8JsonReportStore.java"
gradle=app/"app/build.gradle"
assert all(p.is_file() for p in (cpp,activity,main,report_store,gradle))

def once(t, old, new):
    assert t.count(old)==1, ("R3D39_SOURCE_DRIFT",old[:120],t.count(old))
    return t.replace(old,new,1)

s=cpp.read_text()
s=once(s,
'''              const auto found=GuestReadOnlyFiles.open_guest_file(
                  GuestRootfsDirFD,guestPath);''',
'''              carx_r3d6::note("N60_R3D39_REAL_FEX_OPENAT_REACHED_PATCHED_ROOTFS");
              const auto found=GuestReadOnlyFiles.open_guest_file(
                  GuestRootfsDirFD,guestPath);
              char r39Evidence[160]{};
              std::snprintf(r39Evidence,sizeof(r39Evidence),
                  "N60_R3D39_OPENAT_STATE_%u_REASON_%u_RETURN_%lld",
                  static_cast<unsigned>(found.state),
                  static_cast<unsigned>(found.reason),
                  static_cast<long long>(found.value));
              carx_r3d6::note(r39Evidence);''')
cpp.write_text(s)

s=activity.read_text()
s=once(s,'''r4.carx.r3d33.integrated-104-preflight-owned-vm-rootfs-vfs-fex512.v1''',
          '''r4.carx.r3d39.real-guest-rootfs-runtime-trace-fex512.v1''')
s=once(s,'''07H_R3D33_BATCH104_UNIFIED_SOURCE_WINE_FEX512''',
          '''07H_R3D39_TRACE_WINE_ROOTFS_FEX512''')
s=once(s,'''07H_INTEGRATED_WINE_GNU_LDSO_LIBC_ROOTFS_BATCH104_VM_PATH_FEX512''',
          '''07H_R3D39_ROOTFS_OPENAT_TRACE_AUTHENTIC_FEX512''')
s=once(s,'''        report.put("r3d33_guest_vm_path_preflight_count",pathCases);''',
'''        report.put("r3d39_apk_runtime_identity","R3D39_v63_PATCHED_NATIVE_ROOTFS_TRACE");
        report.put("r3d39_real_fex_rootfs_walker_entered",
          phases.toString().contains("N60_R3D39_REAL_FEX_OPENAT_REACHED_PATCHED_ROOTFS"));
        report.put("r3d33_guest_vm_path_preflight_count",pathCases);''')
# Button is a single UI entry: avoids requiring a menu change.
s=once(s,'''R3D33 Batch 104 + Wine 512''',
          '''R3D39 Trace RootFS + Wine 512''')
activity.write_text(s)

s=report_store.read_text()
s=once(s,'''CarX_PC_R3D33_Batch104GuestPaths_Diagnostics_''',
          '''CarX_PC_R3D39_RootfsTrace_Diagnostics_''')
report_store.write_text(s)

s=main.read_text()
s=once(s,'''10 | R3D33 — فحص 104 حالات ومسارات Wine''',
          '''10 | R3D39 — إثبات تشغيل Wine RootFS''')
main.write_text(s)

s=gradle.read_text()
s=once(s,'''versionCode 62''','''versionCode 63''')
s=once(s,'''0.62-r3d38-wine-rootfs-openat-safe''',
          '''0.63-r3d39-rootfs-openat-verified-trace''')
gradle.write_text(s)

assert "N60_R3D39_REAL_FEX_OPENAT_REACHED_PATCHED_ROOTFS" in cpp.read_text()
assert "r3d39_apk_runtime_identity" in activity.read_text()
assert "versionCode 63" in gradle.read_text()
print("R3D39_NATIVE_SOURCE_ANDROID_REPORT_IDENTITY_PATCHED")
