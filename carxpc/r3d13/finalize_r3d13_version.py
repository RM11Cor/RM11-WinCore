#!/usr/bin/env python3
"""Source-pinned R3D13 final corrected packaging, signed versionCode 41.

Preserves all existing stages and the strict O_CLOEXEC-only policy; the
mode argument is unused if O_CREAT/O_TMPFILE are absent.
"""
import re,sys
from pathlib import Path
if len(sys.argv)!=2:raise SystemExit("usage: finalize_r3d13_version.py /tmp/carxpc")
base=Path(sys.argv[1]); gradle=base/"app/build.gradle"
native=base/"app/src/main/cpp/carx_r3d4_first_syscall.cpp"
activity=base/"app/src/main/java/com/r4/carxpc/R3D4ProbeActivity.java"
header=Path("carxpc/r3d13/native/strict_batch_policy.hpp")
assert all(p.is_file() for p in (gradle,native,activity,header))
s=gradle.read_text()
s,n=re.subn(r"\bversionCode\s+40\b","versionCode 41",s)
assert n==1,"REQUIRES_R3D13_40"
s,n=re.subn(r"versionName\s+'0.40-r3d13-batched-ldso-syscall-diagnostics'",
 "versionName '0.41-r3d13-batched-syscalls-verified'",s)
assert n==1
gradle.write_text(s)
src=header.read_text()
assert "flags==kOpenAtCloexecOnly;" in src
assert "O_CREAT or O_TMPFILE." in src
assert "return (dirfd==kAtFdcwdZeroExtended" in src
assert "N22_BATCH_RETURN_OPENAT_CACHE_ENOENT" in native.read_text()
assert "BATCH_HALTED_AT_FIRST_UNSUPPORTED_SYSCALL" in activity.read_text()
print("R3D13_41_FINAL_SOURCE_GUARD_POLICY_AND_JSON_AUDIT_OK")
