#!/usr/bin/env python3
"""R3-C9: verify original libc fourth owned RW PT_LOAD, retaining first RO, RX, third RO and W^X.
The KERNIX original source intentionally exits 117 at its next bounded syscall,
not 142: the latter belonged to the previously unimplemented fourth map.
"""
from pathlib import Path
import re, sys
root=Path(sys.argv[1])
p=root/"app/build.gradle"
s=p.read_text()
s,n=re.subn(r"\bversionCode\s+15\b","versionCode 16",s)
assert n==1,("R3C8 versionCode15 expected",n)
s,n=re.subn(r"\bversionName\s+'[^']+'","versionName '0.16-r3c9-libc-rw-ptload'",s)
assert n==1
p.write_text(s)
p=root/"app/src/main/java/com/r4/carxpc/FexIntegrationProbe.java"
s=p.read_text()
def one(before,after):
    global s
    n=s.count(before)
    assert n==1,("expected unique prior R3C8 gate",n,before)
    s=s.replace(before,after,1)
one(
'      String nextMapGuard="KERNIX_G0_ORIGINAL_LDSO_LIBC_LARGE_RO_MMAP_PRECONDITION_REJECT after_first=3";',
'      String fourthRWMap="KERNIX_G0_REAL_ORIGINAL_GNU_LIBC_FOURTH_FIXED_RW_MMAP_PTLOAD_OFFSET_SHIFT_SOURCE_0x1fe000_TO_VADDR_0x1ff000_LENGTH_0x6000_NO_NATIVE_FIXED_NO_WX_PASS base=8041ff000";')
one(
'      int f=log.indexOf(read832),h=log.indexOf(pread784),i=log.indexOf(fstat5),k=log.indexOf(firstMap),m=log.indexOf(rxTextMap),n=log.indexOf(thirdROMap),l=log.indexOf(nextMapGuard),g=log.indexOf(nextSyscall);',
'      int f=log.indexOf(read832),h=log.indexOf(pread784),i=log.indexOf(fstat5),k=log.indexOf(firstMap),m=log.indexOf(rxTextMap),n=log.indexOf(thirdROMap),q=log.indexOf(fourthRWMap),g=log.indexOf(nextSyscall);')
one(
'''      boolean roProved=n>m && rxProved;
      boolean safeBoundary=l>n && roProved && exit==142;''',
'''      boolean roProved=n>m && rxProved;
      boolean rwProved=q>n && roProved;
      boolean safeBoundary=g>q && rwProved && exit==117;''')
one(
'''      j.put("original_libc_fourth_mapping_intentionally_guarded",safeBoundary);''',
'''      j.put("original_libc_fourth_mapping_intentionally_guarded",false);
      j.put("original_libc_fourth_data_rw_ptload_verified",rwProved);
      j.put("original_libc_fourth_data_rw_wx_safe_verified",rwProved);
      j.put("original_libc_next_unsupported_syscall_after_fourth_rw_observed",safeBoundary);''')
one(
'''      j.put("original_libc_next_mapping_intentionally_guarded",safeBoundary);''',
'''      j.put("original_libc_next_mapping_intentionally_guarded",false);''')
one(
'''        preadProved && fstatProved && mmapProved && rxProved && roProved &&
        safeBoundary && nextProved && finished && !bad.get();''',
'''        preadProved && fstatProved && mmapProved && rxProved && roProved &&
        rwProved && safeBoundary && nextProved && finished && !bad.get();''')
one(
'''      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_LIBC_THIRD_SOURCE_AUTHENTICATED_RO_PTLOAD_MAPPED_FOURTH_MAPPING_SAFELY_GUARDED":
        (roProved?"LIBC_THIRD_RO_PTLOAD_PROVEN_FOURTH_MAPPING_UNCONFIRMED":
         rxProved?"LIBC_RX_PTLOAD_PROVEN_THIRD_RO_UNCONFIRMED":''',
'''      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_LIBC_FOURTH_SOURCE_AUTHENTICATED_RW_PTLOAD_MAPPED_NEXT_SYSCALL_STOP":
        (rwProved?"LIBC_FOURTH_RW_PTLOAD_PROVEN_NEXT_SYSCALL_UNCONFIRMED":
         roProved?"LIBC_THIRD_RO_PTLOAD_PROVEN_FOURTH_RW_UNCONFIRMED":
         rxProved?"LIBC_RX_PTLOAD_PROVEN_THIRD_RO_UNCONFIRMED":''')
assert "fourthRWMap" in s
p.write_text(s)

p=root/"app/src/main/java/com/r4/carxpc/MainActivity.java"
s=p.read_text()
for old,new in {
 "المرحلة R3-C8 — ربط مقطع بيانات libc الثالث RO":"المرحلة R3-C9 — ربط مقطع بيانات libc الرابع RW",
 "R3-C8 | فحص PT_LOAD الثالث RO لملف libc":"R3-C9 | فحص PT_LOAD الرابع RW لملف libc",
 "نجح ربط مقطع libc الثالث للقراءة فقط؛ لم تكتمل glibc":
   "نجح ربط مقطع بيانات libc الرابع RW دون W+X؛ glibc لم تكتمل"
}.items():
    assert s.count(old)==1,("UI",old)
    s=s.replace(old,new)
p.write_text(s)
print("CARX_R3C9_GENUINE_GNU_LIBC_FOURTH_OWNED_RW_PTLOAD_VERSION16_GATE_READY")
