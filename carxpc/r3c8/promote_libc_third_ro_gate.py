#!/usr/bin/env python3
"""R3-C8: prove original GNU libc third readonly PT_LOAD segment mmap and stop safely before RW."""
from pathlib import Path
import re,sys
root=Path(sys.argv[1])
gradle=root/"app/build.gradle"
s=gradle.read_text()
s,n=re.subn(r"\bversionCode\s+14\b","versionCode 15",s)
assert n==1,("R3C7 versionCode14 expected",n)
s,n=re.subn(r"\bversionName\s+'[^']+'","versionName '0.15-r3c8-libc-ro-ptload'",s)
assert n==1
gradle.write_text(s)
probe=root/"app/src/main/java/com/r4/carxpc/FexIntegrationProbe.java"
s=probe.read_text()
def one(a,b):
    global s
    n=s.count(a)
    assert n==1,("expected unique",n,a)
    s=s.replace(a,b,1)
one(
'      String nextMapGuard="KERNIX_G0_ORIGINAL_LDSO_LIBC_LARGE_RO_MMAP_PRECONDITION_REJECT after_first=2";',
'''      String thirdROMap="KERNIX_G0_REAL_ORIGINAL_GNU_LIBC_THIRD_FIXED_RO_MMAP_PTLOAD_VERIFIED_SOURCE_NO_NATIVE_FIXED_NO_WX_PASS base=8041b0000 length=0x4f000 offset=0x1b0000";
      String nextMapGuard="KERNIX_G0_ORIGINAL_LDSO_LIBC_LARGE_RO_MMAP_PRECONDITION_REJECT after_first=3";''')
one(
'      int f=log.indexOf(read832),h=log.indexOf(pread784),i=log.indexOf(fstat5),k=log.indexOf(firstMap),m=log.indexOf(rxTextMap),l=log.indexOf(nextMapGuard),g=log.indexOf(nextSyscall);',
'      int f=log.indexOf(read832),h=log.indexOf(pread784),i=log.indexOf(fstat5),k=log.indexOf(firstMap),m=log.indexOf(rxTextMap),n=log.indexOf(thirdROMap),l=log.indexOf(nextMapGuard),g=log.indexOf(nextSyscall);')
one(
'''      boolean rxProved=m>k && mmapProved;
      boolean safeBoundary=l>m && rxProved && exit==142;''',
'''      boolean rxProved=m>k && mmapProved;
      boolean roProved=n>m && rxProved;
      boolean safeBoundary=l>n && roProved && exit==142;''')
one(
'''      j.put("original_libc_third_mapping_intentionally_guarded",safeBoundary);''',
'''      j.put("original_libc_third_mapping_intentionally_guarded",false);
      j.put("original_libc_third_data_ro_ptload_verified",roProved);
      j.put("original_libc_third_data_ro_wx_safe_verified",roProved);
      j.put("original_libc_fourth_mapping_intentionally_guarded",safeBoundary);''')
one(
'''        preadProved && fstatProved && mmapProved && rxProved &&
        safeBoundary && nextProved && finished && !bad.get();''',
'''        preadProved && fstatProved && mmapProved && rxProved && roProved &&
        safeBoundary && nextProved && finished && !bad.get();''')
one(
'''      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_LIBC_SOURCE_AUTHENTICATED_RX_PTLOAD_MAPPED_THIRD_MAPPING_SAFELY_GUARDED":
        (rxProved?"LIBC_RX_PTLOAD_PROVEN_THIRD_MAPPING_UNCONFIRMED":
         mmapProved?"LIBC_LARGE_RO_MMAP9_PROVEN_RX_PTLOAD_UNCONFIRMED":''',
'''      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_LIBC_THIRD_SOURCE_AUTHENTICATED_RO_PTLOAD_MAPPED_FOURTH_MAPPING_SAFELY_GUARDED":
        (roProved?"LIBC_THIRD_RO_PTLOAD_PROVEN_FOURTH_MAPPING_UNCONFIRMED":
         rxProved?"LIBC_RX_PTLOAD_PROVEN_THIRD_RO_UNCONFIRMED":
         mmapProved?"LIBC_LARGE_RO_MMAP9_PROVEN_RX_PTLOAD_UNCONFIRMED":''')
probe.write_text(s)

activity=root/"app/src/main/java/com/r4/carxpc/MainActivity.java"
s=activity.read_text()
for old,new in {
  "المرحلة R3-C7 — ربط مقطع libc التنفيذي RX دون W+X":
    "المرحلة R3-C8 — ربط مقطع بيانات libc الثالث RO",
  "R3-C7 | فحص PT_LOAD التنفيذي RX لملف libc":
    "R3-C8 | فحص PT_LOAD الثالث RO لملف libc",
  "نجح ربط مقطع libc التنفيذي RX بشروط W^X؛ لم تكتمل glibc":
    "نجح ربط مقطع libc الثالث للقراءة فقط؛ لم تكتمل glibc"
}.items():
    assert s.count(old)==1,("missing UI",old)
    s=s.replace(old,new)
activity.write_text(s)
print("CARX_R3C8_GNU_LIBC_THIRD_READONLY_PTLOAD_VERSION15_GATE_READY")
