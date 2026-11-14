#!/usr/bin/env python3
"""R3-C7: attest first RO libc map, second *source-authenticated* RX text PT_LOAD map,
and deliberate stop before the third map, with no guest W+X or host MAP_FIXED.
"""
from pathlib import Path
import re,sys

root=Path(sys.argv[1])
p=root/"app/build.gradle"
s=p.read_text()
s,n=re.subn(r"\bversionCode\s+13\b","versionCode 14",s)
assert n==1,("R3C6 versionCode 13 expected",n)
s,n=re.subn(r"\bversionName\s+'[^']+'","versionName '0.14-r3c7-libc-rx-ptload'",s)
assert n==1
p.write_text(s)

p=root/"app/src/main/java/com/r4/carxpc/FexIntegrationProbe.java"
s=p.read_text()
def one(a,b):
    global s
    count=s.count(a)
    assert count==1,("expected exactly one occurrence",count,a)
    s=s.replace(a,b,1)

one(
'      String nextMapGuard="KERNIX_G0_ORIGINAL_LDSO_LIBC_LARGE_RO_MMAP_PRECONDITION_REJECT after_first=1";',
'''      String rxTextMap="KERNIX_G0_REAL_ORIGINAL_GNU_LIBC_SECOND_FIXED_TEXT_MMAP_PTLOAD_VERIFIED_RX_NO_NATIVE_FIXED_NO_WX_PASS";
      String nextMapGuard="KERNIX_G0_ORIGINAL_LDSO_LIBC_LARGE_RO_MMAP_PRECONDITION_REJECT after_first=2";''')
one(
'      int f=log.indexOf(read832),h=log.indexOf(pread784),i=log.indexOf(fstat5),k=log.indexOf(firstMap),l=log.indexOf(nextMapGuard),g=log.indexOf(nextSyscall);',
'      int f=log.indexOf(read832),h=log.indexOf(pread784),i=log.indexOf(fstat5),k=log.indexOf(firstMap),m=log.indexOf(rxTextMap),l=log.indexOf(nextMapGuard),g=log.indexOf(nextSyscall);')
one(
'''      boolean mmapProved=k>i && fstatProved;
      boolean safeBoundary=l>k && mmapProved && exit==142;
      boolean nextProved=safeBoundary;''',
'''      boolean mmapProved=k>i && fstatProved;
      boolean rxProved=m>k && mmapProved;
      boolean safeBoundary=l>m && rxProved && exit==142;
      boolean nextProved=safeBoundary;''')
one(
'''      j.put("original_libc_next_mapping_intentionally_guarded",safeBoundary);''',
'''      j.put("original_libc_second_text_rx_ptload_verified",rxProved);
      j.put("original_libc_second_text_rx_wx_safe_verified",rxProved);
      j.put("original_libc_third_mapping_intentionally_guarded",safeBoundary);
      j.put("original_libc_next_mapping_intentionally_guarded",safeBoundary);''')
one(
'''        preadProved && fstatProved && mmapProved && safeBoundary &&
        nextProved && finished && !bad.get();''',
'''        preadProved && fstatProved && mmapProved && rxProved &&
        safeBoundary && nextProved && finished && !bad.get();''')
one(
'''      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_LIBC_LARGE_RO_MMAP9_VERIFIED_NEXT_MAPPING_SAFELY_GUARDED":
        (mmapProved?"LIBC_LARGE_RO_MMAP9_PROVEN_NEXT_MAPPING_UNCONFIRMED":
         fstatProved?"LIBC_FSTAT5_PROVEN_MMAP9_UNCONFIRMED":''',
'''      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_LIBC_SOURCE_AUTHENTICATED_RX_PTLOAD_MAPPED_THIRD_MAPPING_SAFELY_GUARDED":
        (rxProved?"LIBC_RX_PTLOAD_PROVEN_THIRD_MAPPING_UNCONFIRMED":
         mmapProved?"LIBC_LARGE_RO_MMAP9_PROVEN_RX_PTLOAD_UNCONFIRMED":
         fstatProved?"LIBC_FSTAT5_PROVEN_MMAP9_UNCONFIRMED":''')
p.write_text(s)

p=root/"app/src/main/java/com/r4/carxpc/MainActivity.java"
s=p.read_text()
for old,new in {
  "المرحلة R3-C6 — mmap للقراءة فقط من libc الأصلية":
    "المرحلة R3-C7 — ربط مقطع libc التنفيذي RX دون W+X",
  "R3-C6 | فحص mmap الآمن لملف libc":
    "R3-C7 | فحص PT_LOAD التنفيذي RX لملف libc",
  "نجح ربط libc للقراءة فقط مع حماية نهاية الملف؛ لم تكتمل glibc":
    "نجح ربط مقطع libc التنفيذي RX بشروط W^X؛ لم تكتمل glibc"
}.items():
    assert s.count(old)==1,("missing UI text",old)
    s=s.replace(old,new)
p.write_text(s)
print("CARX_R3C7_ORIGINAL_GNU_LIBC_EXECUTABLE_RX_PTLOAD_PROOF_VERSION14_READY")
