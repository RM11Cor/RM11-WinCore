#!/usr/bin/env python3
"""R3-C6: prove source-pinned libc large private RO guest mmap, with safe next-map stop.

This deliberately tests ONLY the initial libc image map; the original KERNIX
source stops BEFORE the second MAP_FIXED transition (exit 142). A bounded PASS
must NOT imply executable PT_LOAD mapping or GNU loader/glibc completion.
"""
from pathlib import Path
import re,sys

root=Path(sys.argv[1])
p=root/"app/build.gradle"
s=p.read_text()
s,n=re.subn(r"\bversionCode\s+12\b","versionCode 13",s)
assert n==1,("Expected R3C5 versionCode12",n)
s,n=re.subn(r"\bversionName\s+'[^']+'","versionName '0.13-r3c6-libc-ro-mmap9'",s)
assert n==1
p.write_text(s)

p=root/"app/src/main/java/com/r4/carxpc/FexIntegrationProbe.java"
s=p.read_text()
def one(a,b):
    global s
    count=s.count(a)
    assert count==1,("expected one occurrence",count,a)
    s=s.replace(a,b,1)

one(
'      String nextSyscall="KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL";',
'''      String firstMap="KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_LIBC_MMAP9_LARGE_PRIVATE_RO_SOURCE_2118168_REQUEST_0x211d90_FD100_OFFSET0_WX_SAFE_EOF_GUARD_PASS";
      String nextMapGuard="KERNIX_G0_ORIGINAL_LDSO_LIBC_LARGE_RO_MMAP_PRECONDITION_REJECT after_first=1";
      String nextSyscall="KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL";''')
one(
'      int f=log.indexOf(read832),h=log.indexOf(pread784),i=log.indexOf(fstat5),g=log.indexOf(nextSyscall);',
'      int f=log.indexOf(read832),h=log.indexOf(pread784),i=log.indexOf(fstat5),k=log.indexOf(firstMap),l=log.indexOf(nextMapGuard),g=log.indexOf(nextSyscall);')
one(
'      boolean nextProved=g>i && fstatProved && exit==117;',
'''      boolean mmapProved=k>i && fstatProved;
      boolean safeBoundary=l>k && mmapProved && exit==142;
      boolean nextProved=safeBoundary;''')
one(
'      j.put("original_next_guest_syscall_after_fstat_verified",nextProved);',
'''      j.put("original_libc_mmap9_large_private_ro_verified",mmapProved);
      j.put("original_libc_mmap9_source_eof_and_wx_guard_verified",mmapProved);
      j.put("original_libc_next_mapping_intentionally_guarded",safeBoundary);
      j.put("original_next_guest_syscall_after_fstat_verified",mmapProved);''')
one(
'''      boolean gate=a>=0 && b>a && c>b && d>c && opened && readProved &&
        preadProved && fstatProved && nextProved && finished && !bad.get();''',
'''      boolean gate=a>=0 && b>a && c>b && d>c && opened && readProved &&
        preadProved && fstatProved && mmapProved && safeBoundary &&
        nextProved && finished && !bad.get();''')
one(
'''      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_LIBC_VIRTUAL_FSTAT5_STAT144_AND_NEXT_SYSCALL":
        (fstatProved?"LIBC_FSTAT5_PROVEN_NEXT_SYSCALL_UNCONFIRMED":
         preadProved?"LIBC_PREAD64_PROVEN_FSTAT5_UNCONFIRMED":''',
'''      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_LIBC_LARGE_RO_MMAP9_VERIFIED_NEXT_MAPPING_SAFELY_GUARDED":
        (mmapProved?"LIBC_LARGE_RO_MMAP9_PROVEN_NEXT_MAPPING_UNCONFIRMED":
         fstatProved?"LIBC_FSTAT5_PROVEN_MMAP9_UNCONFIRMED":
         preadProved?"LIBC_PREAD64_PROVEN_FSTAT5_UNCONFIRMED":''')
# Leave genuine nextSyscall variable available but don't require it: KERNIX bounded
# first-mmap probe rejects the next mapping with exit(142) BEFORE generic exit(117).
assert "g=log.indexOf(nextSyscall)" in s
p.write_text(s)

p=root/"app/src/main/java/com/r4/carxpc/MainActivity.java"
s=p.read_text()
for old,new in {
"المرحلة R3-C5 — fstat لملف libc الأصلي عبر FEX":
"المرحلة R3-C6 — mmap للقراءة فقط من libc الأصلية",
"R3-C5 | فحص fstat لحالة libc داخل ضيف x86-64":
"R3-C6 | فحص mmap الآمن لملف libc",
"نجح fstat لملف libc الافتراضي وتعبئة stat144 بذاكرة الضيف؛ glibc لم تكتمل":
"نجح ربط libc للقراءة فقط مع حماية نهاية الملف؛ لم تكتمل glibc",
}.items():
    assert s.count(old)==1,("missing_ui_text",old)
    s=s.replace(old,new)
p.write_text(s)
print("CARX_R3C6_LIBC_FIRST_MMAP9_WX_EOF_GUARD_PROOF_VERSION13_READY")
