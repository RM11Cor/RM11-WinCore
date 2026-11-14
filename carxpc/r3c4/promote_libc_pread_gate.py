#!/usr/bin/env python3
"""R3-C4: promote a proven original GNU libc pread64(100, guestRW, 784, 64)."""
from pathlib import Path
import re,sys
root=Path(sys.argv[1])
gradle=root/'app/build.gradle'
s=gradle.read_text()
s,n=re.subn(r'\bversionCode\s+10\b','versionCode 11',s)
assert n==1,("Expected R3C3 versionCode 10",n)
s,n=re.subn(r"\bversionName\s+'[^']+'","versionName '0.11-r3c4-libc-pread64'",s)
assert n==1
gradle.write_text(s)

probe=root/'app/src/main/java/com/r4/carxpc/FexIntegrationProbe.java'
s=probe.read_text()
def once(before,after):
    global s
    n=s.count(before)
    assert n==1,(n,before)
    s=s.replace(before,after,1)
once(
'      String nextSyscall="KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL";',
'''      String pread784="KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_LIBC_SYNTHETIC_FD_PREAD64_784_SOURCE_OFFSET_40_OWNED_GUEST_STACK_PASS_NO_HOST_PREAD";
      String nextSyscall="KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL";''')
once(
'      int f=log.indexOf(read832),g=log.indexOf(nextSyscall);',
'      int f=log.indexOf(read832),h=log.indexOf(pread784),g=log.indexOf(nextSyscall);')
once(
'      boolean nextProved=g>f && readProved && exit==117;',
'''      boolean preadProved=h>f && readProved;
      boolean nextProved=g>h && preadProved && exit==117;''')
once(
'      j.put("original_next_guest_syscall_after_read_verified",nextProved);',
'''      j.put("original_libc_pread64_784_offset_64_verified",preadProved);
      j.put("original_next_guest_syscall_after_read_verified",g>f && readProved && exit==117);
      j.put("original_next_guest_syscall_after_pread_verified",nextProved);''')
once(
'      boolean gate=a>=0 && b>a && c>b && d>c && opened && readProved &&\n        nextProved && finished && !bad.get();',
'''      boolean gate=a>=0 && b>a && c>b && d>c && opened && readProved &&
        preadProved && nextProved && finished && !bad.get();''')
once(
'      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_SOURCE_PINNED_LIBC_832_READ_AND_NEXT_SYSCALL":\n        (readProved?"LIBC_READ_PROVEN_NEXT_SYSCALL_UNCONFIRMED":',
'''      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_LIBC_784_PREAD64_OFFSET_64_AND_NEXT_SYSCALL":
        (preadProved?"LIBC_PREAD64_PROVEN_NEXT_SYSCALL_UNCONFIRMED":
         readProved?"LIBC_READ_832_PROVEN_PREAD64_UNCONFIRMED":''')
probe.write_text(s)

activity=root/'app/src/main/java/com/r4/carxpc/MainActivity.java'
s=activity.read_text()
for old,new in {
"المرحلة R3-C3 — قراءة libc الأصلية من ذاكرة الضيف عبر FEX المثبت":
"المرحلة R3-C4 — pread64 من libc الأصلية عبر FEX",
"R3-C3 | فحص قراءة 832 بايت من libc عبر FEX":
"R3-C4 | فحص pread64 لقراءة 784 بايت من libc",
"نجحت قراءة أول 832 بايت من libc الأصلية داخل ذاكرة الضيف؛ glibc لم تكتمل":
"نجحت قراءة 784 بايت إضافية من libc الأصلية بموضع 64؛ glibc لم تكتمل",
}.items():
    assert s.count(old)==1,("UI",old)
    s=s.replace(old,new)
activity.write_text(s)
print("CARX_R3C4_PREAD64_GUEST_784_OFFSET_64_GATED_REPORT_VERSION11_READY")
