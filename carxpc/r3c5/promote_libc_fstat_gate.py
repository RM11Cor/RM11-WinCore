#!/usr/bin/env python3
"""R3-C5: verify source-pinned GNU libc virtual fstat(5) writes Linux x86-64 stat144."""
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
gradle = root / "app/build.gradle"
s = gradle.read_text()
s, n = re.subn(r"\bversionCode\s+11\b", "versionCode 12", s)
assert n == 1, ("expected versionCode 11", n)
s, n = re.subn(r"\bversionName\s+'[^']+'", "versionName '0.12-r3c5-libc-fstat5'", s)
assert n == 1
gradle.write_text(s)

probe = root / "app/src/main/java/com/r4/carxpc/FexIntegrationProbe.java"
s = probe.read_text()
def one(old, new):
    global s
    n = s.count(old)
    assert n == 1, ("missing_or_duplicate", n, old)
    s = s.replace(old, new, 1)

one(
'      String nextSyscall="KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL";',
'''      String fstat5="KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_LIBC_FSTAT5_VIRTUAL_X86_64_STAT144_SOURCE_SIZE_2118168_OWNED_GUEST_STACK_PASS_NO_HOST_FSTAT";
      String nextSyscall="KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL";''')
one(
'      int f=log.indexOf(read832),h=log.indexOf(pread784),g=log.indexOf(nextSyscall);',
'      int f=log.indexOf(read832),h=log.indexOf(pread784),i=log.indexOf(fstat5),g=log.indexOf(nextSyscall);')
one(
'      boolean nextProved=g>h && preadProved && exit==117;',
'''      boolean fstatProved=i>h && preadProved;
      boolean nextProved=g>i && fstatProved && exit==117;''')
one(
'      j.put("original_next_guest_syscall_after_pread_verified",nextProved);',
'''      j.put("original_libc_fstat5_virtual_stat144_verified",fstatProved);
      j.put("original_next_guest_syscall_after_pread_verified",g>h && preadProved && exit==117);
      j.put("original_next_guest_syscall_after_fstat_verified",nextProved);''')
one(
'''      boolean gate=a>=0 && b>a && c>b && d>c && opened && readProved &&
        preadProved && nextProved && finished && !bad.get();''',
'''      boolean gate=a>=0 && b>a && c>b && d>c && opened && readProved &&
        preadProved && fstatProved && nextProved && finished && !bad.get();''')
one(
'''      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_LIBC_784_PREAD64_OFFSET_64_AND_NEXT_SYSCALL":
        (preadProved?"LIBC_PREAD64_PROVEN_NEXT_SYSCALL_UNCONFIRMED":
         readProved?"LIBC_READ_832_PROVEN_PREAD64_UNCONFIRMED":''',
'''      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_LIBC_VIRTUAL_FSTAT5_STAT144_AND_NEXT_SYSCALL":
        (fstatProved?"LIBC_FSTAT5_PROVEN_NEXT_SYSCALL_UNCONFIRMED":
         preadProved?"LIBC_PREAD64_PROVEN_FSTAT5_UNCONFIRMED":
         readProved?"LIBC_READ_832_PROVEN_PREAD64_UNCONFIRMED":''')
probe.write_text(s)

activity = root / "app/src/main/java/com/r4/carxpc/MainActivity.java"
s = activity.read_text()
changes = {
    "المرحلة R3-C4 — pread64 من libc الأصلية عبر FEX":
      "المرحلة R3-C5 — fstat لملف libc الأصلي عبر FEX",
    "R3-C4 | فحص pread64 لقراءة 784 بايت من libc":
      "R3-C5 | فحص fstat لحالة libc داخل ضيف x86-64",
    "نجحت قراءة 784 بايت إضافية من libc الأصلية بموضع 64؛ glibc لم تكتمل":
      "نجح fstat لملف libc الافتراضي وتعبئة stat144 بذاكرة الضيف؛ glibc لم تكتمل",
}
for old, new in changes.items():
    assert s.count(old) == 1, ("missing UI string", old)
    s = s.replace(old, new)
activity.write_text(s)
print("CARX_R3C5_VIRTUAL_FSTAT5_STAT144_DEVICE_PROBE_VERSION12_READY")
