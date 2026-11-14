#!/usr/bin/env python3
"""R3-C10: prove genuine libc anonymous BSS mmap(9), byte-zero and W^X
using the original KERNIX bounded FEX guest implementation.
Do not mark glibc initialized or Wine/CarX launched.
"""
from pathlib import Path
import re,sys
root=Path(sys.argv[1])
p=root/"app/build.gradle"
s=p.read_text()
s,n=re.subn(r"\bversionCode\s+16\b","versionCode 17",s)
assert n==1,("Expected R3C9 versionCode16",n)
s,n=re.subn(r"\bversionName\s+'[^']+'","versionName '0.17-r3c10-libc-zero-bss'",s)
assert n==1
p.write_text(s)
p=root/"app/src/main/java/com/r4/carxpc/FexIntegrationProbe.java"
s=p.read_text()
def one(before,after):
    global s
    n=s.count(before)
    assert n==1,("R3C9 gate unexpected",n,before)
    s=s.replace(before,after,1)
one(
'      String nextSyscall="KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL";',
'''      String fifthBss="KERNIX_G0_REAL_ORIGINAL_GNU_LIBC_FIFTH_ANONYMOUS_BSS_MMAP_ORIGINAL_RW_PTLOAD_SOURCE_MEM_END_0x211d90_ZERO_0xcd90_OWNED_NO_NATIVE_FIXED_NO_WX_PASS base=804205000";
      String nextSyscall="KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL";''')
one(
'      int f=log.indexOf(read832),h=log.indexOf(pread784),i=log.indexOf(fstat5),k=log.indexOf(firstMap),m=log.indexOf(rxTextMap),n=log.indexOf(thirdROMap),q=log.indexOf(fourthRWMap),g=log.indexOf(nextSyscall);',
'      int f=log.indexOf(read832),h=log.indexOf(pread784),i=log.indexOf(fstat5),k=log.indexOf(firstMap),m=log.indexOf(rxTextMap),n=log.indexOf(thirdROMap),q=log.indexOf(fourthRWMap),z=log.indexOf(fifthBss),g=log.indexOf(nextSyscall);')
one(
'''      boolean rwProved=q>n && roProved;
      boolean safeBoundary=g>q && rwProved && exit==117;''',
'''      boolean rwProved=q>n && roProved;
      boolean bssProved=z>q && rwProved;
      boolean safeBoundary=g>z && bssProved && exit==117;''')
one(
'''      j.put("original_libc_next_unsupported_syscall_after_fourth_rw_observed",safeBoundary);''',
'''      j.put("original_libc_fifth_anonymous_bss_zero_mmap_verified",bssProved);
      j.put("original_libc_fifth_bss_zero_sample_and_wx_safe_verified",bssProved);
      j.put("original_libc_next_unsupported_syscall_after_fourth_rw_observed",g>q && rwProved && exit==117);
      j.put("original_libc_next_unsupported_syscall_after_fifth_bss_observed",safeBoundary);''')
one(
'''        rwProved && safeBoundary && nextProved && finished && !bad.get();''',
'''        rwProved && bssProved && safeBoundary && nextProved &&
        finished && !bad.get();''')
one(
'''      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_LIBC_FOURTH_SOURCE_AUTHENTICATED_RW_PTLOAD_MAPPED_NEXT_SYSCALL_STOP":
        (rwProved?"LIBC_FOURTH_RW_PTLOAD_PROVEN_NEXT_SYSCALL_UNCONFIRMED":
         roProved?"LIBC_THIRD_RO_PTLOAD_PROVEN_FOURTH_RW_UNCONFIRMED":''',
'''      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_LIBC_FIFTH_ANONYMOUS_BSS_ZERO_MAPPED_NEXT_SYSCALL_STOP":
        (bssProved?"LIBC_FIFTH_ZERO_BSS_PROVEN_NEXT_SYSCALL_UNCONFIRMED":
         rwProved?"LIBC_FOURTH_RW_PTLOAD_PROVEN_FIFTH_BSS_UNCONFIRMED":
         roProved?"LIBC_THIRD_RO_PTLOAD_PROVEN_FOURTH_RW_UNCONFIRMED":''')
p.write_text(s)
p=root/"app/src/main/java/com/r4/carxpc/MainActivity.java"
s=p.read_text()
for old,new in {
"المرحلة R3-C9 — ربط مقطع بيانات libc الرابع RW":"المرحلة R3-C10 — تخصيص BSS الصفري لملف libc",
"R3-C9 | فحص PT_LOAD الرابع RW لملف libc":"R3-C10 | فحص BSS الصفري وخرائط libc",
"نجح ربط مقطع بيانات libc الرابع RW دون W+X؛ glibc لم تكتمل":
"نجح تخصيص BSS الصفري لملف libc مع حماية W^X؛ glibc لم تكتمل"
}.items():
    assert s.count(old)==1,("UI label",old)
    s=s.replace(old,new)
p.write_text(s)
print("CARX_R3C10_ORIGINAL_GNU_LIBC_ANONYMOUS_ZERO_BSS_DEVICE_GATE_VERSION17_READY")
