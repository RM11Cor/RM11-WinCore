#!/usr/bin/env python3
"""R3-C11: prove post-BSS libc fd=100 close(3) from original GNU ld-linux.
Preserve complete prior bounded-stage evidence; do not claim full ldso/glibc.
"""
from pathlib import Path
import re,sys
root=Path(sys.argv[1])
p=root/"app/build.gradle"
s=p.read_text()
s,n=re.subn(r"\bversionCode\s+17\b","versionCode 18",s)
assert n==1,("expected R3C10 versionCode 17",n)
s,n=re.subn(r"\bversionName\s+'[^']+'","versionName '0.18-r3c11-libc-close3'",s)
assert n==1
p.write_text(s)
p=root/"app/src/main/java/com/r4/carxpc/FexIntegrationProbe.java"
s=p.read_text()
def once(before,after):
    global s
    n=s.count(before)
    assert n==1,("expected exactly one R3C10 gate",n,before)
    s=s.replace(before,after,1)
once(
'      String nextSyscall="KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL";',
'''      String close3="KERNIX_G0_REAL_ORIGINAL_GNU_LIBC_CLOSE3_AFTER_FIFTH_BSS_SYNTHETIC_FD100_ONLY_MAPPED_RO_RX_RW_PTLOADS_REMAIN_PASS";
      String nextSyscall="KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL";''')
once(
'      int f=log.indexOf(read832),h=log.indexOf(pread784),i=log.indexOf(fstat5),k=log.indexOf(firstMap),m=log.indexOf(rxTextMap),n=log.indexOf(thirdROMap),q=log.indexOf(fourthRWMap),z=log.indexOf(fifthBss),g=log.indexOf(nextSyscall);',
'      int f=log.indexOf(read832),h=log.indexOf(pread784),i=log.indexOf(fstat5),k=log.indexOf(firstMap),m=log.indexOf(rxTextMap),n=log.indexOf(thirdROMap),q=log.indexOf(fourthRWMap),z=log.indexOf(fifthBss),v=log.indexOf(close3),g=log.indexOf(nextSyscall);')
once(
'''      boolean bssProved=z>q && rwProved;
      boolean safeBoundary=g>z && bssProved && exit==117;''',
'''      boolean bssProved=z>q && rwProved;
      boolean closeProved=v>z && bssProved && log.indexOf("NO_HOST_CLOSE",v)>v;
      boolean safeBoundary=g>v && closeProved && exit==117;''')
once(
'      j.put("original_libc_next_unsupported_syscall_after_fifth_bss_observed",safeBoundary);',
'''      j.put("original_libc_close3_virtual_fd100_after_bss_verified",closeProved);
      j.put("original_libc_close3_no_host_close_and_maps_preserved_verified",closeProved);
      j.put("original_libc_next_unsupported_syscall_after_fifth_bss_observed",g>z && bssProved && exit==117);
      j.put("original_libc_next_unsupported_syscall_after_close3_observed",safeBoundary);''')
once(
'''        rwProved && bssProved && safeBoundary && nextProved &&
        finished && !bad.get();''',
'''        rwProved && bssProved && closeProved && safeBoundary && nextProved &&
        finished && !bad.get();''')
once(
'''      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_LIBC_FIFTH_ANONYMOUS_BSS_ZERO_MAPPED_NEXT_SYSCALL_STOP":
        (bssProved?"LIBC_FIFTH_ZERO_BSS_PROVEN_NEXT_SYSCALL_UNCONFIRMED":
         rwProved?"LIBC_FOURTH_RW_PTLOAD_PROVEN_FIFTH_BSS_UNCONFIRMED":''',
'''      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_LIBC_VIRTUAL_CLOSE3_AFTER_BSS_VERIFIED_NEXT_SYSCALL_STOP":
        (closeProved?"LIBC_VIRTUAL_CLOSE3_PROVEN_NEXT_SYSCALL_UNCONFIRMED":
         bssProved?"LIBC_FIFTH_ZERO_BSS_PROVEN_CLOSE3_UNCONFIRMED":
         rwProved?"LIBC_FOURTH_RW_PTLOAD_PROVEN_FIFTH_BSS_UNCONFIRMED":''')
p.write_text(s)

p=root/"app/src/main/java/com/r4/carxpc/MainActivity.java"
s=p.read_text()
for old,new in {
"المرحلة R3-C10 — تخصيص BSS الصفري لملف libc":"المرحلة R3-C11 — إغلاق libc الافتراضي بعد BSS",
"R3-C10 | فحص BSS الصفري وخرائط libc":"R3-C11 | فحص close(3) بعد BSS لملف libc",
"نجح تخصيص BSS الصفري لملف libc مع حماية W^X؛ glibc لم تكتمل":
"نجح إغلاق واصف libc الافتراضي مع بقاء الخرائط؛ glibc لم تكتمل"
}.items():
    assert s.count(old)==1,("expected R3C10 UI",old)
    s=s.replace(old,new,1)
p.write_text(s)
print("CARX_R3C11_GNU_LIBC_POST_BSS_CLOSE3_DEVICE_GATE_VERSION18_READY")
