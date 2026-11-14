#!/usr/bin/env python3
"""R3-C12: preserve R3-C11 and require an authentic post-libc-close 8KiB
anonymous RW mmap from original unpatched GNU ld-linux in FEX.
This is a bounded Android hardware device diagnostic, NOT glibc boot.
"""
from pathlib import Path
import re, sys
root=Path(sys.argv[1])
p=root/"app/build.gradle"
s=p.read_text()
s,n=re.subn(r"\bversionCode\s+18\b","versionCode 19",s)
assert n==1,("expected versionCode 18",n)
s,n=re.subn(r"\bversionName\s+'[^']+'","versionName '0.19-r3c12-anon8k'",s)
assert n==1
p.write_text(s)

p=root/"app/src/main/java/com/r4/carxpc/FexIntegrationProbe.java"
s=p.read_text()
def once(before,after):
    global s
    n=s.count(before)
    assert n==1,("expected unique R3C11 gate",n,before)
    s=s.replace(before,after,1)

once(
'      String nextSyscall="KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL";',
'''      String anon8k="KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_POST_LIBC_CLOSE_ANONYMOUS_RW_8K_OWNED_ZERO_SOURCE_VM_PASS";
      String nextSyscall="KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL";''')
once(
'      int f=log.indexOf(read832),h=log.indexOf(pread784),i=log.indexOf(fstat5),k=log.indexOf(firstMap),m=log.indexOf(rxTextMap),n=log.indexOf(thirdROMap),q=log.indexOf(fourthRWMap),z=log.indexOf(fifthBss),v=log.indexOf(close3),g=log.indexOf(nextSyscall);',
'      int f=log.indexOf(read832),h=log.indexOf(pread784),i=log.indexOf(fstat5),k=log.indexOf(firstMap),m=log.indexOf(rxTextMap),n=log.indexOf(thirdROMap),q=log.indexOf(fourthRWMap),z=log.indexOf(fifthBss),v=log.indexOf(close3),u=log.indexOf(anon8k),g=log.indexOf(nextSyscall);')
once(
'''      boolean closeProved=v>z && bssProved && log.indexOf("NO_HOST_CLOSE",v)>v;
      boolean safeBoundary=g>v && closeProved && exit==117;''',
'''      boolean closeProved=v>z && bssProved && log.indexOf("NO_HOST_CLOSE",v)>v;
      boolean anon8kProved=u>v && closeProved && log.indexOf("NO_HOST_GUEST_FD_NO_WX",u)>u;
      boolean safeBoundary=g>u && anon8kProved && exit==117;''')
once(
'      j.put("original_libc_close3_no_host_close_and_maps_preserved_verified",closeProved);',
'''      j.put("original_libc_close3_no_host_close_and_maps_preserved_verified",closeProved);
      j.put("original_ldso_post_libc_close_anon8k_guest_rw_zero_owned_verified",anon8kProved);
      j.put("original_ldso_post_libc_close_anon8k_next_unsupported_syscall_observed",safeBoundary);''')
once(
'''        rwProved && bssProved && closeProved && safeBoundary && nextProved &&
        finished && !bad.get();''',
'''        rwProved && bssProved && closeProved && anon8kProved && safeBoundary && nextProved &&
        finished && !bad.get();''')
once(
'''      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_LIBC_VIRTUAL_CLOSE3_AFTER_BSS_VERIFIED_NEXT_SYSCALL_STOP":
        (closeProved?"LIBC_VIRTUAL_CLOSE3_PROVEN_NEXT_SYSCALL_UNCONFIRMED":
         bssProved?"LIBC_FIFTH_ZERO_BSS_PROVEN_CLOSE3_UNCONFIRMED":''',
'''      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_POST_LIBC_CLOSE_ANON8K_RW_ZERO_VERIFIED_NEXT_SYSCALL_STOP":
        (anon8kProved?"ORIGINAL_GNU_LDSO_POST_CLOSE_ANON8K_PROVEN_NEXT_SYSCALL_UNCONFIRMED":
         closeProved?"LIBC_VIRTUAL_CLOSE3_PROVEN_ANON8K_UNCONFIRMED":
         bssProved?"LIBC_FIFTH_ZERO_BSS_PROVEN_CLOSE3_UNCONFIRMED":''')
p.write_text(s)

p=root/"app/src/main/java/com/r4/carxpc/MainActivity.java"
s=p.read_text()
for old,new in {
"المرحلة R3-C11 — إغلاق libc الافتراضي بعد BSS":"المرحلة R3-C12 — تخصيص GNU ld.so لذاكرة 8KB",
"R3-C11 | فحص close(3) بعد BSS لملف libc":"R3-C12 | فحص mmap مجهول 8KB بعد close",
"نجح إغلاق واصف libc الافتراضي مع بقاء الخرائط؛ glibc لم تكتمل":
"نجح تخصيص GNU ld.so لذاكرة RW صفرية 8KB بعد close؛ glibc لم تكتمل"
}.items():
    assert s.count(old)==1,("expected unique R3C11 UI text",old)
    s=s.replace(old,new,1)
p.write_text(s)
print("CARX_R3C12_LDSO_POST_CLOSE_ANON8K_DEVICE_GATE_VERSION19_READY")
