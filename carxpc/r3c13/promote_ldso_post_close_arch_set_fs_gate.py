#!/usr/bin/env python3
"""R3-C13: prove original GNU ld-linux arch_prctl(158) ARCH_SET_FS(0x1002)
rebases only the FEX x86 guest FS base to the authenticated source-owned
anonymous 8KiB region after libc fd100 close; Android host TLS untouched.
This is a bounded device gate, not proof of full glibc.
"""
from pathlib import Path
import re,sys
root=Path(sys.argv[1])

p=root/"app/build.gradle"
s=p.read_text()
s,n=re.subn(r"\bversionCode\s+19\b","versionCode 20",s)
assert n==1,("expected R3C12 versionCode 19",n)
s,n=re.subn(r"\bversionName\s+'[^']+'","versionName '0.20-r3c13-guest-set-fs'",s)
assert n==1
p.write_text(s)

p=root/"app/src/main/java/com/r4/carxpc/FexIntegrationProbe.java"
s=p.read_text()
def once(a,b):
    global s
    n=s.count(a)
    assert n==1,("R3C12 unique gate mismatch",n,a)
    s=s.replace(a,b,1)
once(
'      String nextSyscall="KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL";',
'''      String setFs="KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_POST_CLOSE_ARCH_PRCTL158_ARCH_SET_FS1002_OWNED_8K_TCB_PLUS_0x10c0_FEX_FS_CACHED_GUEST_ONLY_PASS";
      String nextSyscall="KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL";''')
once(
'      int f=log.indexOf(read832),h=log.indexOf(pread784),i=log.indexOf(fstat5),k=log.indexOf(firstMap),m=log.indexOf(rxTextMap),n=log.indexOf(thirdROMap),q=log.indexOf(fourthRWMap),z=log.indexOf(fifthBss),v=log.indexOf(close3),u=log.indexOf(anon8k),g=log.indexOf(nextSyscall);',
'      int f=log.indexOf(read832),h=log.indexOf(pread784),i=log.indexOf(fstat5),k=log.indexOf(firstMap),m=log.indexOf(rxTextMap),n=log.indexOf(thirdROMap),q=log.indexOf(fourthRWMap),z=log.indexOf(fifthBss),v=log.indexOf(close3),u=log.indexOf(anon8k),t=log.indexOf(setFs),g=log.indexOf(nextSyscall);')
once(
'''      boolean anon8kProved=u>v && closeProved && log.indexOf("NO_HOST_GUEST_FD_NO_WX",u)>u;
      boolean safeBoundary=g>u && anon8kProved && exit==117;''',
'''      boolean anon8kProved=u>v && closeProved && log.indexOf("NO_HOST_GUEST_FD_NO_WX",u)>u;
      boolean setFsProved=t>u && anon8kProved && log.indexOf("NO_HOST_TLS",t)>t;
      boolean safeBoundary=g>t && setFsProved && exit==117;''')
once(
'      j.put("original_ldso_post_libc_close_anon8k_guest_rw_zero_owned_verified",anon8kProved);',
'''      j.put("original_ldso_post_libc_close_anon8k_guest_rw_zero_owned_verified",anon8kProved);
      j.put("original_ldso_post_libc_close_arch_set_fs_guest_tls_verified",setFsProved);
      j.put("original_ldso_post_libc_close_arch_set_fs_next_unsupported_syscall_observed",safeBoundary);''')
once(
'''        rwProved && bssProved && closeProved && anon8kProved && safeBoundary && nextProved &&
        finished && !bad.get();''',
'''        rwProved && bssProved && closeProved && anon8kProved && setFsProved && safeBoundary && nextProved &&
        finished && !bad.get();''')
once(
'''      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_POST_LIBC_CLOSE_ANON8K_RW_ZERO_VERIFIED_NEXT_SYSCALL_STOP":
        (anon8kProved?"ORIGINAL_GNU_LDSO_POST_CLOSE_ANON8K_PROVEN_NEXT_SYSCALL_UNCONFIRMED":
         closeProved?"LIBC_VIRTUAL_CLOSE3_PROVEN_ANON8K_UNCONFIRMED":''',
'''      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_POST_CLOSE_ARCH_SET_FS_GUEST_TLS_VERIFIED_NEXT_SYSCALL_STOP":
        (setFsProved?"ORIGINAL_GNU_LDSO_POST_CLOSE_ARCH_SET_FS_PROVEN_NEXT_SYSCALL_UNCONFIRMED":
         anon8kProved?"ORIGINAL_GNU_LDSO_POST_CLOSE_ANON8K_PROVEN_ARCH_SET_FS_UNCONFIRMED":
         closeProved?"LIBC_VIRTUAL_CLOSE3_PROVEN_ANON8K_UNCONFIRMED":''')
p.write_text(s)

p=root/"app/src/main/java/com/r4/carxpc/MainActivity.java"
s=p.read_text()
for old,new in {
"المرحلة R3-C12 — تخصيص GNU ld.so لذاكرة 8KB":
"المرحلة R3-C13 — FS/TLS للضيف بعد تخصيص 8KB",
"R3-C12 | فحص mmap مجهول 8KB بعد close":
"R3-C13 | فحص ARCH_SET_FS الأصلي للضيف",
"نجح تخصيص GNU ld.so لذاكرة RW صفرية 8KB بعد close؛ glibc لم تكتمل":
"نجح تحويل FS إلى TLS الخاص بالضيف فقط؛ glibc لم تكتمل"
}.items():
    assert s.count(old)==1,("R3C12 UI text mismatch",old)
    s=s.replace(old,new,1)
p.write_text(s)
print("CARX_R3C13_ARCH_SET_FS_GUEST_TLS_DEVICE_GATE_VERSION20_READY")
