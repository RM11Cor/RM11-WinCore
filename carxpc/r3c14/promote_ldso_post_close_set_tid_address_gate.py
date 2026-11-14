#!/usr/bin/env python3
"""R3-C14: validate bounded genuine GNU ld-linux x86 set_tid_address(218)
on the new 8KiB guest TLS after arch_prctl(158, ARCH_SET_FS).
Preserve prior original source-authenticated guest ELF maps, FS, fd and
TID slot; no Android kernel set_tid_address or host TLS side effects.
This proves only the guarded next step of a guest dynamic loader.
"""
from pathlib import Path
import re,sys
root=Path(sys.argv[1])

p=root/"app/build.gradle"
s=p.read_text()
s,n=re.subn(r"\bversionCode\s+20\b","versionCode 21",s)
assert n==1,("expected R3C13 versionCode 20",n)
s,n=re.subn(r"\bversionName\s+'[^']+'","versionName '0.21-r3c14-guest-set-tid'",s)
assert n==1
p.write_text(s)

p=root/"app/src/main/java/com/r4/carxpc/FexIntegrationProbe.java"
s=p.read_text()
def once(a,b):
    global s
    n=s.count(a)
    assert n==1,("R3C13 gate mismatch",n,a)
    s=s.replace(a,b,1)
once(
'      String nextSyscall="KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL";',
'''      String setTid="KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_SET_TID_ADDRESS218_AFTER_ARCH_SET_FS_CLEAR_CHILD_TID_POINTER_IN_OWNED_GUEST_8K_TLS_NO_HOST_TID_SYSCALL_PASS";
      String nextSyscall="KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL";''')
once(
'      int f=log.indexOf(read832),h=log.indexOf(pread784),i=log.indexOf(fstat5),k=log.indexOf(firstMap),m=log.indexOf(rxTextMap),n=log.indexOf(thirdROMap),q=log.indexOf(fourthRWMap),z=log.indexOf(fifthBss),v=log.indexOf(close3),u=log.indexOf(anon8k),t=log.indexOf(setFs),g=log.indexOf(nextSyscall);',
'      int f=log.indexOf(read832),h=log.indexOf(pread784),i=log.indexOf(fstat5),k=log.indexOf(firstMap),m=log.indexOf(rxTextMap),n=log.indexOf(thirdROMap),q=log.indexOf(fourthRWMap),z=log.indexOf(fifthBss),v=log.indexOf(close3),u=log.indexOf(anon8k),t=log.indexOf(setFs),w=log.indexOf(setTid),g=log.indexOf(nextSyscall);')
once(
'''      boolean setFsProved=t>u && anon8kProved && log.indexOf("NO_HOST_TLS",t)>t;
      boolean safeBoundary=g>t && setFsProved && exit==117;''',
'''      boolean setFsProved=t>u && anon8kProved && log.indexOf("NO_HOST_TLS",t)>t;
      boolean setTidProved=w>t && setFsProved && log.indexOf("tid=1",w)>w;
      boolean safeBoundary=g>w && setTidProved && exit==117;''')
once(
'      j.put("original_ldso_post_libc_close_arch_set_fs_guest_tls_verified",setFsProved);',
'''      j.put("original_ldso_post_libc_close_arch_set_fs_guest_tls_verified",setFsProved);
      j.put("original_ldso_post_libc_close_set_tid_address_guest_clear_child_tid_verified",setTidProved);
      j.put("original_ldso_post_libc_close_set_tid_address_next_unsupported_syscall_observed",safeBoundary);''')
once(
'''        rwProved && bssProved && closeProved && anon8kProved && setFsProved && safeBoundary && nextProved &&
        finished && !bad.get();''',
'''        rwProved && bssProved && closeProved && anon8kProved && setFsProved && setTidProved && safeBoundary && nextProved &&
        finished && !bad.get();''')
once(
'''      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_POST_CLOSE_ARCH_SET_FS_GUEST_TLS_VERIFIED_NEXT_SYSCALL_STOP":
        (setFsProved?"ORIGINAL_GNU_LDSO_POST_CLOSE_ARCH_SET_FS_PROVEN_NEXT_SYSCALL_UNCONFIRMED":
         anon8kProved?"ORIGINAL_GNU_LDSO_POST_CLOSE_ANON8K_PROVEN_ARCH_SET_FS_UNCONFIRMED":''',
'''      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_POST_CLOSE_SET_TID_ADDRESS_GUEST_TLS_VERIFIED_NEXT_SYSCALL_STOP":
        (setTidProved?"ORIGINAL_GNU_LDSO_POST_CLOSE_SET_TID_ADDRESS_PROVEN_NEXT_SYSCALL_UNCONFIRMED":
         setFsProved?"ORIGINAL_GNU_LDSO_POST_CLOSE_ARCH_SET_FS_PROVEN_SET_TID_ADDRESS_UNCONFIRMED":
         anon8kProved?"ORIGINAL_GNU_LDSO_POST_CLOSE_ANON8K_PROVEN_ARCH_SET_FS_UNCONFIRMED":''')
p.write_text(s)

p=root/"app/src/main/java/com/r4/carxpc/MainActivity.java"
s=p.read_text()
for old,new in {
"المرحلة R3-C13 — FS/TLS للضيف بعد تخصيص 8KB":
"المرحلة R3-C14 — تسجيل clear_child_tid داخل TLS للضيف",
"R3-C13 | فحص ARCH_SET_FS الأصلي للضيف":
"R3-C14 | فحص set_tid_address(218) للضيف",
"نجح تحويل FS إلى TLS الخاص بالضيف فقط؛ glibc لم تكتمل":
"نجح تسجيل TID داخل TLS الخاص بالضيف دون نواة أندرويد؛ glibc لم تكتمل"
}.items():
    assert s.count(old)==1,("R3C13 UI mismatch",old)
    s=s.replace(old,new,1)
p.write_text(s)
print("CARX_R3C14_GUEST_SET_TID_ADDRESS_DEVICE_GATE_VERSION21_READY")
