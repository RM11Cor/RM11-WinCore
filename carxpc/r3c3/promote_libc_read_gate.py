#!/usr/bin/env python3
"""Promote R3-C3 guest libc read(0) 832 witness to independent device diagnostic."""
from pathlib import Path
import re,sys
root=Path(sys.argv[1])
gradle=root/'app/build.gradle'
s=gradle.read_text()
s,n=re.subn(r'\bversionCode\s+9\b','versionCode 10',s)
assert n==1,("version_code_9",n)
s,n=re.subn(r"\bversionName\s+'[^']+'","versionName '0.10-r3c3-libc-read-832'",s)
assert n==1
gradle.write_text(s)

probe=root/'app/src/main/java/com/r4/carxpc/FexIntegrationProbe.java'
s=probe.read_text()
find='''      String libc="KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_LIBC_STACK_OPENAT257_SHA_PINNED_SYNTHETIC_FD_PASS";
      int a=log.indexOf(brk),b=log.indexOf(access),c=log.indexOf(cache);
      int d=log.indexOf(patch),e=log.indexOf(libc);'''
replace='''      String libc="KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_LIBC_STACK_OPENAT257_SHA_PINNED_SYNTHETIC_FD_PASS";
      String read832="KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_LIBC_SYNTHETIC_FD_READ_832_SOURCE_ELF64_TO_OWNED_GUEST_STACK_PASS_NO_HOST_READ";
      String nextSyscall="KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL";
      int a=log.indexOf(brk),b=log.indexOf(access),c=log.indexOf(cache);
      int d=log.indexOf(patch),e=log.indexOf(libc);
      int f=log.indexOf(read832),g=log.indexOf(nextSyscall);'''
assert s.count(find)==1
s=s.replace(find,replace)
find='''      j.put("original_libc_virtual_open_observed",e>=0 && d>=0 && e>d);
      // A bounded test may intentionally return a nonzero exit code. In that
      // case retain all verified progress, but NEVER say the loader completed.
      boolean gate=a>=0 && b>a && c>b && d>=0 && e>d && !bad.get();
      j.put("bounded_genuine_loader_progress_observed",gate);
      j.put("success",gate); // Only the bounded R3-C progress gate, not glibc/PE.
      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_REACHED_SOURCE_PINNED_LIBC_VIRTUAL_OPEN":
        (d>=0?"PAST_UNALIGNED_JIT_SIGBUS_BUT_LIBC_OPEN_UNCONFIRMED":
         c>=0?"PAST_GUEST_BRK_ACCESS_CACHE_OPENAT":
         a>=0?"REAL_GUEST_BRK_OBSERVED":"BEFORE_REAL_GUEST_BRK_OR_NATIVE_INIT"));'''
replace='''      j.put("original_libc_virtual_open_observed",e>=0 && d>=0 && e>d);
      boolean opened=e>d && d>=0;
      boolean readProved=f>e && opened;
      boolean nextProved=g>f && readProved && exit==117;
      j.put("original_libc_guest_read_832_verified",readProved);
      j.put("original_next_guest_syscall_after_read_verified",nextProved);
      // The source uses an intentional exit 117 at the NEXT unsupported
      // syscall. The success here is only the bounded read/ELF header gate.
      // Never infer _dl_start completion, libc init, Wine or game launch.
      boolean gate=a>=0 && b>a && c>b && d>c && opened && readProved &&
        nextProved && finished && !bad.get();
      j.put("bounded_genuine_loader_progress_observed",gate);
      j.put("success",gate);
      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_SOURCE_PINNED_LIBC_832_READ_AND_NEXT_SYSCALL":
        (readProved?"LIBC_READ_PROVEN_NEXT_SYSCALL_UNCONFIRMED":
         opened?"LIBC_OPEN_PROVEN_READ_UNCONFIRMED":
         d>=0?"PAST_UNALIGNED_JIT_SIGBUS_BUT_LIBC_OPEN_UNCONFIRMED":
         c>=0?"PAST_GUEST_BRK_ACCESS_CACHE_OPENAT":
         a>=0?"REAL_GUEST_BRK_OBSERVED":"BEFORE_REAL_GUEST_BRK_OR_NATIVE_INIT"));'''
assert s.count(find)==1
s=s.replace(find,replace)
assert "original_libc_guest_read_832_verified" in s
probe.write_text(s)

activity=root/'app/src/main/java/com/r4/carxpc/MainActivity.java'
s=activity.read_text()
replacements={
"المرحلة R3-C — متابعة تشغيل GNU ld-linux الحقيقي باستخدام FEX المثبت":
"المرحلة R3-C3 — قراءة libc الأصلية من ذاكرة الضيف عبر FEX المثبت",
"R3-C | اختبار تقدّم ld-linux وفتح libc عبر FEX":
"R3-C3 | فحص قراءة 832 بايت من libc عبر FEX",
"وصل GNU ld-linux الأصلي إلى فتح libc في بيئة الضيف؛ ليس تشغيل glibc بالكامل":
"نجحت قراءة أول 832 بايت من libc الأصلية داخل ذاكرة الضيف؛ glibc لم تكتمل",
}
for old,new in replacements.items():
    assert s.count(old)==1,("missing_ui",old)
    s=s.replace(old,new)
activity.write_text(s)
print("CARX_R3C3_JAVA_GATED_READ_832_WITNESS_AND_VERSIONCODE_10_READY")
