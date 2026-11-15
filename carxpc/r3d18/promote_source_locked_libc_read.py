#!/usr/bin/env python3
"""R3D18: continue authentic GNU ld.so x86-64 read(0) after real libc FD100.

Only own 64KiB guest stack may be written. Source-witnessed guest read(fd100,
832 bytes) uses pread at a private virtual guest file offset, copies exact
bytes to mapped x86 guest stack, then returns actual byte count to FEX and
continues with the same 32-call fail-closed batch. No generic x86 syscalls.
"""
from pathlib import Path
import re,sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_source_locked_libc_read.py /tmp/carxpc")
app=Path(sys.argv[1])
java=app/"app/src/main/java/com/r4/carxpc"
native=app/"app/src/main/cpp/carx_r3d4_first_syscall.cpp"
activity=java/"R3D4ProbeActivity.java"
main=java/"MainActivity.java"
gradle=app/"app/build.gradle"
store=java/"R3D8JsonReportStore.java"
assert all(x.is_file() for x in (native,activity,main,gradle,store))
def one(s,a,b):
    n=s.count(a)
    assert n==1,("R3D18_PINNED_SOURCE_ANCHOR_CHANGED",a[:110],n)
    return s.replace(a,b,1)
def reone(s,pat,new):
    s,n=re.subn(pat,new,s,count=1)
    assert n==1,("R3D18_REGEX_SOURCE_CHANGED",pat,n)
    return s

s=gradle.read_text()
s=reone(s,r"\bversionCode\s+45\b","versionCode 46")
s=reone(s,r"versionName\s+'[^']+'",
        "versionName '0.46-r3d18-real-libc-source-locked-read832'")
gradle.write_text(s)
s=main.read_text()
s=one(s,"10 | R3D17 — ربط libc الحقيقي وفحص الاستدعاء التالي",
      "10 | R3D18 — قراءة libc الحقيقية ومعالجة دفعة Wine")
main.write_text(s)
s=store.read_text()
s=one(s,'"CarX_PC_R3D17_LibcFD_Batch_Diagnostics_"',
      '"CarX_PC_R3D18_LibcRead_Batch_Diagnostics_"')
store.write_text(s)

s=native.read_text()
s=one(s,
'''#include "carxpc/r3d17/native/verified_libc_fd.hpp"''',
'''#include "carxpc/r3d17/native/verified_libc_fd.hpp"
#include "carxpc/r3d18/native/bounded_libc_guest_read.hpp"''')
s=one(s,'''  int LibcHostFD{-1};''',
'''  int LibcHostFD{-1};
  uint64_t LibcReadCursor{0};''')
s=one(s,
'''      std::snprintf(msg,sizeof(msg),"E_BATCH_UNSUPPORTED_NR_%llu",''',
'''      // Source-verified fifth original x86 GNU ld.so syscall: read(0).
      // Guest FD100 maps to the already preopened app-owned GNU libc file.
      // The guest destination must lie entirely within our mapped 64KiB
      // Linux ABI stack. A host FD is never leaked into guest RAX.
      if(Mode==4 && number==0 && Seen>=4 &&
         arg0==uint64_t(carx_r3d17::kGuestLibcFd)) {
        if(Seen==4 && arg2!=832) {
          carx_r3d6::note("E_R3D18_FIRST_LIBC_READ_SIZE_NOT_832");
          ::_exit(121);
        }
        const auto result=carx_r3d18::read_libc_to_owned_guest_stack(
            LibcHostFD,arg0,arg1,arg2,LibcReadCursor);
        if(!result.ok) {
          carx_r3d6::note("E_R3D18_READ_FD_OR_GUEST_STACK_UNSAFE");
          ::_exit(120);
        }
        if(Seen==4 && result.n!=832) {
          carx_r3d6::note("E_R3D18_FIRST_READ_SHORT_OR_EMPTY");
          ::_exit(122);
        }
        std::snprintf(msg,sizeof(msg),"N25_R3D18_LIBC_READ_BYTES_%zd",
                      result.n);
        carx_r3d6::note(msg);
        carx_r3d6::note("N25_R3D18_STACK_WRITE_BOUNDED_VERIFIED");
        state.gregs[FEXCore::X86State::REG_RAX]=
            static_cast<uint64_t>(result.n);
        state.rip=newRIP;
        ++Seen;
        carx_r3d6::note("N22_BATCH_RETURN_READ_LIBC_FD100");
        return;
      }
      std::snprintf(msg,sizeof(msg),"E_BATCH_UNSUPPORTED_NR_%llu",''')
assert 'context->ExecuteThread(thread)' in s
assert 'N22_BATCH_RETURN_OPENAT_LIBC_FD100' in s
assert 'N22_BATCH_RETURN_READ_LIBC_FD100' in s
native.write_text(s)

s=activity.read_text()
s=one(s,
'''runCacheless.setText("تشغيل 07H — R3D17 libc حقيقي + Batch");''',
'''runCacheless.setText("تشغيل 07H — R3D18 قراءة libc + Batch");''')
s=one(s,'"r4.carx.r3d17.real-libc-fd-source-locked-batch.v1"',
      '"r4.carx.r3d18.real-libc-read832-batch.v1"')
s=one(s,'"07H_REAL_ROOTFS_LIBC_READONLY_FD_GUEST_BRIDGE"',
      '"07H_ROOTFS_LIBC_PREOPEN_PLUS_REAL_READ_GUEST_STACK"')
s=one(s,'"07H_R3D17_LIBC_READONLY_FD_BATCH_32"',
      '"07H_R3D18_REAL_LIBC_READ832_BATCH_32"')
s=one(s,
'''        final boolean bridgedLibc=phases.toString().contains(''',
'''        final boolean readLibcVerified=phases.toString().contains(
            "N22_BATCH_RETURN_READ_LIBC_FD100") &&
            phases.toString().contains(
            "N25_R3D18_STACK_WRITE_BOUNDED_VERIFIED") &&
            phases.toString().contains("N25_R3D18_LIBC_READ_BYTES_832");
        report.put("batch_libc_read832_guest_stack_verified",readLibcVerified);
        if(readLibcVerified){
            if(count<5 || events.optJSONObject(4)==null ||
               events.optJSONObject(4).optLong("guest_syscall_number")!=0){
                return "BATCH_REJECTED_READ832_WITHOUT_SOURCE_LOCKED_SYSCALL";
            }
            report.put("batch_libc_read_requested_bytes",832);
            report.put("batch_libc_read_returned_bytes",832);
            report.put("batch_libc_guest_stack_copy_proven_in_child",true);
            report.put("batch_libc_read_scope",
                "HOST_PREAD_VERIFIED_ROOTFS_LIBC_INTO_OWNED_GUEST_STACK_ONLY");
        }
        final boolean bridgedLibc=phases.toString().contains(''')
s=one(s,
'''            report.put("batch_libc_read_fstat_mmap_implemented",false);''',
'''            report.put("batch_libc_read_implemented",readLibcVerified);
            report.put("batch_libc_fstat_mmap_implemented",false);''')
s=one(s,
'''R3D17 original source-witnessed fourth GNU ld.so openat can receive only guest FD100 mapped to Java preopened read-only original guest libc ELF64 x86_64; next unknown syscall stops. Previous brk/access/cache responses remain diagnostic shims. No full Linux VFS, libc read/mmap, Wine boot, PE, DXVK or gameplay proven.''',
'''R3D18 extends source-witnessed original ld.so libc openat FD100 with a narrowly bounded host pread(832) from verified app-rootfs x86_64 libc into the already mapped writable 64KiB guest stack, returns actual count; next unknown source-witnessed x86 syscall stops. Earlier brk/access/cache are still diagnostic shims; guest fstat/mmap, full Linux VFS, Wine boot, PE, DXVK and gameplay remain unproven.''')
activity.write_text(s)
print("R3D18_ORIGINAL_GNU_LIBC_READ832_TO_OWNED_STACK_SOURCE_PROMOTION_PASS")
print("R3D18_BOUNDED_32_WITNESSES_NO_GENERIC_HOST_SYSCALL_FORWARDING_PASS")
