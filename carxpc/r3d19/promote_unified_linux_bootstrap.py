#!/usr/bin/env python3
"""R3D19 integrated Wine GNU ld.so Linux ABI bootstrap, opt-in mode4.

Bundled in one signed APK: source-locked read/pread64/lseek/fstat, real libc
FD100, bounded guest mappings/protection/unmapping, private brk growth, guest
stack I/O, 512 original x86 syscall witnesses and one JSON report.
Unsupported or unsafe operations still STOP instead of fake Wine success.
The guest rootfs is not a full Linux VFS; full Wine/PE boot is NOT claimed.
"""
from pathlib import Path
import re,sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_unified_linux_bootstrap.py /tmp/carxpc")
app=Path(sys.argv[1]); java=app/"app/src/main/java/com/r4/carxpc"
cpp=app/"app/src/main/cpp/carx_r3d4_first_syscall.cpp"
act=java/"R3D4ProbeActivity.java"; main=java/"MainActivity.java"
gradle=app/"app/build.gradle"; store=java/"R3D8JsonReportStore.java"
assert all(x.is_file() for x in (cpp,act,main,gradle,store))
def one(s,a,b):
    n=s.count(a)
    assert n==1,("R3D19_PINNED_SOURCE_ANCHOR_CHANGED",a[:130],n)
    return s.replace(a,b,1)
def reone(s,pat,new):
    s,n=re.subn(pat,new,s,count=1)
    assert n==1,("R3D19_REGEX_SOURCE_CHANGED",pat,n)
    return s

s=gradle.read_text()
s=reone(s,r"\bversionCode\s+46\b","versionCode 47")
s=reone(s,r"versionName\s+'[^']+'",
    "versionName '0.47-r3d19-integrated-source-locked-wine-bootstrap'")
gradle.write_text(s)
s=main.read_text()
s=one(s,"10 | R3D18 — قراءة libc الحقيقية ومعالجة دفعة Wine",
      "10 | R3D19 — منظومة Linux ABI المجمّعة لإقلاع Wine")
main.write_text(s)
s=store.read_text()
s=one(s,'"CarX_PC_R3D18_LibcRead_Batch_Diagnostics_"',
      '"CarX_PC_R3D19_UnifiedWineBoot_Diagnostics_"')
store.write_text(s)

s=cpp.read_text()
s=one(s,
'#include "carxpc/r3d18/native/bounded_libc_guest_read.hpp"',
'#include "carxpc/r3d18/native/bounded_libc_guest_read.hpp"\n'
'#include "carxpc/r3d19/native/unified_guest_libc_abi.hpp"')
# Keep 07G's 32-call cap unchanged. Only mode4 gets 512 witnesses.
s=one(s,
'''if(Seen>=carx_r3d13::kMaxWitnesses-1) {
        carx_r3d6::note("E_BATCH_WITNESS_CAP_32_REACHED");''',
'''if(Seen>= (Mode==4 ? 511 : carx_r3d13::kMaxWitnesses-1)) {
        carx_r3d6::note(Mode==4 ?
            "E_R3D19_WITNESS_CAP_512_REACHED" :
            "E_BATCH_WITNESS_CAP_32_REACHED");''')
s=one(s,
'''  int LibcHostFD{-1};
  uint64_t LibcReadCursor{0};''',
'''  int LibcHostFD{-1};
  uint64_t LibcReadCursor{0};
  bool LibcGuestOpen{true};
  uint64_t GuestBrkCurrent{0};
  carx_r3d19::GuestMappings GuestMaps{};''')
s=one(s,
'''              carx_r3d6::note("N24_R3D17_LIBC_REAL_FD_SOURCE_VERIFIED");''',
'''              LibcGuestOpen=true;
              LibcReadCursor=0;
              carx_r3d6::note("N24_R3D17_LIBC_REAL_FD_SOURCE_VERIFIED");''')
s=one(s,
'''if(Mode==4 && number==0 && Seen>=4 &&
         arg0==uint64_t(carx_r3d17::kGuestLibcFd))''',
'''if(Mode==4 && number==0 && Seen>=4 && LibcGuestOpen &&
         arg0==uint64_t(carx_r3d17::kGuestLibcFd))''')
# All extended x86 syscall arguments remain sourced from the real FEX CPU
# frame; never infer pread offsets or mmap flags from a previous report.
s=one(s,
'''      std::snprintf(msg,sizeof(msg),"N21_BATCH_INDEX_%d",Seen);''',
'''      if(Mode==4) {
        std::snprintf(msg,sizeof(msg),"N26_SYSCALL_ARG3_%016llX",
          static_cast<unsigned long long>(
            state.gregs[FEXCore::X86State::REG_R10]));
        carx_r3d6::note(msg);
        std::snprintf(msg,sizeof(msg),"N26_SYSCALL_ARG4_%016llX",
          static_cast<unsigned long long>(
            state.gregs[FEXCore::X86State::REG_R8]));
        carx_r3d6::note(msg);
        std::snprintf(msg,sizeof(msg),"N26_SYSCALL_ARG5_%016llX",
          static_cast<unsigned long long>(
            state.gregs[FEXCore::X86State::REG_R9]));
        carx_r3d6::note(msg);
      }
      std::snprintf(msg,sizeof(msg),"N21_BATCH_INDEX_%d",Seen);''')
inject=r'''      // R3D19 unified source-locked Linux ABI dispatch (07H only).
      // Every event has already been recorded as authentic original x86
      // GNU ld.so SYSCALL byte pair and full guest register snapshot.
      if(Mode==4) {
        const uint64_t arg3=state.gregs[FEXCore::X86State::REG_R10];
        const uint64_t arg4=state.gregs[FEXCore::X86State::REG_R8];
        const uint64_t arg5=state.gregs[FEXCore::X86State::REG_R9];
        const uint64_t libcFd=uint64_t(carx_r3d17::kGuestLibcFd);
        const auto accept=[&](int64_t value,const char*note) {
          state.gregs[FEXCore::X86State::REG_RAX]=static_cast<uint64_t>(value);
          state.rip=newRIP;
          ++Seen;
          carx_r3d6::note(note);
        };
        if(number==17 && arg0==libcFd && LibcGuestOpen) { // pread64
          // x86-64 ABI positional offset in R10; file cursor untouched.
          const auto outcome=carx_r3d19::pread64_verified_libc_stack(
              LibcHostFD,arg0,arg1,arg2,arg3);
          if(!outcome.ok) {
            carx_r3d6::note("E_R3D19_PREAD64_FD_OFFSET_OR_STACK_UNSAFE");
            ::_exit(131);
          }
          std::snprintf(msg,sizeof(msg),"N27_PREAD64_OFFSET_%016llX",
                        static_cast<unsigned long long>(arg3));
          carx_r3d6::note(msg);
          std::snprintf(msg,sizeof(msg),"N27_PREAD64_RETURNED_%zd",
                        outcome.n);
          carx_r3d6::note(msg);
          accept(int64_t(outcome.n),"N22_BATCH_RETURN_R3D19_PREAD64_REAL_LIBC");
          return;
        }
        if(number==5 && arg0==libcFd && LibcGuestOpen) { // fstat
          if(!carx_r3d19::fstat_verified_libc_to_guest_stack(
                 LibcHostFD,arg0,arg1)) {
            carx_r3d6::note("E_R3D19_FSTAT_GUEST_STACK_OR_LIBC_INVALID");
            ::_exit(132);
          }
          accept(0,"N22_BATCH_RETURN_R3D19_FSTAT_X64_144");
          return;
        }
        if(number==8 && arg0==libcFd && LibcGuestOpen) { // lseek
          struct stat st{};
          if(::fstat(LibcHostFD,&st)!=0 ||
             !carx_r3d17::verified_readonly_libc_fd(LibcHostFD)) {
            carx_r3d6::note("E_R3D19_LSEEK_SOURCE_FILE_INVALID");
            ::_exit(133);
          }
          const int64_t off=static_cast<int64_t>(arg1);
          int64_t base=0;
          if(arg2==SEEK_CUR)base=int64_t(LibcReadCursor);
          else if(arg2==SEEK_END)base=int64_t(st.st_size);
          else if(arg2!=SEEK_SET){
            carx_r3d6::note("E_R3D19_LSEEK_WHENCE_NOT_SUPPORTED");
            ::_exit(134);
          }
          if(off<0 && -off>base || off>0 &&
             uint64_t(off)>carx_r3d17::kMaxLibcLength-uint64_t(base)){
            carx_r3d6::note("E_R3D19_LSEEK_OFFSET_OUT_OF_BOUNDS");
            ::_exit(135);
          }
          const int64_t next=base+off;
          if(next<0 || uint64_t(next)>carx_r3d17::kMaxLibcLength){
            carx_r3d6::note("E_R3D19_LSEEK_RESULT_OUT_OF_BOUNDS");
            ::_exit(136);
          }
          LibcReadCursor=uint64_t(next);
          accept(next,"N22_BATCH_RETURN_R3D19_LSEEK_REAL_LIBC");
          return;
        }
        if(number==9) { // mmap(addr,len,prot,flags,fd,offset)
          const int64_t mapped=GuestMaps.map(
              LibcHostFD,LibcGuestOpen,arg0,arg1,arg2,arg3,arg4,arg5);
          if(mapped<0) {
            std::snprintf(msg,sizeof(msg),"E_R3D19_MMAP_GUEST_VM_DENIED_%lld",
                          static_cast<long long>(mapped));
            carx_r3d6::note(msg);
            ::_exit(137);
          }
          std::snprintf(msg,sizeof(msg),"N28_MMAP_GUEST_ADDRESS_%016llX",
                        static_cast<unsigned long long>(mapped));
          carx_r3d6::note(msg);
          accept(mapped,"N22_BATCH_RETURN_R3D19_MMAP_OWNED_GUEST");
          return;
        }
        if(number==10) { // mprotect
          const int64_t rc=GuestMaps.protect(arg0,arg1,arg2);
          if(rc<0) {
            carx_r3d6::note("E_R3D19_MPROTECT_NON_OWNED_OR_WX_DENIED");
            ::_exit(138);
          }
          accept(0,"N22_BATCH_RETURN_R3D19_MPROTECT_OWNED_GUEST");
          return;
        }
        if(number==11) { // munmap
          const int64_t rc=GuestMaps.unmap(arg0,arg1);
          if(rc<0) {
            carx_r3d6::note("E_R3D19_MUNMAP_UNOWNED_OR_PARTIAL_DENIED");
            ::_exit(139);
          }
          accept(0,"N22_BATCH_RETURN_R3D19_MUNMAP_OWNED_GUEST");
          return;
        }
        if(number==3 && arg0==libcFd && LibcGuestOpen){ // close
          LibcGuestOpen=false; // Host FD remains owned by JNI until process exit.
          accept(0,"N22_BATCH_RETURN_R3D19_LIBC_VIRTUAL_FD_CLOSE");
          return;
        }
        if(number==12 && arg0!=0 && BRKBase) { // brk growth
          if(!carx_r3d19::grow_guest_brk(
                  BRKBase,arg0,GuestBrkCurrent)) {
            carx_r3d6::note("E_R3D19_BRK_OUTSIDE_OWNED_HEAP");
            ::_exit(140);
          }
          accept(int64_t(arg0),"N22_BATCH_RETURN_R3D19_BRK_OWNED_GROWTH");
          return;
        }
      }
'''
s=one(s,
'''      std::snprintf(msg,sizeof(msg),"E_BATCH_UNSUPPORTED_NR_%llu",''',
inject+'''      std::snprintf(msg,sizeof(msg),"E_BATCH_UNSUPPORTED_NR_%llu",''')
assert all(t in s for t in (
  'N22_BATCH_RETURN_R3D19_PREAD64_REAL_LIBC',
  'N22_BATCH_RETURN_R3D19_FSTAT_X64_144',
  'N22_BATCH_RETURN_R3D19_MMAP_OWNED_GUEST',
  'N22_BATCH_RETURN_R3D19_MPROTECT_OWNED_GUEST',
  'N22_BATCH_RETURN_R3D19_MUNMAP_OWNED_GUEST',
  'N22_BATCH_RETURN_R3D19_BRK_OWNED_GROWTH',
  'E_R3D19_WITNESS_CAP_512_REACHED',
  'context->ExecuteThread(thread)','N22_BATCH_RETURN_READ_LIBC_FD100'))
cpp.write_text(s)

s=act.read_text()
s=one(s,
'''runCacheless.setText("تشغيل 07H — R3D18 قراءة libc + Batch");''',
'''runCacheless.setText("تشغيل 07H — R3D19 Linux ABI + Wine Bootstrap");''')
s=one(s,'"r4.carx.r3d18.real-libc-read832-batch.v1"',
      '"r4.carx.r3d19.integrated-wine-linux-abi-bootstrap.v1"')
s=one(s,'"07H_ROOTFS_LIBC_PREOPEN_PLUS_REAL_READ_GUEST_STACK"',
      '"07H_INTEGRATED_WINE_GNU_LDSO_LINUX_ABI_BOOTSTRAP"')
s=one(s,'"07H_R3D18_REAL_LIBC_READ832_BATCH_32"',
      '"07H_R3D19_INTEGRATED_WINE_BOOTSTRAP_BATCH_512"')
s=one(s,'    private static String inspectBatchJournal(',
      '    private String inspectBatchJournal(')
s=one(s,'        report.put("batch_max_witnesses",32);',
'''        final int guestWitnessLimit=currentProbeMode==4?512:32;
        report.put("batch_max_witnesses",guestWitnessLimit);''')
s=one(s,'''data.length>32*56)''',
      '''data.length>guestWitnessLimit*56)''')
s=one(s,'''if(handled>count || handled>32)''',
      '''if(handled>count || handled>guestWitnessLimit)''')
s=one(s,
'''        if(stop.startsWith("E_BATCH_UNSUPPORTED_NR_"))''',
'''        if(stop.equals("E_R3D19_WITNESS_CAP_512_REACHED"))
            return "R3D19_INTEGRATED_BOOTSTRAP_SOURCE_WITNESS_LIMIT_512";
        if(stop.startsWith("E_R3D19_"))
            return "R3D19_INTEGRATED_BOOTSTRAP_GUEST_ABI_BOUNDED_STOP";
        if(stop.startsWith("E_BATCH_UNSUPPORTED_NR_"))''')
s=one(s,
'''        if (!lines.isEmpty() && lines.size() <= 512 &&''',
'''        if (!lines.isEmpty() && lines.size() <= 8192 &&''')
s=one(s,
'''        report.put("batch_libc_read832_guest_stack_verified",readLibcVerified);''',
'''        report.put("batch_libc_read832_guest_stack_verified",readLibcVerified);
        report.put("r3d19_integrated_linux_abi_enabled",currentProbeMode==4);
        report.put("r3d19_abi_capabilities",
            "pread64_R10,lseek,fstat_x64,mmap_private_anon_or_libc,mprotect,munmap_whole_owned_region,close_libc,brk_owned_growth");
        report.put("r3d19_real_pread64_observed",
            phases.toString().contains(
                "N22_BATCH_RETURN_R3D19_PREAD64_REAL_LIBC"));
        report.put("r3d19_real_mmap_observed",
            phases.toString().contains(
                "N22_BATCH_RETURN_R3D19_MMAP_OWNED_GUEST"));
        report.put("r3d19_real_fstat_observed",
            phases.toString().contains(
                "N22_BATCH_RETURN_R3D19_FSTAT_X64_144"));
        report.put("r3d19_original_wine_loader_progress_only",true);''')
s=one(s,'''        report.put("batch_was_not_full_wine_boot",true);''',
'''        report.put("batch_was_not_full_wine_boot",true);
        report.put("r3d19_full_wine_boot_proven",false);
        report.put("r3d19_windows_pe_boot_proven",false);''')
s=one(s,'''R3D18 extends source-witnessed original ld.so libc openat FD100 with a narrowly bounded host pread(832) from verified app-rootfs x86_64 libc into the already mapped writable 64KiB guest stack, returns actual count; next unknown source-witnessed x86 syscall stops. Earlier brk/access/cache are still diagnostic shims; guest fstat/mmap, full Linux VFS, Wine boot, PE, DXVK and gameplay remain unproven.''',
'''R3D19 integrated one-APK source-locked diagnostic bootstrap: authentic GNU ld.so x86 Linux syscall journal up to 512 witnesses; bounded rootfs libc guest FD100 read and pread64 R10, x86 fstat, owned private mmap/protection/unmapping, brk heap growth and lseek. All unsupported or unsafe requests stop in child process. This does not implement the whole Linux rootfs VFS, process/thread/signal/TLS system, all Wine dependencies, full Wine boot, Windows PE, DXVK, Vulkan or game launch.''')
act.write_text(s)
print("R3D19_ONE_APK_INTEGRATED_LINUX_ABI_SOURCE_LOCKED_BOOTSTRAP_PROMOTED_PASS")
print("R3D19_PREADER_FSTAT_MMAP_MPROTECT_MUNMAP_LSEEK_BRK_GUARDED_WITH_512_ORIGINAL_WITNESSES")
