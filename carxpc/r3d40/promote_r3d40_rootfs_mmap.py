#!/usr/bin/env python3
"""R3D40: real bounded RootFS FD101+ file mmap and original x86 Wine ELF RX opcode source."""
from pathlib import Path
import sys
if len(sys.argv)!=2: raise SystemExit("usage: promote_r3d40_rootfs_mmap.py /tmp/carxpc")
root=Path(sys.argv[1])/"app"
cpp=root/"src/main/cpp/carx_r3d4_first_syscall.cpp"
act=root/"src/main/java/com/r4/carxpc/R3D4ProbeActivity.java"
store=root/"src/main/java/com/r4/carxpc/R3D8JsonReportStore.java"
main=root/"src/main/java/com/r4/carxpc/MainActivity.java"
gradle=root/"build.gradle"
assert all(p.is_file() for p in (cpp,act,store,main,gradle))
def one(s,a,b):
 n=s.count(a)
 assert n==1,("R3D40_SOURCE_CHANGED",a[:150],n)
 return s.replace(a,b,1)

s=cpp.read_text()
s=one(s,
'#include "carxpc/r3d33/native/preflight24_guest_vm_paths.hpp"',
'''#include "carxpc/r3d33/native/preflight24_guest_vm_paths.hpp"
#include "carxpc/r3d40/native/verified_rootfs_mmap_source.hpp"''')
s=one(s,
'''  carx_r3d25::RootfsLibcSource LibcOpcodeSource{};''',
'''  carx_r3d25::RootfsLibcSource LibcOpcodeSource{};
  carx_r3d40::GuestRootfsRxSource RootfsOpcodeSource{};''')

# Source-independent, verified RX guest ELF identity. No guest memory pointer or
# untrusted host FD is forwarded to the kernel. Selection is exclusive across
# GNU ldso, Wine, libc FD100, and installed original app-rootfs ELF FD101+.
s=one(s,
'''       verified=carx_r3d25::select_exactly_one(
         sourceGNU,sourceWine,sourceLibc,owner,record);
       if(!verified) {''',
'''       verified=carx_r3d25::select_exactly_one(
         sourceGNU,sourceWine,sourceLibc,owner,record);
       carx_r3d3::Record rootfsRecord{};
       const bool rootfsHit=RootfsOpcodeSource.make_record(
         state.rip,state.gregs[FEXCore::X86State::REG_RAX],
         Nonce,executable,&rootfsRecord);
       if(rootfsHit){
         carx_r3d3::Record other{};
         if(verified || sourceGNU(&other) || sourceWine(&other) ||
            sourceLibc(&other)){
           verified=false;
           carx_r3d6::note("E_R3D40_MULTIPLE_GUEST_ELF_OPCODE_SOURCES");
         }else{
           verified=true;
           owner=carx_r3d25::Source::ROOTFS_ELF_FD101_116;
           record=rootfsRecord;
         }
       }
       if(!verified) {''')
s=one(s,
'''        "N34_SOURCE_DOMAIN_VERIFIED_LIBC_FD100");''',
'''        owner==carx_r3d25::Source::LIBC_FD100?
        "N34_SOURCE_DOMAIN_VERIFIED_LIBC_FD100":
        "N34_SOURCE_DOMAIN_ROOTFS_ELF_FD101_116");''')

# This intercept is intentionally BEFORE the old libc-only mmap(9) switch.
s=one(s,
'''        if(number==9) { // mmap(addr,len,prot,flags,fd,offset)''',
'''        if(number==9 &&
           (arg3&carx_r3d19::kLinuxMapAnonymous)==0 &&
           GuestReadOnlyFiles.owns(arg4)) {
          // The guest FD is a private VFS token, not an Android host FD.
          // A dup is granted ONLY for an O_NOFOLLOW read-only regular file
          // originally opened below the authenticated app rootfs descriptor.
          const int pinnedFd=GuestReadOnlyFiles.dup_regular_guest_fd_for_mapping(arg4);
          if(pinnedFd<0){
            char reason[110]{};
            std::snprintf(reason,sizeof(reason),
               "E_R3D40_ROOTFS_FD_MMAP_INVALID_NEG_%llu",
               static_cast<unsigned long long>(-int64_t(pinnedFd)));
            carx_r3d6::note(reason);::_exit(201);
          }
          const int64_t mapped=GuestMaps.map(
            pinnedFd,true,arg0,arg1,arg2,arg3,arg4,arg5,true);
          if(mapped<0){
            char reason[110]{};
            std::snprintf(reason,sizeof(reason),
               "E_R3D40_ROOTFS_FD_MMAP_DENIED_NEG_%llu",
               static_cast<unsigned long long>(-mapped));
            carx_r3d6::note(reason);
            ::close(pinnedFd);::_exit(202);
          }
          uint64_t mapLen=0;
          const bool rx=(arg2&(PROT_READ|PROT_EXEC))==
                              (PROT_READ|PROT_EXEC);
          if(((arg2&PROT_EXEC)!=0 && !rx) ||
             !carx_r3d19::checked_round_page(arg1,mapLen) ||
             !ExecVMAs.replace_permissions(uint64_t(mapped),
                                           mapLen,(arg2&PROT_EXEC)!=0) ||
             !RootfsOpcodeSource.observe_mmap(
                  pinnedFd,uint64_t(mapped),mapLen,rx,arg5)){
            carx_r3d6::note("E_R3D40_GUEST_ROOTFS_ELF_VMA_SOURCE_UNPROVEN");
            ::close(pinnedFd);::_exit(203);
          }
          ::close(pinnedFd);
          carx_r3d6::note("N61_R3D40_ROOTFS_FD101_FILE_MMAP_ACCEPTED");
          if(rx)carx_r3d6::note(
             "N62_R3D40_VERIFIED_ROOTFS_ELF_RX_OPCODE_SOURCE_REGISTERED");
          accept(mapped,"N22_BATCH_RETURN_R3D40_ROOTFS_FD_MMAP");
          return;
        }
        if(number==9) { // mmap(addr,len,prot,flags,fd,offset)''')

# The legacy libc-only mmap error had a '-' char, which was disallowed by the
# nonce-bound journal regexp and disguised real -EBADF as a nonce mismatch.
s=one(s,
'''"E_R3D19_MMAP_GUEST_VM_DENIED_%lld",
                          static_cast<long long>(mapped)''',
'''"E_R3D19_MMAP_GUEST_VM_DENIED_NEG_%llu",
                          static_cast<unsigned long long>(-mapped)''')

s=one(s,
'''          LibcOpcodeSource.invalidate(arg0,pageLength);''',
'''          LibcOpcodeSource.invalidate(arg0,pageLength);
          RootfsOpcodeSource.invalidate(arg0,pageLength);''')
s=one(s,
'''          LibcOpcodeSource.invalidate(arg0,arg1);''',
'''          LibcOpcodeSource.invalidate(arg0,arg1);
          RootfsOpcodeSource.invalidate(arg0,arg1);''')
assert all(x in s for x in (
  "N61_R3D40_ROOTFS_FD101_FILE_MMAP_ACCEPTED",
  "N62_R3D40_VERIFIED_ROOTFS_ELF_RX_OPCODE_SOURCE_REGISTERED",
  "N34_SOURCE_DOMAIN_ROOTFS_ELF_FD101_116",
  "N60_R3D39_REAL_FEX_OPENAT_REACHED_PATCHED_ROOTFS",
  "context->ExecuteThread(thread)"))
cpp.write_text(s)

s=act.read_text()
s=one(s,"r4.carx.r3d39.real-guest-rootfs-runtime-trace-fex512.v1",
        "r4.carx.r3d40.real-rootfs-file-mmap-elf-rx-fex512.v1")
s=one(s,"07H_R3D39_ROOTFS_OPENAT_TRACE_AUTHENTIC_FEX512",
        "07H_R3D40_ROOTFS_MMAP_ELF_RX_AUTHENTIC_FEX512")
s=one(s,"07H_R3D39_TRACE_WINE_ROOTFS_FEX512",
        "07H_R3D40_ROOTFS_ELF_MMAP_FEX512")
s=one(s,"R3D39 Trace RootFS + Wine 512",
        "R3D40 RootFS mmap + Wine 512")
s=one(s,
'''        report.put("r3d39_apk_runtime_identity","R3D39_v63_PATCHED_NATIVE_ROOTFS_TRACE");''',
'''        report.put("r3d39_apk_runtime_identity","R3D39_v63_PATCHED_NATIVE_ROOTFS_TRACE");
        report.put("r3d40_apk_runtime_identity","R3D40_v64_REAL_FD101_ELF_MMAP");
        report.put("r3d40_rootfs_fd101_file_mmap_accepted",
          phases.toString().contains("N61_R3D40_ROOTFS_FD101_FILE_MMAP_ACCEPTED"));
        report.put("r3d40_rootfs_elf_rx_source_registered",
          phases.toString().contains("N62_R3D40_VERIFIED_ROOTFS_ELF_RX_OPCODE_SOURCE_REGISTERED"));
        report.put("r3d40_rootfs_elf_callback_witnessed",
          phases.toString().contains("N34_SOURCE_DOMAIN_ROOTFS_ELF_FD101_116"));''')
# Accept a bounded diagnostic negative errno string. Nonce/header matching is
# unchanged: we only prevent legitimate negative error details from corrupting
# a perfectly valid native phase session.
s=one(s,'[A-Z0-9_]{3,150}','[A-Z0-9_-]{3,150}')
act.write_text(s)

s=store.read_text()
s=one(s,"CarX_PC_R3D39_RootfsTrace_Diagnostics_",
        "CarX_PC_R3D40_ElfMmap_Diagnostics_")
store.write_text(s)
s=main.read_text()
s=one(s,"10 | R3D39 — إثبات تشغيل Wine RootFS",
        "10 | R3D40 — ربط خرائط Wine ELF")
main.write_text(s)
s=gradle.read_text()
s=one(s,"versionCode 63","versionCode 64")
s=one(s,"0.63-r3d39-rootfs-openat-verified-trace",
        "0.64-r3d40-rootfs-mmap-elf-rx")
gradle.write_text(s)
print("R3D40_NATIVE_FEX_ROOTFS_FD101_MMAP_ELF_RX_OPCODE_SOURCE_PROMOTION_PASS")
print("R3D40_NONCE_BOUND_PHASE_JOURNAL_SIGNED_ERROR_MESSAGES_FIXED")
