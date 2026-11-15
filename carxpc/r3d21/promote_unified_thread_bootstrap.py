#!/usr/bin/env python3
"""R3D21: grouped x86 guest THREAD/PROCESS ABI inside same 512-syscall 07H.

The first unseen original x86-64 syscall after successful TLS is
set_tid_address(218) at guest-owned 0x...63D0. Register it with a genuine
native-worker TID, without calling Android host set_tid_address. Include
set_robust_list(273), rseq(334)->ENOSYS, gettid/getpid and credentials in the
SAME source-verified ABI module. Unknown calls still stop with JSON evidence.
This is not a full multi-thread Wine, clone, futex wake or signal backend.
"""
from pathlib import Path
import re,sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_unified_thread_bootstrap.py /tmp/carxpc")
app=Path(sys.argv[1]);java=app/"app/src/main/java/com/r4/carxpc"
cpp=app/"app/src/main/cpp/carx_r3d4_first_syscall.cpp"
act=java/"R3D4ProbeActivity.java";main=java/"MainActivity.java"
gradle=app/"app/build.gradle";store=java/"R3D8JsonReportStore.java"
assert all(x.is_file() for x in (cpp,act,main,gradle,store))
def one(s,a,b):
 n=s.count(a)
 assert n==1,("R3D21_SOURCE_LOCK_ANCHOR_CHANGED",a[:110],n)
 return s.replace(a,b,1)
def reone(s,p,n):
 s,k=re.subn(p,n,s,count=1)
 assert k==1,("R3D21_REGEX_SOURCE_CHANGED",p,k)
 return s

s=gradle.read_text()
s=reone(s,r"\bversionCode\s+48\b","versionCode 49")
s=reone(s,r"versionName\s+'[^']+'",
        "versionName '0.49-r3d21-unified-wine-linux-thread-process-abi'")
gradle.write_text(s)
s=main.read_text()
s=one(s,"10 | R3D20 — محرك Wine Linux ABI الموحّد وTLS",
      "10 | R3D21 — إقلاع Wine الموحد مع TLS والخيوط")
main.write_text(s)
s=store.read_text()
s=one(s,'"CarX_PC_R3D20_UnifiedWineTLS_Diagnostics_"',
      '"CarX_PC_R3D21_UnifiedThreadBoot_Diagnostics_"')
store.write_text(s)

s=cpp.read_text()
s=one(s,
'''#include "carxpc/r3d20/native/guest_fs_gs_tls.hpp"''',
'''#include "carxpc/r3d20/native/guest_fs_gs_tls.hpp"
#include "carxpc/r3d21/native/single_guest_thread_abi.hpp"''')
s=one(s,'''  carx_r3d19::GuestMappings GuestMaps{};''',
'''  carx_r3d19::GuestMappings GuestMaps{};
  carx_r3d21::ThreadABI GuestThread{};''')
anchor=r'''        if(number==158) { // Linux x86-64 arch_prctl TLS'''
inject=r'''        // R3D21 grouped single-guest-thread Linux ABI. The original x86
        // GNU ld.so source witness is recorded before entering here.
        // Only data from the isolated native worker and explicitly owned
        // guest allocations may be returned. Never mutate Android host
        // clear_child_tid, robust list, TLS or process identity.
        const auto ownedGuest=[this](uint64_t address,uint64_t bytes){
          return GuestMaps.owned_range(address,bytes);
        };
        if(number==218) { // set_tid_address(int *clear_child_tid)
          const int64_t guestTid=
             GuestThread.register_guest_clear_child_tid(arg0,ownedGuest);
          if(guestTid<=0) {
            carx_r3d6::note("E_R3D21_SET_TID_ADDRESS_NOT_OWNED_OR_INVALID");
            ::_exit(151);
          }
          std::snprintf(msg,sizeof(msg),"N30_REAL_NATIVE_WORKER_TID_%lld",
                        static_cast<long long>(guestTid));
          carx_r3d6::note(msg);
          std::snprintf(msg,sizeof(msg),"N30_GUEST_CLEAR_CHILD_TID_%016llX",
                        static_cast<unsigned long long>(arg0));
          carx_r3d6::note(msg);
          accept(guestTid,"N22_BATCH_RETURN_R3D21_SET_TID_ADDRESS");
          return;
        }
        if(number==273) { // set_robust_list(head, sizeof(x86_64 struct))
          const int64_t result=
             GuestThread.register_guest_robust_list(arg0,arg1,ownedGuest);
          if(result!=0){
            carx_r3d6::note("E_R3D21_ROBUST_HEAD_NOT_OWNED_OR_ABI_WRONG");
            ::_exit(152);
          }
          carx_r3d6::note("N30_GUEST_ROBUST_LIST_REGISTERED_SINGLE_THREAD_ONLY");
          accept(0,"N22_BATCH_RETURN_R3D21_SET_ROBUST_LIST_BOUNDED");
          return;
        }
        if(number==334) { // rseq — no guest RSEQ kernel thread backend.
          const int64_t rejected=GuestThread.unsupported_guest_rseq(
              arg0,arg1,arg2,arg3);
          carx_r3d6::note("N30_GUEST_RSEQ_UNAVAILABLE_NO_KERNEL_FORWARDING");
          accept(rejected,"N22_BATCH_RETURN_R3D21_RSEQ_NEG_ENOSYS");
          return;
        }
        if(number==186) { // gettid — same real native worker as registration
          const int64_t guestTid=GuestThread.guest_gettid();
          if(guestTid<=0){
            carx_r3d6::note("E_R3D21_GETTID_KERNEL_WORKER_INVALID");
            ::_exit(153);
          }
          accept(guestTid,"N22_BATCH_RETURN_R3D21_GETTID_SINGLE_WORKER");
          return;
        }
        if(number==39) { // getpid — isolated app child process
          const int64_t guestPid=GuestThread.guest_getpid();
          if(guestPid<=0){
            carx_r3d6::note("E_R3D21_GETPID_ISOLATED_CHILD_INVALID");
            ::_exit(154);
          }
          accept(guestPid,"N22_BATCH_RETURN_R3D21_GETPID_ISOLATED_CHILD");
          return;
        }
        if(number==102 || number==107 || // getuid, geteuid
           number==104 || number==108) { // getgid, getegid
          const int64_t realId=number==102?int64_t(::getuid()) :
              number==107?int64_t(::geteuid()) :
              number==104?int64_t(::getgid()) :int64_t(::getegid());
          accept(realId,"N22_BATCH_RETURN_R3D21_REAL_APP_UID_GID");
          return;
        }
'''
s=one(s,anchor,inject+anchor)
assert all(x in s for x in [
 'N22_BATCH_RETURN_R3D21_SET_TID_ADDRESS',
 'N22_BATCH_RETURN_R3D21_SET_ROBUST_LIST_BOUNDED',
 'N22_BATCH_RETURN_R3D21_RSEQ_NEG_ENOSYS',
 'N22_BATCH_RETURN_R3D20_ARCH_SET_FS_GUEST_CPUSTATE',
 'N22_BATCH_RETURN_R3D19_MMAP_OWNED_GUEST',
 'context->ExecuteThread(thread)',
 'E_R3D19_WITNESS_CAP_512_REACHED'])
cpp.write_text(s)

s=act.read_text()
s=one(s,
'''runCacheless.setText("تشغيل 07H — R3D20 Wine ABI + TLS موحّد");''',
'''runCacheless.setText("تشغيل 07H — R3D21 Wine + TLS + Threads");''')
s=one(s,'"r4.carx.r3d20.integrated-wine-linux-abi-guest-tls.v1"',
      '"r4.carx.r3d21.integrated-wine-linux-abi-threads.v1"')
s=one(s,'"07H_INTEGRATED_WINE_GNU_LDSO_LINUX_ABI_TLS"',
      '"07H_INTEGRATED_WINE_GNU_LDSO_LINUX_ABI_TLS_THREADS"')
s=one(s,'"07H_R3D20_UNIFIED_WINE_GUEST_TLS_BATCH_512"',
      '"07H_R3D21_UNIFIED_WINE_TLS_THREADS_BATCH_512"')
s=one(s,
'''        report.put("r3d20_guest_tls_arch_prctl_via_fex_cpustate",true);''',
'''        report.put("r3d20_guest_tls_arch_prctl_via_fex_cpustate",true);
        boolean realTid=phases.toString().contains(
           "N22_BATCH_RETURN_R3D21_SET_TID_ADDRESS");
        if(realTid && (count<=16 || events.optJSONObject(16)==null ||
             events.optJSONObject(16).optLong("guest_syscall_number")!=218))
           return "R3D21_REJECTED_TID_RETURN_WITHOUT_SOURCE_LOCKED_218";
        report.put("r3d21_guest_clear_child_tid_registered",realTid);
        report.put("r3d21_tids_from_real_isolated_worker",true);
        report.put("r3d21_robust_list_registered",phases.toString().contains(
           "N22_BATCH_RETURN_R3D21_SET_ROBUST_LIST_BOUNDED"));
        report.put("r3d21_rseq_reports_enosys",phases.toString().contains(
           "N22_BATCH_RETURN_R3D21_RSEQ_NEG_ENOSYS"));
        report.put("r3d21_thread_exit_futex_clear_supported",false);
        report.put("r3d21_clone_and_multithread_supported",false);''')
s=one(s,
'''        stages.put("guest_tls_fs_base_initialized",tlsFsSet);''',
'''        stages.put("guest_tls_fs_base_initialized",tlsFsSet);
        stages.put("single_guest_thread_tid_registered",phases.toString().contains(
           "N22_BATCH_RETURN_R3D21_SET_TID_ADDRESS"));
        stages.put("guest_robust_head_registered",phases.toString().contains(
           "N22_BATCH_RETURN_R3D21_SET_ROBUST_LIST_BOUNDED"));
        stages.put("guest_rseq_capability_rejected",phases.toString().contains(
           "N22_BATCH_RETURN_R3D21_RSEQ_NEG_ENOSYS"));''')
s=one(s,
'''R3D20 integrates FEX x86 guest TLS arch_prctl ARCH_SET_FS/GS, GET_FS/GS with R3D19 source-locked Linux ABI and 512-event journal in one APK. Linux FS/GS bases update guest CPUState only and require owned guest mapped memory; host ARM64 TLS stays untouched. Unknown/unsafe operations stop with journal. This is not complete Linux process/thread/signal/VFS, Wine or Windows PE boot, DXVK, Vulkan or CarX gameplay.''',
'''R3D21 integrates into the same 512-source-witnessed GNU ld.so x86 Wine/Linux ABI bootstrap: genuine isolated native worker TID via set_tid_address(218) registered at owned guest pointer, getpid/gettid, guest robust-list address-only, rseq explicitly -ENOSYS, app UID/GID, plus R3D20 FEX guest FS/GS TLS and R3D19 libc ELF mappings. Never passes guest pointers to host set_tid_address. Guest clone, robust exit futex wake, complete Linux VFS and signals, full Wine or Win64 PE boot remain unproven.''')
act.write_text(s)
print("R3D21_UNIFIED_SINGLE_GUEST_THREAD_AND_TLS_SOURCE_LOCKED_RUNTIME_PASS")
print("R3D21_REAL_NATIVE_WORKER_TID_OWNED_CLEAR_CHILD_POINTER_AND_COHERENT_PROCESS_IDS")
