#!/usr/bin/env python3
"""R3D22: instrument FEX ExecuteThread returning after 19 source-locked calls.

Same integrated R3D19-R3D21 512-witness Wine Linux ABI; no new isolated syscall
probe. Only capture FEX guest CPUState read-only AFTER ExecuteThread returns,
including RIP, x86 return/error registers and synchronous fault flags; publish
a dedicated terminal marker and grouped report. Do not infer an unproven
SIGSEGV/SIGILL/HLT, blindly resume execution or claim Wine boot.
"""
from pathlib import Path
import re,sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_return_provenance.py /tmp/carxpc")
app=Path(sys.argv[1]);java=app/"app/src/main/java/com/r4/carxpc"
cpp=app/"app/src/main/cpp/carx_r3d4_first_syscall.cpp"
act=java/"R3D4ProbeActivity.java";main=java/"MainActivity.java"
gradle=app/"app/build.gradle";store=java/"R3D8JsonReportStore.java"
assert all(x.is_file() for x in (cpp,act,main,gradle,store))
def one(s,a,n):
 c=s.count(a)
 assert c==1,("R3D22_SOURCE_LOCK_ANCHOR_CHANGED",a[:125],c)
 return s.replace(a,n,1)
def reone(s,p,n):
 s,k=re.subn(p,n,s,count=1)
 assert k==1,("R3D22_VERSION_ANCHOR_CHANGED",p,k)
 return s
s=gradle.read_text()
s=reone(s,r"\bversionCode\s+49\b","versionCode 50")
s=reone(s,r"versionName\s+'[^']+'",
        "versionName '0.50-r3d22-unified-fex-execution-return-provenance'")
gradle.write_text(s)
s=main.read_text()
s=one(s,"10 | R3D21 — إقلاع Wine الموحد مع TLS والخيوط",
      "10 | R3D22 — إقلاع Wine الموحّد وتشخيص رجوع FEX")
main.write_text(s)
s=store.read_text()
s=one(s,'"CarX_PC_R3D21_UnifiedThreadBoot_Diagnostics_"',
      '"CarX_PC_R3D22_FEXReturn_Diagnostics_"')
store.write_text(s)
s=cpp.read_text()
s=one(s,
'''#include "carxpc/r3d21/native/single_guest_thread_abi.hpp"''',
'''#include "carxpc/r3d21/native/single_guest_thread_abi.hpp"
#include "carxpc/r3d22/native/postexecute_guest_snapshot.hpp"''')
# This is a DIFFERENT failure class from unknown x86 syscall. Instrument only
# AFTER real FEX execute returns, never change previously accepted responses.
s=one(s,
'''  context->ExecuteThread(thread);
  reason="FEX_EXECUTE_RETURNED_WITHOUT_SOURCE_LOCKED_SYSCALL";''',
'''  context->ExecuteThread(thread);
  if(mode==4) {
    // FEXCore 02e24ca: ExecuteThread returns void, so the CPUState and
    // synchronous-fault fields are only post-return observations, NOT proof
    // of the faulting guest instruction or its underlying exit cause.
    carx_r3d6::note("N31_FEX_EXECUTE_THREAD_RETURNED_TO_JNI_WORKER");
    if(thread && thread->CurrentFrame) {
      const auto snap=carx_r3d22::capture_readonly_postexecute(
          *thread->CurrentFrame,
          FEXCore::X86State::REG_RAX,FEXCore::X86State::REG_RSP,
          FEXCore::X86State::REG_RBP,FEXCore::X86State::REG_RDI,
          FEXCore::X86State::REG_RSI,FEXCore::X86State::REG_RDX);
      char output[144]{};
      const auto hex=[&](const char* label,uint64_t value){
        std::snprintf(output,sizeof(output),"%s_%016llX",label,
          static_cast<unsigned long long>(value));
        carx_r3d6::note(output);
      };
      const auto number=[&](const char* label,uint64_t value){
        std::snprintf(output,sizeof(output),"%s_%llu",label,
          static_cast<unsigned long long>(value));
        carx_r3d6::note(output);
      };
      hex("N31_POSTEXEC_GUEST_RIP",snap.stateRip);
      hex("N31_POSTEXEC_GUEST_RAX",snap.rax);
      hex("N31_POSTEXEC_GUEST_RSP",snap.rsp);
      hex("N31_POSTEXEC_GUEST_RBP",snap.rbp);
      hex("N31_POSTEXEC_GUEST_RDI",snap.rdi);
      hex("N31_POSTEXEC_GUEST_RSI",snap.rsi);
      hex("N31_POSTEXEC_GUEST_RDX",snap.rdx);
      hex("N31_POSTEXEC_GUEST_FS",snap.fsBase);
      hex("N31_POSTEXEC_GUEST_GS",snap.gsBase);
      number("N31_POSTEXEC_SYNCHRONOUS_SIGNAL",snap.synchronousSignal);
      number("N31_POSTEXEC_SYNCHRONOUS_TRAP",snap.trapNo);
      number("N31_POSTEXEC_SYNCHRONOUS_SICODE",snap.siCode);
      number("N31_POSTEXEC_SYNCHRONOUS_ERR",snap.errCode);
      number("N31_POSTEXEC_FAULT_TO_TOP",
             snap.faultToTopAndGeneratedException?1:0);
      carx_r3d6::note(carx_r3d22::coherent_register_snapshot(snap)?
          "N31_POSTEXEC_CONTEXT_REGISTER_ENVELOPE_COHERENT":
          "N31_POSTEXEC_CONTEXT_REGISTER_ENVELOPE_UNCERTAIN");
    } else {
      carx_r3d6::note("N31_POSTEXEC_GUEST_FRAME_UNAVAILABLE");
    }
    carx_r3d6::note("E_R3D22_FEX_EXECUTE_RETURN_NO_NEW_X86_SYSCALL");
  }
  reason="FEX_EXECUTE_RETURNED_WITHOUT_SOURCE_LOCKED_SYSCALL";''')
assert "context->ExecuteThread(thread);" in s
assert "E_R3D22_FEX_EXECUTE_RETURN_NO_NEW_X86_SYSCALL" in s
assert "N22_BATCH_RETURN_R3D21_RSEQ_NEG_ENOSYS" in s
cpp.write_text(s)
s=act.read_text()
s=one(s,
'''runCacheless.setText("تشغيل 07H — R3D21 Wine + TLS + Threads");''',
'''runCacheless.setText("تشغيل 07H — R3D22 Wine + FEX Return Trace");''')
s=one(s,'"r4.carx.r3d21.integrated-wine-linux-abi-threads.v1"',
      '"r4.carx.r3d22.integrated-wine-fex-return-provenance.v1"')
s=one(s,'"07H_INTEGRATED_WINE_GNU_LDSO_LINUX_ABI_TLS_THREADS"',
      '"07H_INTEGRATED_WINE_GNU_LDSO_LINUX_ABI_TLS_THREADS_FEX_RETURN"')
s=one(s,'"07H_R3D21_UNIFIED_WINE_TLS_THREADS_BATCH_512"',
      '"07H_R3D22_UNIFIED_WINE_FEX_RETURN_BATCH_512"')
s=one(s,'''if(p.startsWith("E_BATCH_")) stop=p;''',
'''if(p.startsWith("E_BATCH_") || p.startsWith("E_R3D22_")) stop=p;''')
s=one(s,
'''        if(stop.equals("E_R3D19_WITNESS_CAP_512_REACHED"))''',
'''        if(stop.equals("E_R3D22_FEX_EXECUTE_RETURN_NO_NEW_X86_SYSCALL"))
            return "R3D22_FEX_EXECUTE_RETURNED_AFTER_RESPONSES_NOT_WINE_BOOT";
        if(stop.equals("E_R3D19_WITNESS_CAP_512_REACHED"))''')
s=one(s,
'''        report.put("r3d21_clone_and_multithread_supported",false);''',
'''        report.put("r3d21_clone_and_multithread_supported",false);
        final boolean returned=phases.toString().contains(
          "N31_FEX_EXECUTE_THREAD_RETURNED_TO_JNI_WORKER") &&
          phases.toString().contains(
          "E_R3D22_FEX_EXECUTE_RETURN_NO_NEW_X86_SYSCALL");
        report.put("r3d22_fex_execute_returned_without_guest_syscall",returned);
        report.put("r3d22_fex_return_cause_proven",false);
        report.put("r3d22_guest_rip_may_be_stale_after_jit",true);
        report.put("r3d22_after_rseq_negative_enosys",
          returned && phases.toString().contains(
             "N22_BATCH_RETURN_R3D21_RSEQ_NEG_ENOSYS"));
        JSONObject stateSnapshot=new JSONObject();
        final String[] names={"GUEST_RIP","GUEST_RAX","GUEST_RSP",
          "GUEST_RBP","GUEST_RDI","GUEST_RSI","GUEST_RDX",
          "GUEST_FS","GUEST_GS"};
        for(String name:names) {
          final String marker="N31_POSTEXEC_"+name+"_";
          for(int i=0;i<phases.length();i++){
            String line=phases.optString(i,"");
            if(line.startsWith(marker))
              stateSnapshot.put(name.toLowerCase(java.util.Locale.ROOT),
                line.substring(marker.length()));
          }
        }
        report.put("r3d22_fex_postexecute_guest_register_snapshot",stateSnapshot);
        JSONObject signalFlags=new JSONObject();
        final String[] fields={"SYNCHRONOUS_SIGNAL","SYNCHRONOUS_TRAP",
          "SYNCHRONOUS_SICODE","SYNCHRONOUS_ERR","FAULT_TO_TOP"};
        for(String field:fields){
          final String marker="N31_POSTEXEC_"+field+"_";
          for(int i=0;i<phases.length();++i){
            final String line=phases.optString(i,"");
            if(line.startsWith(marker))
              signalFlags.put(field.toLowerCase(java.util.Locale.ROOT),
                line.substring(marker.length()));
          }
        }
        report.put("r3d22_fex_postexecute_sync_fault_observations",signalFlags);''')
s=one(s,
'''        stages.put("guest_rseq_capability_rejected",phases.toString().contains(
           "N22_BATCH_RETURN_R3D21_RSEQ_NEG_ENOSYS"));''',
'''        stages.put("guest_rseq_capability_rejected",phases.toString().contains(
           "N22_BATCH_RETURN_R3D21_RSEQ_NEG_ENOSYS"));
        stages.put("fex_postexecute_state_captured",phases.toString().contains(
           "N31_POSTEXEC_GUEST_RIP_"));
        stages.put("fex_return_requires_diagnosis",phases.toString().contains(
           "E_R3D22_FEX_EXECUTE_RETURN_NO_NEW_X86_SYSCALL"));''')
s=one(s,
'''R3D21 integrates into the same 512-source-witnessed GNU ld.so x86 Wine/Linux ABI bootstrap: genuine isolated native worker TID via set_tid_address(218) registered at owned guest pointer, getpid/gettid, guest robust-list address-only, rseq explicitly -ENOSYS, app UID/GID, plus R3D20 FEX guest FS/GS TLS and R3D19 libc ELF mappings. Never passes guest pointers to host set_tid_address. Guest clone, robust exit futex wake, complete Linux VFS and signals, full Wine or Win64 PE boot remain unproven.''',
'''R3D22 preserves the same unified 512-source-witnessed R3D19-R3D21 guest Linux/Wine loader, now diagnosing a post-rseq -ENOSYS FEX ExecuteThread return without a twentieth original x86 syscall. Captures postexecute x86 CPUState RIP/RAX/RSP/FS and FEX synchronous fault flags read-only; reported RIP/fault fields MAY BE STALE and do not alone establish cause. No extra syscalls are faked or forwarded and no unverified restart occurs. The 19 acknowledged calls were not Wine boot; complete Linux VFS, signals, futex and Wine/PE/DXVK/game remain unproven.''')
act.write_text(s)
print("R3D22_UNIFIED_FEX_POSTEXECUTE_GUEST_REGISTER_AND_FAULT_FLAG_TRACE_PROMOTION_PASS")
print("R3D22_NO_FALSE_WINE_BOOT_NO_GUEST_MEMORY_DEREFERENCE_NO_EXECUTE_RESTART")
