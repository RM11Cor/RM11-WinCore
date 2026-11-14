#!/usr/bin/env python3
"""R3C15 one-device-run multi-checkpoint original GNU x86 loader batch.
Adopts already source-pinned native FEX flow from R3C14 to eventual
sample original guest exit_group(0), with per-stage ordered evidence.
No generic syscall forwarding, no game/graphics/Wine false positives.
"""
from pathlib import Path
import re,sys
root=Path(sys.argv[1])
p=root/"app/build.gradle"
s=p.read_text()
s,n=re.subn(r"\bversionCode\s+21\b","versionCode 22",s)
assert n==1,("R3C14 versionCode21 missing",n)
s,n=re.subn(r"\bversionName\s+'[^']+'","versionName '0.22-r3c15-auto-batch'",s)
assert n==1
p.write_text(s)

p=root/"app/src/main/java/com/r4/carxpc/FexIntegrationProbe.java"
s=p.read_text()
def once(old,new):
    global s
    n=s.count(old)
    assert n==1,("source-pinned gate target mismatch",n,old)
    s=s.replace(old,new,1)

once(
'      boolean safeBoundary=g>w && setTidProved && exit==117;',
'''      boolean safeBoundary=g>w && setTidProved && exit==117;
      // Fail-closed, ordered per-stage transcript from ONE native child
      // execution. Only source-authenticated stage markers count.
      String[][] stages = new String[][] {
        {"01_robust_list273","KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_SET_ROBUST_LIST273_AFTER_TID218_GUEST_FS_PLUS_0x2e0_LEN24_SOURCE_OWNED_NO_NATIVE_FUTEX_PASS"},
        {"02_source_globdat","KERNIX_G0_REAL_ORIGINAL_LIBC_GLOB_DAT_RTLD_GLOBAL_RO_ONE_AUTHENTIC_SOURCE_ELF_GUEST_RW_GOT8_RELOCATED_TO_SOURCE_LDSO_GLOBAL_RO_PASS"},
        {"03_rseq334_enosys","KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_RSEQ334_AFTER_ROBUST273_GUEST_FS_PLUS_0x920_LEN32_SIG_53053053_NATIVE_UNSUPPORTED_ENOSYS_NO_FAKE_CPU_TLS_PASS"},
        {"04_rseq_cpu_fallback","KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_RSEQ334_ENOSYS_GLIBC_TLS_CPU_ID_REGISTRATION_FAILED_NEG2_OBSERVED_PASS"},
        {"05_libc_relro_kernel_ro","KERNIX_G0_REAL_ORIGINAL_LIBC_SOURCE_GNU_RELRO_MPROTECT10_RW_TO_RO_FOUR_4K_PAGES_PASS"},
        {"06_main_relro_kernel_ro","KERNIX_G0_ORIGINAL_FEX_GNU_MAIN_PT_GNU_RELRO_LIVE_GUEST_SYSCALL10_KERNEL_RO_CHILD_WRITE_DENIED"},
        {"07_ldso_relro_kernel_ro","KERNIX_G0_ORIGINAL_FEX_GNU_LDSO_SELF_PT_GNU_RELRO_TWO_4K_NATIVE_KERNEL_RO_CHILD_SIGSEGV_BOTH_GUEST_RAX_SUCCESS"},
        {"08_prlimit64_stack","KERNIX_G0_REAL_ORIGINAL_LIBC_PRLIMIT64_RLIMIT_STACK_NATIVE_KERNEL_GET_SOURCE_GUEST_LIBC_RX_SYSCALL_AND_OWNED_STACK_16BYTE_RESULT_PASS"},
        {"09_fstat5_stdout","KERNIX_G0_REAL_ORIGINAL_FEX_LIBC_FSTAT5_STDOUT1_SOURCE_X86_NATIVE_FSTAT_EXPLICIT_X86_STAT144_GUEST_STACK_READBACK_PASS"},
        {"10_getrandom318_bss","KERNIX_G0_REAL_FEX_SOURCE_LIBC_GETRANDOM318_ORIGINAL_BSS8_NATIVE_KERNEL_NONBLOCK_LOCAL_BUFFER_GUEST_READBACK_PASS"},
        {"11_write1_stdout45","KERNIX_G0_REAL_SOURCE_ORIGINAL_GNU_X86_MAIN_FIRST_TEXT_LIBC_WRITE1_KERNEL45_BYTES_ONLY_FROM_OWNED_BRK_HEAP_PASS"},
        {"12_exit_group231_zero","KERNIX_G0_REAL_SOURCE_ORIGINAL_X86_GNU_MAIN_STDOUT45_THEN_ORIGINAL_LIBC_EXIT_GROUP231_STATUS0_GUEST_REQUEST"}
      };
      org.json.JSONArray batchSteps = new org.json.JSONArray();
      int previous=w;
      boolean chainOrdered=setTidProved;
      int batchPassed=0;
      String firstUnreached="";
      for(int checkpoint=0;checkpoint<stages.length;++checkpoint){
        int hit=log.indexOf(stages[checkpoint][1]);
        boolean passed=chainOrdered && hit>previous;
        if(passed){ previous=hit; ++batchPassed; }
        else {
          chainOrdered=false;
          if(firstUnreached.isEmpty())firstUnreached=stages[checkpoint][0];
        }
        org.json.JSONObject step=new org.json.JSONObject();
        step.put("id",stages[checkpoint][0]);
        step.put("status",passed?"PASS":firstUnreached.equals(stages[checkpoint][0])?"STOPPED_OR_FAILED":"NOT_REACHED");
        step.put("log_index",passed?hit:-1);
        batchSteps.put(step);
      }
      boolean batchTerminal=chainOrdered && batchPassed==stages.length &&
        exit==0 && log.contains("guest_exit_status=0") &&
        log.contains("no_host_guest_exit_group_forward=1");
      String batchStopReason=batchTerminal?"COMPLETED_BOUNDED_ORIGINAL_GUEST_EXIT_ZERO":
        (g>=0?"UNSUPPORTED_ORIGINAL_GUEST_SYSCALL":
        (exit!=0?"NATIVE_CHILD_STOP_OR_FAILED":"INCOMPLETE_BOUNDED_GUEST_PROOF"));''')

once(
'      j.put("original_ldso_post_libc_close_set_tid_address_guest_clear_child_tid_verified",setTidProved);',
'''      j.put("original_ldso_post_libc_close_set_tid_address_guest_clear_child_tid_verified",setTidProved);
      j.put("auto_batch_active",true);
      j.put("auto_batch_step_results",batchSteps);
      j.put("auto_batch_steps_passed",batchPassed);
      j.put("auto_batch_steps_total",stages.length);
      j.put("auto_batch_first_failed_or_unreached_step",firstUnreached);
      j.put("auto_batch_stop_reason",batchStopReason);
      j.put("auto_batch_terminal_original_guest_exit_group0_proven",batchTerminal);
      if(g>=0) {
        int boundaryEnd=log.indexOf('\\n',g);
        j.put("auto_batch_last_unsupported_x86_syscall",log.substring(g,boundaryEnd>g?boundaryEnd:log.length()));
      }''')
once(
'''        rwProved && bssProved && closeProved && anon8kProved && setFsProved && setTidProved && safeBoundary && nextProved &&
        finished && !bad.get();''',
'''        rwProved && bssProved && closeProved && anon8kProved && setFsProved && setTidProved && batchTerminal &&
        finished && !bad.get();''')
once(
'      j.put("progress_boundary",gate?"ORIGINAL_GNU_LDSO_POST_CLOSE_SET_TID_ADDRESS_GUEST_TLS_VERIFIED_NEXT_SYSCALL_STOP":',
'      j.put("progress_boundary",gate?"ORIGINAL_GNU_GUEST_ELF_SAMPLE_BOUNDARY_EXIT_GROUP_ZERO_AFTER_12_BATCH_STAGES":')
p.write_text(s)

p=root/"app/src/main/java/com/r4/carxpc/MainActivity.java"
s=p.read_text()
for old,new in {
"المرحلة R3-C14 — تسجيل clear_child_tid داخل TLS للضيف":
"المرحلة R3-C15 — تشغيل تلقائي لاختبارات محمل GNU الأصلية",
"R3-C14 | فحص set_tid_address(218) للضيف":
"R3-C15 | تشغيل الدفعة الأصلية كاملة باختبار واحد",
"نجح تسجيل TID داخل TLS الخاص بالضيف دون نواة أندرويد؛ glibc لم تكتمل":
"وصل تنفيذ عينة ELF الأصلية إلى نهاية الدفعة؛ تشغيل CarX وWine غير مثبت"
}.items():
    assert s.count(old)==1,("R3C14 UI mismatch",old)
    s=s.replace(old,new,1)
p.write_text(s)
print("CARX_R3C15_ORIGINAL_GNU_SINGLE_RUN_12_CHECKPOINT_AUTO_BATCH_VERSION22_GATE_READY")
