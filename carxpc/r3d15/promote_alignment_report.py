#!/usr/bin/env python3
"""R3D15 report correction and explicit patched FEXCore provenance.

Device R3D14 facts:
  three original x86 source-lock witnesses; three diagnostic responses;
  subsequent native SIGBUS BUS_ADRALN in [anon:FEXMemJIT] at LDAR X7,[X20],
  x20=0x4000000819. The R3D13 parser wrongly rejected 3==3 as inconsistent.
This patch corrects report classification. It does NOT claim 4th syscall
or Wine boot without an actual new source-authenticated witness.
"""
from pathlib import Path
import re,sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_alignment_report.py /tmp/carxpc")
app=Path(sys.argv[1])
gradle=app/"app/build.gradle"
java=app/"app/src/main/java/com/r4/carxpc"
activity=java/"R3D4ProbeActivity.java"
main=java/"MainActivity.java"
store=java/"R3D8JsonReportStore.java"
assert all(x.is_file() for x in (gradle,activity,main,store))
def one(s,old,new):
    n=s.count(old)
    assert n==1,("R3D15_SOURCE_ANCHOR_CHANGED",old[:120],n)
    return s.replace(old,new,1)
s=gradle.read_text()
s,n=re.subn(r"\bversionCode\s+42\b","versionCode 43",s)
assert n==1, "R3D15_EXPECTS_VERSION_42"
s,n=re.subn(r"versionName\s+'[^']+'","versionName '0.43-r3d15-fex-unaligned-safe-tso-diagnostic'",s)
assert n==1
gradle.write_text(s)

s=main.read_text()
s=one(s,"10 | R3D14 — فحص Batch بدون كاش GNU",
     "10 | R3D15 — إصلاح محاذاة FEX وفحص Batch")
main.write_text(s)
s=store.read_text()
s=one(s,'"CarX_PC_R3D14_Cacheless_Batch_Diagnostics_"',
    '"CarX_PC_R3D15_Alignment_Batch_Diagnostics_"')
store.write_text(s)

s=activity.read_text()
s=one(s,'''        runCacheless.setText("تشغيل 07H — الفحص المجمّع بدون كاش");''',
'''        runCacheless.setText("تشغيل 07H — Batch مع إصلاح محاذاة FEX");''')
s=one(s,'''        if(handled>=count || handled>32)''',
'''        // R3D14 bug: 3 captured + 3 handled is consistent even if native
        // thread crashes before the fourth source-locked x86 syscall.
        if(handled>count || handled>32)''')
s=one(s,
'''            report.put("schema",currentProbeMode==4 ?
                "r4.carx.r3d14.cacheless-original-ldso-syscall-batch.v1" :''',
'''            report.put("schema",currentProbeMode==4 ?
                "r4.carx.r3d15.align-safe-original-ldso-syscall-batch.v1" :''')
s=one(s,
'''            report.put("stage",currentProbeMode==4 ?
                "07H_GUEST_CACHELESS_SOURCE_LOCKED_SYSCALL_BATCH" :''',
'''            report.put("stage",currentProbeMode==4 ?
                "07H_GUEST_CACHELESS_SOURCE_LOCKED_SYSCALL_BATCH_FEX_ALIGN_FIX" :''')
s=one(s,
'''            report.put("probe_mode",currentProbeMode==4 ?
                "07H_DIAGNOSTIC_GUEST_CACHELESS_BATCH_32" :''',
'''            report.put("probe_mode",currentProbeMode==4 ?
                "07H_FEX_ALIGN_SAFE_DIAGNOSTIC_BATCH_32" :''')
s=one(s,
'''                report.put("guest_cache_optimized_lookup_disabled",true);''',
'''                report.put("guest_cache_optimized_lookup_disabled",true);
                report.put("fexcore_active_variant",
                    "R3D15_PATCHED_SOURCE_02e24ca_JIT_UNALIGNED_TSO_DIAGNOSTIC");
                report.put("fexcore_jit_unaligned_tso_policy",
                    "DMB_ISH_LDR_STR_FULL_BARRIERS_NON_RCPC_GPR_AND_MEMCOPY_MEMSET");
                report.put("fexcore_is_original_unmodified_binary",false);
                report.put("performance_measurement_valid_for_final_engine",false);''')
s=one(s,
'''            report.put("stage_07d_only_succeeds_on_source_verified_syscall",
                true);
            report.put("status",state);''',
'''            report.put("stage_07d_only_succeeds_on_source_verified_syscall",
                true);
            if(currentProbeMode==4 &&
               "CRASH_NATIVE".equals(exitState) &&
               state.equals("BATCH_INCOMPLETE_OR_CHILD_EXIT_WITHOUT_TERMINAL_MARKER")) {
                report.put("batch_terminal_classification",
                    "NATIVE_CRASH_AFTER_LAST_OBSERVED_RESPONSE");
                report.put("batch_crash_signal_from_android",
                    exitRecord.optInt("status_or_signal",-1));
                state="BATCH_NATIVE_CRASH_AFTER_BOUNDED_RESPONSES";
            }
            report.put("status",state);''')
s=one(s,
'''            report.put("evidence_limit",currentProbeMode==4 ?
                "Diagnostic-only guest virtual view suppresses /etc/ld.so.cache; existing rootfs file remains unchanged, and all x86 ld.so source-lock witnesses are independently verified. This does not prove full Linux filesystem, Wine, Windows PE, DXVK or CarX boot." :''',
'''            report.put("evidence_limit",currentProbeMode==4 ?
                "Diagnostic unaligned-safe FEX JIT full barriers, source-pinned to original FEX commit, paired with limited cacheless guest view. Original x86 GNU ld.so x86 syscalls are source-witnessed; synthetic responses do not prove full Linux, Wine startup, Windows PE, DXVK, Vulkan or gameplay. This alignment fallback is not a performance benchmark." :''')
assert "BATCH_REJECTED_RESPONSE_COUNT_INCONSISTENT" in s
assert "handled>=count" not in s
assert all(t in s for t in ["runCacheless", "BATCH_NATIVE_CRASH_AFTER_BOUNDED_RESPONSES","R3D9NativeCrashTrace.extract","saveReportToDownloads()","BATCH_HALTED_AT_FIRST_UNSUPPORTED_SYSCALL"])
activity.write_text(s)
print("R3D15_JSON_REJECT_EQUAL_COUNTS_FALSE_POSITIVE_FIXED")
print("R3D15_ORIGINAL_SOURCE_WITNESSES_AND_GUEST_CACHELESS_BATCH_PRESERVED")
print("R3D15_NATIVE_SIGBUS_VISIBLE_AS_INDEPENDENT_EXIT_CLASSIFICATION")
