#!/usr/bin/env python3
"""R3D14: keep strict R3D13 mode 07G intact, add *opt-in* cacheless 07H batch.

Device R3D13 07G report (2026-11-15): rootfs preload absence validated,
but physical ld.so.cache absence not proven; session ended at Java preflight
with no native witness. Do not conflate that with FEX failure.

GNU ld.so permits --inhibit-cache; 07H implements the equivalent *guest-only*
no-cache view for one source-verified openat("/etc/ld.so.cache") probe while
leaving actual rootfs file/symlink untouched. Never pretend this is an actual
Linux VFS or Wine runtime. The result is labeled synthetic/cacheless.

All source-locked x86 syscall witnesses, diagnostics and legacy 07D..07G
remain. The native FEX syscalls never forward to Android host kernel.
"""
from pathlib import Path
import re, sys
if len(sys.argv)!=2:
    raise SystemExit("usage: promote_cacheless_batch.py /tmp/carxpc")
app=Path(sys.argv[1]); java=app/"app/src/main/java/com/r4/carxpc"
gradle=app/"app/build.gradle"
main=java/"MainActivity.java"
native=app/"app/src/main/cpp/carx_r3d4_first_syscall.cpp"
service=java/"R3D4ProbeService.java"
activity=java/"R3D4ProbeActivity.java"
store=java/"R3D8JsonReportStore.java"
assert all(x.is_file() for x in (gradle,main,native,service,activity,store))

def one(s,old,new):
    n=s.count(old)
    assert n==1,("R3D14_SOURCE_BOUNDARY_CHANGED",old[:140],n)
    return s.replace(old,new,1)

s=gradle.read_text()
s,n=re.subn(r"\bversionCode\s+41\b","versionCode 42",s)
assert n==1,"R3D14_EXPECTS_SIGNED_R3D13_FINAL_V41"
s,n=re.subn(r"versionName\s+'[^']+'",
    "versionName '0.42-r3d14-cacheless-source-locked-batch'",s)
assert n==1
gradle.write_text(s)

s=main.read_text()
s=one(s,"10 | R3D13 — فحص استدعاءات GNU المجمّع",
    "10 | R3D14 — فحص Batch بدون كاش GNU")
main.write_text(s)

s=store.read_text()
s=one(s,'"CarX_PC_R3D13_Batch_Diagnostics_"',
        '"CarX_PC_R3D14_Cacheless_Batch_Diagnostics_"')
store.write_text(s)

s=native.read_text()
# Mode 3 remains strict, mode 4 is a clearly labeled guest VFS overlay.
s=one(s,'''    if (Mode==3) {''',
        '''    if (Mode==3 || Mode==4) {''')
s=one(s,'''     (probeMode!=0 && probeMode!=1 && probeMode!=2 && probeMode!=3))''',
        '''     (probeMode!=0 && probeMode!=1 && probeMode!=2 &&
      probeMode!=3 && probeMode!=4))''')
s=one(s,'''        carx_r3d6::note("N22_BATCH_RETURN_OPENAT_CACHE_ENOENT");
        return;''',
'''        if(Mode==4)
          carx_r3d6::note("N22_CACHELESS_GUEST_VFS_OVERLAY_ENOENT");
        carx_r3d6::note("N22_BATCH_RETURN_OPENAT_CACHE_ENOENT");
        return;''')
assert 'source_guest_path_equals(' in s
assert 'is_safe_missing_guest_cache_openat(dirfd,flags,mode)' in s
assert 'N22_CACHELESS_GUEST_VFS_OVERLAY_ENOENT' in s
assert 'carx_r3d3::make_record(' in s
assert 'context->ExecuteThread(thread)' in s
native.write_text(s)

s=service.read_text()
s=one(s,
'''if(probeMode!=0 && probeMode!=1 && probeMode!=2 && probeMode!=3){''',
'''if(probeMode!=0 && probeMode!=1 && probeMode!=2 &&
           probeMode!=3 && probeMode!=4){''')
s=one(s,'''                if(probeMode==2 || probeMode==3) {''',
        '''                if(probeMode==2 || probeMode==3 || probeMode==4) {''')
s=one(s,
'''                    if(probeMode==3) {
                        Path cache=etc.resolve("ld.so.cache");
                        if(Files.isSymbolicLink(cache) ||
                           !Files.notExists(cache,LinkOption.NOFOLLOW_LINKS)) {
                            phase("E_BATCH_CACHE_ABSENCE_NOT_PROVEN");
                            return;
                        }
                        phase("J3B_BATCH_CACHE_ABSENT_IN_GUEST_ROOTFS");
                    }''',
'''                    if(probeMode==3) {
                        // Keep original strict 07G as an independent control.
                        Path cache=etc.resolve("ld.so.cache");
                        if(Files.isSymbolicLink(cache) ||
                           !Files.notExists(cache,LinkOption.NOFOLLOW_LINKS)) {
                            phase("E_BATCH_CACHE_ABSENCE_NOT_PROVEN");
                            return;
                        }
                        phase("J3B_BATCH_CACHE_ABSENT_IN_GUEST_ROOTFS");
                    }
                    if(probeMode==4) {
                        // Do not modify/delete the physical cache or resolve
                        // symlinks. Guest-only cacheless policy requires an
                        // exact source-locked pathname in native callback.
                        Path cache=etc.resolve("ld.so.cache");
                        if(Files.isSymbolicLink(cache)) {
                            phase("J3C_CACHE_SYMLINK_PHYSICALLY_PRESENT");
                        } else if(Files.isRegularFile(cache,
                                   LinkOption.NOFOLLOW_LINKS)) {
                            phase("J3C_CACHE_REGULAR_FILE_PHYSICALLY_PRESENT");
                        } else if(Files.notExists(cache,
                                   LinkOption.NOFOLLOW_LINKS)) {
                            phase("J3C_CACHE_PHYSICALLY_ABSENT");
                        } else {
                            phase("E_R3D14_CACHE_PHYSICAL_STATE_UNDETERMINED");
                            return;
                        }
                        phase("J3B_CACHELESS_GUEST_OVERLAY_ENABLED");
                    }''')
service.write_text(s)

s=activity.read_text()
s=one(s,'''    private Button runBatch;''',
        '''    private Button runBatch;
    private Button runCacheless;''')
s=one(s,'''        layout.addView(runBatch);''',
'''        layout.addView(runBatch);
        runCacheless = new Button(this);
        runCacheless.setText("تشغيل 07H — الفحص المجمّع بدون كاش");
        layout.addView(runCacheless);''')
s=one(s,'''        runBatch.setOnClickListener(v -> startProbe(3));''',
        '''        runBatch.setOnClickListener(v -> startProbe(3));
        runCacheless.setOnClickListener(v -> startProbe(4));''')
s=one(s,'''if(probeMode!=0 && probeMode!=1 && probeMode!=2 && probeMode!=3)return;''',
        '''if(probeMode!=0 && probeMode!=1 && probeMode!=2 &&
           probeMode!=3 && probeMode!=4)return;''')
s=one(s,'''        runBatch.setEnabled(false);''',
        '''        runBatch.setEnabled(false);
        runCacheless.setEnabled(false);''')
s=s.replace("runBatch.setEnabled(true);",
            "runBatch.setEnabled(true);runCacheless.setEnabled(true);")
s=one(s,
'''            report.put("schema",currentProbeMode==3 ?''',
'''            report.put("schema",currentProbeMode==4 ?
                "r4.carx.r3d14.cacheless-original-ldso-syscall-batch.v1" :
                currentProbeMode==3 ?''')
s=one(s,
'''            report.put("stage",currentProbeMode==3 ?''',
'''            report.put("stage",currentProbeMode==4 ?
                "07H_GUEST_CACHELESS_SOURCE_LOCKED_SYSCALL_BATCH" :
                currentProbeMode==3 ?''')
s=one(s,
'''            report.put("probe_mode",currentProbeMode==3 ?''',
'''            report.put("probe_mode",currentProbeMode==4 ?
                "07H_DIAGNOSTIC_GUEST_CACHELESS_BATCH_32" :
                currentProbeMode==3 ?''')
s=one(s,'''                if (currentProbeMode!=3 &&''',
        '''                if (currentProbeMode!=3 && currentProbeMode!=4 &&''')
s=one(s,'''            if(currentProbeMode==3) {
                state=inspectBatchJournal(file,expectedNonce,report,
                    phaseArray,phaseSessionValid);
            }''',
'''            if(currentProbeMode==4) {
                report.put("guest_cache_optimized_lookup_disabled",true);
                report.put("virtual_guest_cache_policy",
                    "HIDE_ETC_LD_SO_CACHE_FOR_DIAGNOSTIC_ONLY");
                report.put("host_guest_rootfs_cache_file_mutated",false);
                report.put("no_cache_is_not_a_full_linux_filesystem",true);
                String physical="UNKNOWN";
                for(int i=0;i<phaseArray.length();++i) {
                    String phase=phaseArray.optString(i,"");
                    if(phase.equals("J3C_CACHE_SYMLINK_PHYSICALLY_PRESENT"))
                        physical="SYMLINK";
                    if(phase.equals("J3C_CACHE_REGULAR_FILE_PHYSICALLY_PRESENT"))
                        physical="REGULAR_FILE";
                    if(phase.equals("J3C_CACHE_PHYSICALLY_ABSENT"))
                        physical="ABSENT";
                }
                report.put("physical_cache_file_state",physical);
                report.put("cacheless_guest_policy_activated",
                    phaseArray.toString().contains(
                        "J3B_CACHELESS_GUEST_OVERLAY_ENABLED"));
                state=inspectBatchJournal(file,expectedNonce,report,
                    phaseArray,phaseSessionValid);
            } else if(currentProbeMode==3) {
                state=inspectBatchJournal(file,expectedNonce,report,
                    phaseArray,phaseSessionValid);
            }''')
s=one(s,'''            report.put("evidence_limit",currentProbeMode==3 ?''',
'''            report.put("evidence_limit",currentProbeMode==4 ?
                "Diagnostic-only guest virtual view suppresses /etc/ld.so.cache; existing rootfs file remains unchanged, and all x86 ld.so source-lock witnesses are independently verified. This does not prove full Linux filesystem, Wine, Windows PE, DXVK or CarX boot." :
                currentProbeMode==3 ?''')
s=one(s,
'''            headline.setText((currentProbeMode==3?"07G BATCH: ":''',
'''            headline.setText((currentProbeMode==4?"07H CACHELESS: ":
                currentProbeMode==3?"07G BATCH: ":''')
s=one(s,'''        if(!file.isFile()) return "BATCH_REJECTED_NO_WITNESS_FILE";''',
'''        if(!file.isFile()) {
            for(int i=0;i<phases.length();++i) {
                String reason=phases.optString(i,"");
                if(reason.startsWith("E_BATCH_") ||
                   reason.startsWith("E_R3D14_"))
                    return "BATCH_PREFLIGHT_OR_RUNTIME_REJECTED_"+reason;
            }
            return "BATCH_REJECTED_NO_WITNESS_FILE";
        }''')
s=one(s,
'''        if(handled>=3 && !(phases.toString().contains("J3A_R3D12_PRELOAD_ABSENT_IN_GUEST_ROOTFS") &&
                           phases.toString().contains("J3B_BATCH_CACHE_ABSENT_IN_GUEST_ROOTFS")))''',
'''        if(handled>=3 && !(phases.toString().contains("J3A_R3D12_PRELOAD_ABSENT_IN_GUEST_ROOTFS") &&
                           (phases.toString().contains("J3B_BATCH_CACHE_ABSENT_IN_GUEST_ROOTFS") ||
                            phases.toString().contains("J3B_CACHELESS_GUEST_OVERLAY_ENABLED"))))''')
# Additional provenance: all brk/access/cache responses remain exact source
# checks in native code. Every witness uses source-locked original ld.so.
for required in (
 "runCacheless","J3B_CACHELESS_GUEST_OVERLAY_ENABLED",
 "HIDE_ETC_LD_SO_CACHE_FOR_DIAGNOSTIC_ONLY",
 "BATCH_PREFLIGHT_OR_RUNTIME_REJECTED_",
 "BATCH_HALTED_AT_FIRST_UNSUPPORTED_SYSCALL",
 "R3D9NativeCrashTrace.extract","saveReportToDownloads()"):
    assert required in s,required
activity.write_text(s)
print("R3D14_CACHELESS_GUEST_OVERLAY_MODE4_SOURCE_INTEGRATION_PASS")
print("R3D14_STRICT_MODE3_RETAINED_AND_07D_07E_07F_UNCHANGED")
print("R3D14_NEVER_MUTATES_CACHE_NEVER_FORWARDS_GUEST_SYSCALLS")
