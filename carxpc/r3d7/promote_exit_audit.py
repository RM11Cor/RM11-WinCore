#!/usr/bin/env python3
"""R3D7: distinguish guest FEX timeout vs Android native crash vs clean return.

Apply only after R3D4 + R3D6 promotion on ephemeral /tmp/carxpc.
No original R3C25 baseline source or native witness acceptance is modified.
"""
from pathlib import Path
import re, sys

if len(sys.argv)!=2:
    raise SystemExit("usage: promote_exit_audit.py /tmp/carxpc")
app=Path(sys.argv[1])
java=app/"app/src/main/java/com/r4/carxpc"
gradle=app/"app/build.gradle"
activity=java/"R3D4ProbeActivity.java"
service=java/"R3D4ProbeService.java"
main=java/"MainActivity.java"
assert all(x.is_file() for x in (gradle,activity,service,main))

def replace_once(s,old,new):
    assert s.count(old)==1, ("R3D7_SOURCE_ANCHOR_MISMATCH",old[:100],s.count(old))
    return s.replace(old,new,1)

s=gradle.read_text()
s,n=re.subn(r"\bversionCode\s+33\b","versionCode 34",s)
assert n==1,"R3D7_EXPECTED_V33"
s,n=re.subn(r"versionName\s+'[^']+'",
    "versionName '0.34-r3d7-fex-process-exit-audit'",s)
assert n==1
gradle.write_text(s)

s=main.read_text()
s=replace_once(s,"10 | R3D6 — تشخيص مراحل Wine 07D",
    "10 | R3D7 — تشخيص تعليق أو انهيار FEX بعد N10")
main.write_text(s)

s=service.read_text()
s=replace_once(s,"import java.nio.file.Path;",
    "import java.nio.file.Path;\nimport java.util.concurrent.atomic.AtomicBoolean;")
s=replace_once(s,'''        phase("J0_SERVICE_DISPATCHED");
        new Handler(Looper.getMainLooper()).postDelayed(() ->
            Process.killProcess(Process.myPid()), TIMEOUT_MS);''',
'''        phase("J0_SERVICE_DISPATCHED");
        final AtomicBoolean completed = new AtomicBoolean(false);
        new Handler(Looper.getMainLooper()).postDelayed(() -> {
            // Only a still-running child is classified as timeout.
            if (!completed.get()) {
                phase("E_WATCHDOG_FIRED_6000MS");
                Process.killProcess(Process.myPid());
            }
        }, TIMEOUT_MS);''')
s=replace_once(s,'''            } finally {
                if (rawFd >= 0) {''',
'''            } finally {
                completed.set(true);
                phase("J10_WORKER_FINISHED_WITHOUT_VERIFIED_SYSCALL");
                stopSelf(startId);
                if (rawFd >= 0) {''')
service.write_text(s)

s=activity.read_text()
s=replace_once(s,"import android.app.Activity;",
    "import android.app.Activity;\nimport android.app.ActivityManager;\nimport android.app.ApplicationExitInfo;\nimport android.os.Build;")
s=replace_once(s,"    private long sessionNonce;",
    "    private long sessionNonce;\n    private long probeStartedAtMs;")
s=replace_once(s,'        setTitle("CarX R3D6 | FEX / Wine 07D");',
    '        setTitle("CarX R3D7 | FEX / Wine 07D");')
s=replace_once(s,"        lastReport = null;",
    "        lastReport = null;\n        probeStartedAtMs=System.currentTimeMillis();")

old='''            report.put("status",state);'''
new='''            // Android 11+ records the actual native child process death reason.
            // This information is independent of the ELF-verified syscall
            // witness; process exit alone cannot prove guest execution.
            JSONObject exitRecord = new JSONObject();
            boolean exitFound = false;
            String exitState = "NO_MATCHING_ANDROID_EXIT_RECORD";
            try {
                if (Build.VERSION.SDK_INT >= 30) {
                    ActivityManager am=(ActivityManager)
                        getSystemService(ACTIVITY_SERVICE);
                    ApplicationExitInfo matched=null;
                    if (am!=null) {
                        for (ApplicationExitInfo e :
                            am.getHistoricalProcessExitReasons(
                                getPackageName(),0,24)) {
                            if (!R3D4ProbeService.PROCESS_NAME.equals(
                                    e.getProcessName())) continue;
                            long time=e.getTimestamp();
                            if (time < probeStartedAtMs-1000L ||
                                time > System.currentTimeMillis()+1000L)
                                continue;
                            if (matched==null ||
                                time>matched.getTimestamp()) matched=e;
                        }
                    }
                    if (matched!=null) {
                        exitFound=true;
                        int code=matched.getReason();
                        exitState=describeExit(code);
                        exitRecord.put("reason_code",code);
                        exitRecord.put("reason_name",exitState);
                        exitRecord.put("status_or_signal",matched.getStatus());
                        exitRecord.put("pid",matched.getPid());
                        exitRecord.put("exit_timestamp_ms",matched.getTimestamp());
                        exitRecord.put("elapsed_ms_since_launch",
                            matched.getTimestamp()-probeStartedAtMs);
                        String desc=matched.getDescription();
                        if(desc!=null) exitRecord.put("description",
                            desc.substring(0,Math.min(desc.length(),350)));
                    }
                } else {
                    exitState="ANDROID_EXIT_HISTORY_UNSUPPORTED";
                }
            } catch (Throwable t) {
                exitState="ANDROID_EXIT_HISTORY_ERROR_"+
                    t.getClass().getSimpleName();
            }
            report.put("child_process_exit_record_found",exitFound);
            report.put("child_process_exit_history_status",exitState);
            report.put("child_process_exit_detail",exitRecord);
            report.put("stage_07d_only_succeeds_on_source_verified_syscall",
                true);
            report.put("status",state);'''
s=replace_once(s,old,new)
s=replace_once(s,'''    private void startProbe() {''',
'''    private static String describeExit(int reason) {
        switch (reason) {
            case ApplicationExitInfo.REASON_CRASH_NATIVE: return "CRASH_NATIVE";
            case ApplicationExitInfo.REASON_CRASH: return "JAVA_CRASH";
            case ApplicationExitInfo.REASON_SIGNALED: return "SIGNALED";
            case ApplicationExitInfo.REASON_EXIT_SELF: return "EXIT_SELF";
            case ApplicationExitInfo.REASON_ANR: return "ANR";
            case ApplicationExitInfo.REASON_LOW_MEMORY: return "LOW_MEMORY";
            case ApplicationExitInfo.REASON_USER_REQUESTED: return "USER_REQUESTED";
            case ApplicationExitInfo.REASON_USER_STOPPED: return "USER_STOPPED";
            case ApplicationExitInfo.REASON_INITIALIZATION_FAILURE:
                return "INITIALIZATION_FAILURE";
            default: return "OTHER_"+reason;
        }
    }

    private void startProbe() {''')
s=replace_once(s,'"r4.carx.r3d6.first-syscall-phase-trace.v1"',
    '"r4.carx.r3d7.first-syscall-child-exit-audit.v1"')
assert 'phase_events' in s and 'last_probe_phase' in s
assert 'child_process_exit_detail' in s
assert 'OBSERVED_SOURCE_LOCKED_X86_SYSCALL_IN_FEX_CALLBACK' in s
activity.write_text(s)
print("R3D7_JAVA_SOURCE_ANDROID_CHILD_EXIT_AUDIT_PATCH_PASS")
print("R3D7_SOURCE_ONLY_NOT_DEVICE_GUEST_EXECUTION")
