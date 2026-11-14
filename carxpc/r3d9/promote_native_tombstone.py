#!/usr/bin/env python3
"""R3D9 crash triage: recover Android native tombstone, keep one JSON file.

Applies AFTER R3D8 source promotion only. No guest execution/ELF/FEX changes.
"""
from pathlib import Path
import re,shutil,sys
if len(sys.argv)!=2:
    raise SystemExit("usage: promote_native_tombstone.py /tmp/carxpc")
app=Path(sys.argv[1])
java=app/"app/src/main/java/com/r4/carxpc"
gradle=app/"app/build.gradle"
main=java/"MainActivity.java"
probe=java/"R3D4ProbeActivity.java"
storage=java/"R3D8JsonReportStore.java"
src=Path("carxpc/r3d9/android/R3D9NativeCrashTrace.java")
dst=java/src.name
assert all(p.is_file() for p in (gradle,main,probe,storage,src))
assert not dst.exists()
shutil.copyfile(src,dst)
def one(s,old,new):
    cnt=s.count(old)
    assert cnt==1,("R3D9_SOURCE_BOUNDARY_CHANGED",old[:130],cnt)
    return s.replace(old,new,1)

s=gradle.read_text()
s,n=re.subn(r"\bversionCode\s+35\b","versionCode 36",s)
assert n==1,"R3D9_REQUIRES_R3D8_VERSION35"
s,n=re.subn(r"versionName\s+'[^']+'",
    "versionName '0.36-r3d9-native-crash-tombstone'",s)
assert n==1
gradle.write_text(s)
s=main.read_text()
s=one(s,"10 | R3D8 — تقرير Wine 07D إلى ملف JSON",
    "10 | R3D9 — استخراج انهيار Wine/FEX إلى JSON")
main.write_text(s)

s=storage.read_text()
s=one(s,'"CarX_PC_R3D8_07D_Diagnostics_"',
        '"CarX_PC_R3D9_07D_Diagnostics_"')
storage.write_text(s)

s=probe.read_text()
s=one(s,'setTitle("CarX R3D8 | FEX / Wine 07D");',
        'setTitle("CarX R3D9 | FEX / Wine 07D");')
# This missing line explained erroneous elapsed_ms_since_launch in R3D8.
s=one(s,
'''        lastReport = null;
        savedUri = null;''',
'''        lastReport = null;
        probeStartedAtMs=System.currentTimeMillis();
        savedUri = null;''')

s=one(s,'''        fileStatus = new TextView(this);''',
'''        Button recoverPrevious = new Button(this);
        recoverPrevious.setText("استرجاع انهيار Native السابق بدون إعادة الاختبار");
        layout.addView(recoverPrevious);
        fileStatus = new TextView(this);''')
s=one(s,'''        run.setOnClickListener(v -> startProbe());''',
'''        run.setOnClickListener(v -> startProbe());
        recoverPrevious.setOnClickListener(v -> recoverPreviousNativeCrash());''')

s=one(s,'''                        if(desc!=null) exitRecord.put("description",
                            desc.substring(0,Math.min(desc.length(),350)));''',
'''                        if(desc!=null) exitRecord.put("description",
                            desc.substring(0,Math.min(desc.length(),350)));
                        if (matched.getReason() ==
                            ApplicationExitInfo.REASON_CRASH_NATIVE) {
                            report.put("native_crash_tombstone",
                                R3D9NativeCrashTrace.extract(matched));
                        }''')
s=one(s,'''            output.setText(lastReport);
            saveFile.setEnabled(true);''',
'''            output.setText(R3D9NativeCrashTrace.displayWithoutBinary(report));
            saveFile.setEnabled(true);''')
s=one(s,'"r4.carx.r3d7.first-syscall-child-exit-audit.v1"',
        '"r4.carx.r3d9.first-syscall-native-tombstone.v1"')

insert = '''
    // Reuse Android crash history from the prior R3D8 test if it survives
    // the app update. No guest process or ExecuteThread is started here.
    private void recoverPreviousNativeCrash() {
        if (running) {
            fileStatus.setText("انتظر انتهاء الفحص الحالي أولاً.");
            return;
        }
        try {
            long since=System.currentTimeMillis() - 7L*24*60*60*1000;
            ApplicationExitInfo crash=R3D9NativeCrashTrace.newest(this,since);
            if (crash==null) {
                fileStatus.setText(
                    "ماكو سجل انهيار Native سابق محفوظ بنظام أندرويد.");
                return;
            }
            JSONObject record=new JSONObject();
            record.put("schema",
                "r4.carx.r3d9.recovered-native-crash-tombstone.v1");
            record.put("stage","07D_FEX_NATIVE_CRASH_TRIAGE");
            record.put("source","ANDROID_HISTORICAL_APP_EXIT_RECORD");
            record.put("previous_session_nonce_unavailable",true);
            record.put("recovered_without_running_fex",true);
            record.put("first_guest_syscall_proven",false);
            record.put("wine_process_fully_started",false);
            record.put("status","RECOVERED_NATIVE_CRASH_RECORD_ONLY");
            record.put("process_name",crash.getProcessName());
            record.put("pid",crash.getPid());
            record.put("exit_timestamp_ms",crash.getTimestamp());
            record.put("exit_reason",crash.getReason());
            record.put("status_or_signal",crash.getStatus());
            record.put("native_crash_tombstone",
                R3D9NativeCrashTrace.extract(crash));
            sessionNonce=new SecureRandom().nextLong() & Long.MAX_VALUE;
            if(sessionNonce==0)sessionNonce=1;
            savedUri=null;
            savedFileName=null;
            lastReport=record.toString(2);
            headline.setText("R3D9: استخراج انهيار سابق | PID "+
                crash.getPid());
            output.setText(R3D9NativeCrashTrace.displayWithoutBinary(record));
            saveFile.setEnabled(true);
            shareFile.setEnabled(true);
            saveReportToDownloads();
        } catch (Throwable t) {
            fileStatus.setText("فشل استرجاع سجل الانهيار: "+
                t.getClass().getSimpleName());
        }
    }
'''
assert s.endswith("\n}\n"),"SOURCE_CLASS_FINAL_BRACE_NOT_FOUND"
s=s[:-2]+insert+"}\n"
for mark in ("native_crash_tombstone","probeStartedAtMs=System.currentTimeMillis()",
    "recoverPreviousNativeCrash","R3D9NativeCrashTrace.extract",
    "R3D9NativeCrashTrace.displayWithoutBinary","status_or_signal",
    "child_process_exit_detail","phase_events","saveReportToDownloads()",
    "OBSERVED_SOURCE_LOCKED_X86_SYSCALL_IN_FEX_CALLBACK"):
    assert mark in s,mark
probe.write_text(s)
print("R3D9_NATIVE_CRASH_PROTOBUF_RECOVERY_IN_ONE_JSON_PATCH_PASS")
print("R3D9_NO_GUEST_EXECUTION_MODIFIED_NO_FAKE_WITNESS_PASS")
