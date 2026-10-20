#!/data/data/com.termux/files/usr/bin/bash
# RM11-WinCore v2.4.13: one-run Windows runtime diagnostic.
# Runs only within user's existing Termux / Ubuntu PRoot, NOT inside the Android APK.
# Does not open or modify game files, Steam installations, DRM, or GitHub secrets.
set -u
umask 077
if ! command -v proot-distro >/dev/null 2>&1; then
  echo 'ERROR: proot-distro unavailable. Existing Ubuntu environment is required.'
  exit 1
fi
REPORT_DIR="$HOME/storage/downloads"
if [ ! -d "$REPORT_DIR" ]; then REPORT_DIR="$HOME"; fi
REPORT="$REPORT_DIR/RM11-v2.4.13-Windows-10-in-1-report.txt"
echo "Writing report: $REPORT"
# Preserve both report and readable progress without altering the user's login shell.
set -o pipefail
proot-distro login ubuntu -- bash -s <<'UBUNTU_SCRIPT' 2>&1 | tee "$REPORT"
set -u
umask 077
DIR=/root/rm11-wine
WD="$DIR/rm11-diagnostic-2413"
WINE="$DIR/wine-10.0-amd64-wow64/bin/wine"
PREFIX="$DIR/prefix"
mkdir -p "$WD"
cd "$WD" || exit 2
export WINEPREFIX="$PREFIX" WINEDEBUG=-all BOX64_LOG=0
printf 'RM11-WinCore v2.4.13 Windows ten-check diagnostic\n'
printf 'Environment: PRoot Ubuntu + Box64 + Wine; not the RM11 APK sandbox\n'
printf 'Date: %s\n' "$(date -u +'%Y-%m-%d %H:%M UTC')"
printf 'Evidence: native Windows API test EXEs created for these checks; no games touched.\n\n'
if [ ! -x "$WINE" ] || ! command -v box64 >/dev/null 2>&1; then
  printf 'FATAL: expected Wine or Box64 missing; see previous successful setup.\n'
  exit 3
fi
if ! command -v x86_64-w64-mingw32-gcc-win32 >/dev/null 2>&1; then
  echo 'Installing missing PE64 compiler (Ubuntu packages)...'
  apt-get update -qq && apt-get install -y --no-install-recommends gcc-mingw-w64-x86-64-win32 || exit 4
fi
# For a genuine WOW64 test, install the i686 cross-compiler only if needed.
if ! command -v i686-w64-mingw32-gcc-win32 >/dev/null 2>&1; then
  echo 'Installing PE32 compiler for WOW64 test (Ubuntu packages)...'
  apt-get update -qq && apt-get install -y --no-install-recommends gcc-mingw-w64-i686-win32 || \
    echo 'NOTE: i686 compiler could not be installed; test 02 will be NOT_CONFIGURED.'
fi
cat > rm11_probe64.c <<'C_TEST'
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void result(int n, const char *state, const char *detail) {
    printf("RM11|%02d|%s|%s\n", n, state, detail);
    fflush(stdout);
}
static DWORD WINAPI worker(LPVOID data) {
    InterlockedIncrement((volatile LONG *)data);
    return 0;
}
static void windows_api_test(void) {
    SYSTEM_INFO info;
    LARGE_INTEGER qpc;
    GetSystemInfo(&info);
    if (info.dwNumberOfProcessors && QueryPerformanceCounter(&qpc) && GetCurrentProcessId())
        result(3,"PASS","GetSystemInfo + QueryPerformanceCounter + PID");
    else result(3,"FAIL","Windows API returned invalid values");
}
static void file_test(void) {
    const char *data="RM11_FILE_IO_OK";
    char got[64]={0};
    DWORD count=0;
    HANDLE h=CreateFileA("rm11-only-diagnostic.tmp",GENERIC_READ|GENERIC_WRITE,0,NULL,
                         CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(h==INVALID_HANDLE_VALUE){result(4,"FAIL","CreateFileA");return;}
    BOOL ok=WriteFile(h,data,(DWORD)strlen(data),&count,NULL) && count==strlen(data);
    ok=ok && SetFilePointer(h,0,NULL,FILE_BEGIN)!=INVALID_SET_FILE_POINTER;
    count=0;
    ok=ok && ReadFile(h,got,(DWORD)strlen(data),&count,NULL) && count==strlen(data)
         && strcmp(got,data)==0;
    CloseHandle(h);
    DeleteFileA("rm11-only-diagnostic.tmp");
    result(4,ok?"PASS":"FAIL",ok?"Win32 ReadFile + WriteFile + compare":"Win32 file round-trip");
}
static void process_test(void) {
    char exe[MAX_PATH];
    char cmd[2*MAX_PATH+40];
    STARTUPINFOA startup;
    PROCESS_INFORMATION proc;
    DWORD status=0;
    if (!GetModuleFileNameA(NULL,exe,sizeof(exe))) {result(5,"FAIL","GetModuleFileNameA");return;}
    snprintf(cmd,sizeof(cmd),"\"%s\" --child",exe);
    memset(&startup,0,sizeof(startup));
    memset(&proc,0,sizeof(proc));
    startup.cb=sizeof(startup);
    if (!CreateProcessA(NULL,cmd,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&startup,&proc)) {
        result(5,"FAIL","CreateProcessA");return;
    }
    DWORD wait=WaitForSingleObject(proc.hProcess,15000);
    BOOL ok=wait==WAIT_OBJECT_0 && GetExitCodeProcess(proc.hProcess,&status) && status==42;
    if(wait!=WAIT_OBJECT_0) TerminateProcess(proc.hProcess,1);
    CloseHandle(proc.hThread);
    CloseHandle(proc.hProcess);
    result(5,ok?"PASS":"FAIL",ok?"CreateProcess + child exit code 42":"child process/timeout");
}
static void thread_test(void) {
    HANDLE threads[4]={0};
    volatile LONG count=0;
    int i;
    for(i=0;i<4;i++) {
        threads[i]=CreateThread(NULL,0,worker,(LPVOID)&count,0,NULL);
        if(!threads[i])break;
    }
    DWORD wait=WAIT_FAILED;
    if(i==4) wait=WaitForMultipleObjects(4,threads,TRUE,15000);
    BOOL ok=i==4 && wait==WAIT_OBJECT_0 && count==4;
    for(int j=0;j<i;j++)CloseHandle(threads[j]);
    result(6,ok?"PASS":"FAIL",ok?"Four Windows threads synchronized":"Windows threading/synchronization");
}
static void dll_test(void) {
    HMODULE library=LoadLibraryA("kernel32.dll");
    FARPROC fn=library?GetProcAddress(library,"GetTickCount64"):NULL;
    result(7,fn?"PASS":"FAIL",fn?"LoadLibrary + GetProcAddress":"Windows DLL import");
    if(library) FreeLibrary(library);
}
static LRESULT CALLBACK window_proc(HWND hwnd,UINT msg,WPARAM w,LPARAM l) {
    return DefWindowProcA(hwnd,msg,w,l);
}
static void gui_test(void) {
    char display[256]={0};
    if(!GetEnvironmentVariableA("DISPLAY",display,sizeof(display))) {
        result(8,"NOT_CONFIGURED","No X11 DISPLAY; no window was created"); return;
    }
    WNDCLASSA wc={0};
    wc.lpfnWndProc=window_proc;
    wc.hInstance=GetModuleHandleA(NULL);
    wc.lpszClassName="RM11DiagWindowOnly";
    if(!RegisterClassA(&wc)) {result(8,"FAIL","RegisterClassA");return;}
    HWND w=CreateWindowExA(0,wc.lpszClassName,"RM11",WS_OVERLAPPEDWINDOW,0,0,240,120,
                          NULL,NULL,wc.hInstance,NULL);
    if(w){result(8,"PASS","CreateWindowExA succeeded under X11");DestroyWindow(w);}
    else result(8,"FAIL","CreateWindowExA with DISPLAY configured");
    UnregisterClassA(wc.lpszClassName,wc.hInstance);
}
int main(int argc,char **argv) {
    if(argc>1 && !strcmp(argv[1],"--child"))return 42;
    result(1,"PASS","PE32+ Windows x86-64 entry point executed");
    windows_api_test();
    file_test();
    process_test();
    thread_test();
    dll_test();
    gui_test();
    return 0;
}
C_TEST
cat > rm11_probe32.c <<'C_32'
#include <stdio.h>
int main(void) { puts("RM11_PE32_WOW64_OK"); return 0; }
C_32
if ! x86_64-w64-mingw32-gcc-win32 -O2 -Wall rm11_probe64.c -o rm11_probe64.exe; then
  printf 'FATAL: PE64 cross-compile failed; cannot run the Windows suite.\n'
  exit 5
fi
printf '\n=== Running real PE32+ Windows API checks ===\n'
# Capture Wine's output so that missing test lines can be reported as failures.
if command -v timeout >/dev/null 2>&1; then
  PE64_OUTPUT="$(timeout 90s box64 "$WINE" "$WD/rm11_probe64.exe" 2>&1)"
  PE64_RC=$?
else
  PE64_OUTPUT="$(box64 "$WINE" "$WD/rm11_probe64.exe" 2>&1)"
  PE64_RC=$?
fi
printf '%s\n' "$PE64_OUTPUT"
printf '\n=== Summary (exactly ten numbered checks) ===\n'
# Statuses are taken from the actual program output, never inferred from Wine version.
for number in 01 03 04 05 06 07 08; do
  item="$(printf '%s\n' "$PE64_OUTPUT" | tr -d '\r' | grep -E "^RM11[|]${number}[|]" | tail -n 1)"
  if [ -z "$item" ]; then
    printf '[%s/10] FAIL: no result from executable (wine exit=%s)\n' "$number" "$PE64_RC"
  else
    state="$(printf '%s' "$item" | cut -d '|' -f 3)"
    reason="$(printf '%s' "$item" | cut -d '|' -f 4-)"
    printf '[%s/10] %s — %s\n' "$number" "$state" "$reason"
  fi
done
if command -v i686-w64-mingw32-gcc-win32 >/dev/null 2>&1 && \
     i686-w64-mingw32-gcc-win32 -O2 rm11_probe32.c -o rm11_probe32.exe; then
  if command -v timeout >/dev/null 2>&1; then
    WOW_OUTPUT="$(timeout 60s box64 "$WINE" "$WD/rm11_probe32.exe" 2>&1)"
  else
    WOW_OUTPUT="$(box64 "$WINE" "$WD/rm11_probe32.exe" 2>&1)"
  fi
  if printf '%s\n' "$WOW_OUTPUT" | tr -d '\r' | grep -Fq 'RM11_PE32_WOW64_OK'; then
    printf '[02/10] PASS — PE32 Windows x86 via Wine WOW64\n'
  else
    printf '[02/10] FAIL — PE32 WOW64 test returned: %s\n' "$(printf '%s' "$WOW_OUTPUT" | tail -n 3 | tr '\n' ' ' | cut -c 1-230)"
  fi
else
  printf '[02/10] NOT_CONFIGURED — PE32 cross compiler missing\n'
fi
# Never conflate Wine's builtin D3D DLLs or the Vulkan API with real DXVK/VKD3D execution.
printf '[09/10] NOT_CONFIGURED — DXVK D3D11 native DLL installation + actual D3D11 test not completed\n'
printf '[10/10] NOT_CONFIGURED — VKD3D-Proton D3D12 native DLL installation + actual D3D12 test not completed\n'
printf '\nOVERALL: Functional proof applies only to PASS rows. No DXVK, VKD3D, or games proven.\n'
printf 'Security: no game directories, DRM, root, GitHub tokens or APK sandbox accessed.\n'
UBUNTU_SCRIPT
rc=$?
echo "Report saved to: $REPORT"
if [ "$rc" -ne 0 ]; then
  echo 'Runtime diagnostics could not finish. No GitHub source changes were made.'
  exit "$rc"
fi
if ! command -v gh >/dev/null 2>&1 || ! command -v git >/dev/null 2>&1; then
  echo 'GitHub push skipped: gh/git missing. Runtime report remains available.'
  exit 0
fi
if ! gh auth status >/dev/null 2>&1; then
  echo 'GitHub push skipped: gh not authenticated. Runtime report remains available.'
  exit 0
fi
# Isolate a fresh checkout so that previous phone source folders cannot be modified.
WORK="$HOME/rm11-v2413-direct-source"
if [ -e "$WORK" ]; then
  echo "GitHub source patch skipped: $WORK already exists. Rename it manually if you want to re-run."
  exit 0
fi
echo '[RM11] Cloning direct-source repository for the report-import bridge...'
if ! gh repo clone RM11Cor/RM11-WinCore "$WORK" -- --branch main --single-branch; then
  echo 'GitHub clone failed; diagnostic report is safe in Downloads.'
  exit 1
fi
export RM11_TARGET_REPO="$WORK"
export RM11_SOURCE_SELF="$(realpath "$0")"
if ! python - <<'PY_PATCH'
from pathlib import Path
import os,re,shutil
root=Path(os.environ['RM11_TARGET_REPO'])
assert (root/'.git').is_dir(), 'repository clone incomplete'
app=root/'app/src/main/java/com/rm11/autocore'
main=app/'MainActivity.java'
s=main.read_text(encoding='utf-8')
assert 'v2.4.12 • فحص GPU الموحّد بخمس مراحل' in s, 'unexpected MainActivity version'
assert 'private static final int PICK_TREE = 701;' in s
assert '    private TextView deviceView;' in s
assert '        shareButton = action(' in s
assert '    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {' in s
s=s.replace('v2.4.12 • فحص GPU الموحّد بخمس مراحل', 'v2.4.13 • فحص Windows Runtime الموحد — 10 مراحل',1)
s=s.replace('    private static final int PICK_TREE = 701;', '    private static final int PICK_TREE = 701;\n    private static final int PICK_RUNTIME_REPORT = 918;',1)
s=s.replace('    private TextView deviceView;', '    private TextView deviceView;\n    private TextView runtimeReportView;',1)
anchor='        shareButton = action("مشاركة تقرير الفحص");'
addition='''        Button importRuntime = action("استيراد تقرير Windows — 10 اختبارات (Termux)");
        importRuntime.setOnClickListener(v -> {
            Intent pick = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            pick.addCategory(Intent.CATEGORY_OPENABLE);
            pick.setType("text/plain");
            startActivityForResult(pick, PICK_RUNTIME_REPORT);
        });
        body.addView(importRuntime, margins(0, 0, 0, 10));
        runtimeReportView = label("لا يوجد تقرير Windows مستورد. شغّل فحص Termux مرة واحدة، ثم اختر التقرير.",
                14, 0xFFD1E0F5, false);
        runtimeReportView.setTextIsSelectable(true);
        runtimeReportView.setBackground(boxColor(0xFF19313B));
        runtimeReportView.setPadding(dp(12), dp(12), dp(12), dp(12));
        body.addView(runtimeReportView, margins(0, 0, 0, 14));

'''
assert s.count(anchor)==1
s=s.replace(anchor,addition+anchor,1)
start='''    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
'''
assert s.count(start)==1
branch='''        if (requestCode == PICK_RUNTIME_REPORT) {
            if (resultCode != RESULT_OK || data == null || data.getData() == null) return;
            try (InputStream in = getContentResolver().openInputStream(data.getData())) {
                if (in == null) throw new IllegalArgumentException("report unavailable");
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                byte[] bytes = new byte[4096];
                int n;
                while ((n = in.read(bytes)) >= 0) {
                    if (output.size() + n > 65536) throw new IllegalArgumentException("report over 64 KiB");
                    output.write(bytes, 0, n);
                }
                String source = output.toString("UTF-8");
                RuntimeReportReader.Result parsed = RuntimeReportReader.read(source);
                runtimeReportView.setText(parsed.summary + "\\n\\n" + source);
            } catch (Exception error) {
                runtimeReportView.setText("تعذر قراءة تقرير Windows: " + error.getMessage());
            }
            return;
        }
'''
s=s.replace(start,start+branch,1)
main.write_text(s,encoding='utf-8')
reader='''package com.rm11.autocore;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Parses imported Termux test evidence as untrusted text; never executes it. */
public final class RuntimeReportReader {
    private RuntimeReportReader() { }
    private static final Pattern ROW = Pattern.compile(
            "^\\\\[(\\\\d{2})/10\\\\] (PASS|FAIL|NOT_CONFIGURED) \\u2014 (.*)$");
    public static final class Result {
        public final int passed, failed, notConfigured;
        public final String summary;
        private Result(int pass, int fail, int absent, String display) {
            passed=pass; failed=fail; notConfigured=absent; summary=display;
        }
    }
    public static Result read(String source) {
        if (source == null || source.length() > 65536 || !source.contains(
                "RM11-WinCore v2.4.13 Windows ten-check diagnostic"))
            throw new IllegalArgumentException("unknown report/version");
        String[] rows = new String[10];
        int pass=0, fail=0, missing=0;
        for (String line : source.split("\\\\r?\\\\n")) {
            Matcher m = ROW.matcher(line.trim());
            if (!m.matches()) continue;
            int idx=Integer.parseInt(m.group(1));
            if (idx < 1 || idx > 10 || rows[idx-1] != null)
                throw new IllegalArgumentException("invalid or duplicate test row");
            rows[idx-1]=line.trim();
            switch(m.group(2)) {
                case "PASS": pass++; break;
                case "FAIL": fail++; break;
                default: missing++; break;
            }
        }
        if(pass+fail+missing != 10) throw new IllegalArgumentException("incomplete ten-check report");
        StringBuilder summary = new StringBuilder("RM11 Windows Runtime — تقرير من Termux\\n")
                .append("PASS: ").append(pass).append("   FAIL: ").append(fail)
                .append("   NOT_CONFIGURED: ").append(missing)
                .append("\\nهذه أدلة من Ubuntu/Termux، وليست تشغيل Wine داخل APK.\\n");
        for (String row : rows) summary.append('\\n').append(row);
        return new Result(pass,fail,missing,summary.toString());
    }
}
'''
# Fix Java regex double escaping in output source by using the intended Java literal escapes.
reader=reader.replace('\\\\[', '\\\\[').replace('\\\\d', '\\\\d')
(app/'RuntimeReportReader.java').write_text(reader,encoding='utf-8')
test='''package com.rm11.autocore;
import org.junit.Test;
import static org.junit.Assert.*;
public final class RuntimeReportReaderTest {
    @Test public void parsesEveryResultOnce() {
        StringBuilder raw=new StringBuilder("RM11-WinCore v2.4.13 Windows ten-check diagnostic\\n");
        for(int i=1;i<=10;i++) {
            raw.append(String.format(java.util.Locale.ROOT,"[%02d/10] ",i));
            raw.append(i==9||i==10?"NOT_CONFIGURED":"PASS").append(" — case\\n");
        }
        RuntimeReportReader.Result r=RuntimeReportReader.read(raw.toString());
        assertEquals(8,r.passed);
        assertEquals(0,r.failed);
        assertEquals(2,r.notConfigured);
    }
    @Test(expected=IllegalArgumentException.class) public void rejectsIncomplete() {
        RuntimeReportReader.read("RM11-WinCore v2.4.13 Windows ten-check diagnostic\\n[01/10] PASS — case");
    }
}
'''
(root/'app/src/test/java/com/rm11/autocore/RuntimeReportReaderTest.java').write_text(test,encoding='utf-8')
config=root/'app/build.gradle'
c=config.read_text();assert 'versionCode 13' in c and "versionName '2.4.12-alpha'" in c
c=c.replace('versionCode 13','versionCode 14',1).replace("versionName '2.4.12-alpha'", "versionName '2.4.13-alpha'",1)
config.write_text(c)
workflow=root/'.github/workflows/build-apk.yml'
w=workflow.read_text(); assert "versionCode='13' versionName='2.4.12-alpha'" in w
w=w.replace("versionCode='13' versionName='2.4.12-alpha'", "versionCode='14' versionName='2.4.13-alpha'",1)
w=w.replace('RM11-WinCore-v2.4.12-FIVE-STAGE-SIGNED', 'RM11-WinCore-v2.4.13-WINDOWS-REPORT-SIGNED',1)
workflow.write_text(w)
check=root/'scripts-check.py'; c=check.read_text()
c=c.replace('versionCode 13','versionCode 14').replace("versionName '2.4.12-alpha'", "versionName '2.4.13-alpha'")
c=c.replace('RM11 v2.4.12:', 'RM11 v2.4.13:').replace('RM11 AutoCore v2.4.12:', 'RM11 AutoCore v2.4.13:')
c += "\nfor path in ['app/src/main/java/com/rm11/autocore/RuntimeReportReader.java', 'app/src/test/java/com/rm11/autocore/RuntimeReportReaderTest.java']:\n    if not Path(path).is_file():\n        raise SystemExit('MISSING WINDOWS REPORT PARSER: ' + path)\n"
check.write_text(c)
(root/'README-v2.4.13.md').write_text('''# RM11-WinCore v2.4.13 — Windows Runtime Report Bridge

This Android update **imports a read-only ten-check diagnostic report**, with user consent using ACTION_OPEN_DOCUMENT.
Tests execute in the separate Ubuntu PRoot session inside Termux, not inside the APK.
No root, open TCP server, cross-app private file access, or game-file mutation is required.

- Reuses the v2.4.12 Vulkan 5-in-1 test (prior verified output).
- One Termux invocation runs isolated Wine PE64/PE32 smoke tests, Windows APIs, file IO,
  process creation, threads, DLL loading, and optional GUI test.
- DXVK D3D11 and VKD3D D3D12 remain **NOT_CONFIGURED** until separately installed and exercised;
  Wine's builtin D3D is not mislabelled DXVK.
- Importer rejects incomplete/duplicate results and files larger than 64 KiB.
- Keeps stable app ID com.rm11.autocore, increments versionCode to 14, and retains
  original GitHub Secrets and certificate SHA-256 verification.

This does not yet execute Wine inside the Android app. Later stages require a verified
sandboxed runtime bundling plan (and a genuinely executed D3D11/D3D12 smoke test).
''',encoding='utf-8')
# Install one tracked script that can be run from GitHub directly next time.
(root/'tools/rm11-v2413-windows10-termux.sh').write_bytes(Path(os.environ['RM11_SOURCE_SELF']).read_bytes())
print('v2.4.13 integration patch: OK')
PY_PATCH
then
  echo 'Aborting: code patch failed validation; nothing was pushed to GitHub.'
  exit 1
fi
cd "$WORK" || exit 1
if ! python3 scripts-check.py; then
  echo 'Aborting: preflight validation failed; nothing pushed.'
  exit 1
fi
# Keep the established signing key: the keystore never leaves GitHub Secrets.
if ! gh auth setup-git; then
  echo 'Cannot configure GitHub git credentials; patch is saved locally.'
  exit 1
fi
git config user.name RM11-WinCore
git config user.email rm11-wincore@users.noreply.github.com
git add app/build.gradle app/src/main/java/com/rm11/autocore/MainActivity.java \
        app/src/main/java/com/rm11/autocore/RuntimeReportReader.java \
        app/src/test/java/com/rm11/autocore/RuntimeReportReaderTest.java \
        .github/workflows/build-apk.yml scripts-check.py README-v2.4.13.md \
        tools/rm11-v2413-windows10-termux.sh
if ! git commit -m 'Add v2.4.13 Windows ten-check report import bridge'; then
  echo 'Nothing committed; nothing pushed.'
  exit 1
fi
if ! git push origin HEAD:main; then
  echo 'Push was rejected; previous published app and signing key were not changed.'
  exit 1
fi
printf '\n[RM11 SUCCESS] Direct-source v2.4.13 pushed. GitHub Actions will build the APK.\n'
printf 'GitHub: https://github.com/RM11Cor/RM11-WinCore/actions\n'
printf 'Termux report: %s\n' "$REPORT"
