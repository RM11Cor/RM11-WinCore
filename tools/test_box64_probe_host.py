#!/usr/bin/env python3
"""Runs Java version-probe logic with stand-in Android Context and host scripts.
This does NOT test actual Box64 or Android execution; it tests output handling.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parent.parent
SRC=ROOT/'app/src/main/java/com/rm11/wincore/OfficialBox64Probe.java'
with tempfile.TemporaryDirectory(prefix='rm11-box64-java-') as td:
    base=Path(td)
    def write(name, data):
        p=base/name
        p.parent.mkdir(parents=True,exist_ok=True)
        p.write_text(data)
        return p
    app=write('android/content/pm/ApplicationInfo.java','package android.content.pm; public class ApplicationInfo {public String nativeLibraryDir;}')
    ctx=write('android/content/Context.java','package android.content; public class Context {private final String dir;public Context(String dir){this.dir=dir;}public android.content.pm.ApplicationInfo getApplicationInfo(){android.content.pm.ApplicationInfo app=new android.content.pm.ApplicationInfo();app.nativeLibraryDir=dir;return app;}}')
    os=write('android/os/Build.java','package android.os; public class Build { public static String[] SUPPORTED_ABIS={"arm64-v8a"}; }')
    test=write('ProbeHostTest.java','''import com.rm11.wincore.OfficialBox64Probe;
import android.content.Context;
import java.io.File;
import java.nio.file.Files;
public class ProbeHostTest {
    public static void main(String[] args) throws Exception {
       File dir=new File(args[0]); Context ctx=new Context(dir.getAbsolutePath());
       String a=OfficialBox64Probe.inspect(ctx);
       if(!a.contains("[NOT BUILT]")) throw new Exception("Missing binary not reported: " + a);
       File fake=new File(dir,"librm11box64.so");
       Files.writeString(fake.toPath(),"#!/bin/sh\\necho 'Box64 with Dynarec v0.4.4'\\nexit 0\\n");
       fake.setExecutable(true);
       String b=OfficialBox64Probe.inspect(ctx);
       if(!b.contains("[PASS]")) throw new Exception("Probe launch check failed: " + b);
       Files.writeString(fake.toPath(),"#!/bin/sh\\necho 'broken engine'\\nexit 1\\n");
       String c=OfficialBox64Probe.inspect(ctx);
       if(!c.contains("[FAIL]")) throw new Exception("Probe failure not reported: " + c);
    }
}''')
    out=base/'classes';out.mkdir()
    subprocess.run(['javac','-encoding','UTF-8','-d',str(out),str(app),str(ctx),str(os),str(SRC),str(test)],check=True)
    subprocess.run(['java','-cp',str(out),'ProbeHostTest',str(base)],check=True)
print('PASS: Box64 Java probe checks missing binary, exit code, version output and invalid result')
