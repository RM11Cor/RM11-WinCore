#!/usr/bin/env python3
"""Offline tests of the V1.4 guest runner *control logic* with fake host processes.
This is NOT a test of Android Box64 execution or guest translation.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT/'app/src/main/java/com/rm11/wincore/Box64GuestSmokeTest.java'
GUEST = ROOT/'app/src/main/assets/box64_test/hello_x86_64.elf'

with tempfile.TemporaryDirectory(prefix='rm11-guest-java-test-') as folder:
    root = Path(folder)
    def write(rel, data):
        p=root/rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(data, encoding='utf-8')
        return p
    context = write('android/content/Context.java','''package android.content;
import java.io.File;
public class Context {
    private final File base;
    public Context(File base){this.base=base;}
    public android.content.pm.ApplicationInfo getApplicationInfo(){android.content.pm.ApplicationInfo info=new android.content.pm.ApplicationInfo(); info.nativeLibraryDir=base.getAbsolutePath(); return info;}
    public android.content.res.AssetManager getAssets(){return new android.content.res.AssetManager(base);}
    public File getCacheDir(){return base;}
}''')
    asset=write('android/content/res/AssetManager.java','''package android.content.res;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
public class AssetManager {
    private final File dir;
    public AssetManager(File dir){this.dir=dir;}
    public InputStream open(String name) throws IOException {return new FileInputStream(new File(dir,name));}
}''')
    app=write('android/content/pm/ApplicationInfo.java','package android.content.pm; public class ApplicationInfo {public String nativeLibraryDir;}')
    build=write('android/os/Build.java','package android.os;public class Build {public static String[] SUPPORTED_ABIS={"arm64-v8a"};}')
    test=write('GuestRunnerHostTest.java','''import android.content.Context;
import com.rm11.wincore.Box64GuestSmokeTest;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.File;
class GuestRunnerHostTest {
    static void expect(boolean b,String s) {if(!b)throw new AssertionError(s);}
    static void mock(Path target,String script) throws Exception {
        Files.writeString(target,"#!/bin/sh\\n"+script+"\\n");
        target.toFile().setExecutable(true);
    }
    public static void main(String[] args) throws Exception {
        Path base=Path.of(args[0]); Context c=new Context(base.toFile());
        Path bin=base.resolve("librm11box64.so");
        expect(Box64GuestSmokeTest.run(c).contains("[NOT BUILT]"),"missing Box64 not reported");
        mock(bin,"if [ -x $1 ]; then echo RM11_X86_64_GUEST_EXEC_OK; else echo guest_missing_X_OK; exit 9; fi");
        // An explicit mock: only proves output parsing, not Box64 translation.
        expect(Box64GuestSmokeTest.run(c).contains("[PASS]"),"guest lacked execute bit, or success parser failed");
        mock(bin,"echo RM11_X86_64_GUEST_EXEC_OK; exit 7");
        expect(Box64GuestSmokeTest.run(c).contains("[FAIL]"),"non-zero exit falsely passed");
        mock(bin,"echo invalid; exit 0");
        expect(Box64GuestSmokeTest.run(c).contains("[FAIL]"),"missing marker falsely passed");
        Path guest=base.resolve("box64_test/hello_x86_64.elf");
        byte[] bytes=Files.readAllBytes(guest);
        bytes[18]=(byte)183;
        Files.write(guest,bytes);
        expect(Box64GuestSmokeTest.run(c).contains("Expected x86-64"),"guest architecture was not validated");
    }
}''')
    (root/'box64_test').mkdir()
    (root/'box64_test/hello_x86_64.elf').write_bytes(GUEST.read_bytes())
    out=root/'classes';out.mkdir()
    subprocess.run(['javac','-encoding','UTF-8','-d',str(out),str(context),str(asset),str(app),str(build),str(SRC),str(test)],check=True)
    subprocess.run(['java','-cp',str(out),'GuestRunnerHostTest',str(root)],check=True)
print('PASS: V1.4 Java guest runner missing binary, success/failed exit, marker, invalid architecture (MOCK, not actual Box64)')
