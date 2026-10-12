#!/usr/bin/env python3
"""Offline Java control-flow tests with a mock Box64 (NOT ARM64 translation)."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / 'app/src/main/java/com/rm11/wincore'
GUEST = ROOT / 'app/src/main/assets/box64_test/hello_glibc_x86_64.elf'
with tempfile.TemporaryDirectory(prefix='rm11-dynamic-host-') as d:
    root = Path(d)
    def write(relative, data):
        dest = root / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(data)
        return dest
    context = write('android/content/Context.java', '''package android.content;
import java.io.File;
public class Context {
  final File base; public Context(File b){base=b;}
  public android.content.pm.ApplicationInfo getApplicationInfo(){
    android.content.pm.ApplicationInfo i = new android.content.pm.ApplicationInfo();
    i.nativeLibraryDir=base.getAbsolutePath();return i;
  }
  public android.content.res.AssetManager getAssets(){return new android.content.res.AssetManager(base);}
  public File getCacheDir(){return base;}
}''')
    appinfo = write('android/content/pm/ApplicationInfo.java', 'package android.content.pm; public class ApplicationInfo {public String nativeLibraryDir;}')
    assetmgr = write('android/content/res/AssetManager.java', '''package android.content.res;
import java.io.*;
public class AssetManager {
  final File base; public AssetManager(File b){base=b;}
  public InputStream open(String s)throws IOException{return new FileInputStream(new File(base,s));}
}''')
    build = write('android/os/Build.java', 'package android.os; public class Build {public static String[] SUPPORTED_ABIS={"arm64-v8a"};}')
    test = write('DynamicTest.java', '''import android.content.Context;
import com.rm11.wincore.Box64DynamicGlibcTest;
import java.nio.file.*;
class DynamicTest {
    static void ck(boolean v, String s) {if(!v)throw new AssertionError(s);}
    static void mock(Path p,String s)throws Exception {Files.writeString(p,"#!/bin/sh\\n"+s+"\\n");p.toFile().setExecutable(true);}
    public static void main(String[] args)throws Exception {
        Path root=Path.of(args[0]); Context c=new Context(root.toFile());
        ck(Box64DynamicGlibcTest.run(c).contains("[NOT BUILT]"),"must report missing Box64");
        Path bin=root.resolve("librm11box64.so");
        mock(bin,"if [ -x $1 ]; then echo RM11_X86_64_GLIBC_DYNAMIC_OK; else exit 5; fi");
        String passed=Box64DynamicGlibcTest.run(c);
        ck(passed.contains("[AUDIT OK]") && passed.contains("DT_NEEDED: libc.so.6") && passed.contains("[PASS]"),"dynamic metadata or mocked success failed: " + passed);
        mock(bin,"echo missing libc.so.6; exit 7");
        ck(Box64DynamicGlibcTest.run(c).contains("[DEPENDENCY BLOCKED]"),"libc missing must not pass");
        mock(bin,"echo RM11_X86_64_GLIBC_DYNAMIC_OK; exit 9");
        ck(Box64DynamicGlibcTest.run(c).contains("[FAIL]"),"nonzero exit must fail");
        mock(bin,"echo something_else; exit 0");
        ck(Box64DynamicGlibcTest.run(c).contains("[FAIL]"),"missing marker must fail");
        Path elf=root.resolve("box64_test/hello_glibc_x86_64.elf");
        byte[] contents=Files.readAllBytes(elf); contents[18] = (byte)183;
        Files.write(elf,contents);
        ck(Box64DynamicGlibcTest.run(c).contains("Expected a Linux x86-64"),"malformed guest must fail audit");
    }
}''')
    (root/'box64_test').mkdir()
    (root/'box64_test/hello_glibc_x86_64.elf').write_bytes(GUEST.read_bytes())
    out = root/'classes'; out.mkdir()
    subprocess.run(['javac','-encoding','UTF-8','-d',str(out),str(context),str(appinfo),
        str(assetmgr),str(build),str(SRC/'ElfRuntimeInspector.java'),
        str(SRC/'Box64DynamicGlibcTest.java'),str(test)],check=True)
    subprocess.run(['java','-cp',str(out),'DynamicTest',str(root)],check=True)
print('PASS: V1.5 dynamic Java metadata, mock success, dependency missing, nonzero exit, malformed guest (no Android Box64 run)')
