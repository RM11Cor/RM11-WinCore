#!/usr/bin/env python3
"""Mock host tests for V1.6 state transitions. NOT Android Box64 execution."""
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parent.parent
SRC=ROOT/'app/src/main/java/com/rm11/wincore'
ASSET=ROOT/'app/src/main/assets/box64_test/hello_glibc_x86_64.elf'
with tempfile.TemporaryDirectory(prefix='rm11-v16-host-') as td:
    root=Path(td)
    def write(path, data):
        p=root/path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(data)
        return p
    sources=[
        write('android/content/Context.java', '''package android.content;
import java.io.File;
public class Context {
  final File root; public Context(File r){root=r;}
  public android.content.pm.ApplicationInfo getApplicationInfo(){android.content.pm.ApplicationInfo a=new android.content.pm.ApplicationInfo();a.nativeLibraryDir=root.getAbsolutePath();return a;}
  public android.content.res.AssetManager getAssets(){return new android.content.res.AssetManager(root);}
  public File getCacheDir(){return root;}
}'''),
        write('android/content/pm/ApplicationInfo.java','package android.content.pm; public class ApplicationInfo { public String nativeLibraryDir; }'),
        write('android/content/res/AssetManager.java','''package android.content.res;
import java.io.*;
public class AssetManager {final File root;public AssetManager(File r){root=r;}public InputStream open(String p)throws IOException{return new FileInputStream(new File(root,p));}}'''),
        write('android/os/Build.java','package android.os; public class Build {public static String[] SUPPORTED_ABIS={"arm64-v8a"};}'),
        write('com/rm11/wincore/TestDiagnostic.java','''package com.rm11.wincore;
import android.content.Context;
import java.nio.file.*;
public class TestDiagnostic {
  static void ck(boolean yes,String s){if(!yes)throw new AssertionError(s);}
  static void mock(Path bin, String script)throws Exception {Files.writeString(bin,"#!/bin/sh\\n"+script+"\\n");bin.toFile().setExecutable(true);}
  public static void main(String[] args)throws Exception {
    Path root=Path.of(args[0]);Context ctx=new Context(root.toFile());
    ck(Box64DynarecDiagnostic.run(ctx).contains("[NOT BUILT]"),"no fake Box64 success");
    Path bin=root.resolve("librm11box64.so");
    mock(bin,"if [ \\"$BOX64_DYNAREC\\" = \\"0\\" ]; then echo 'Ask to run at NULL'; exit 134; fi; echo RM11_X86_64_GLIBC_DYNAMIC_OK");
    String a=Box64DynarecDiagnostic.run(ctx);
    ck(a.contains("[PASS DYNAREC ONLY]") && a.contains("[CRASH SIGNAL]") && a.contains("Exit: 134"),"on only: "+a);
    mock(bin,"if [ \\"$BOX64_DYNAREC\\" = \\"1\\" ]; then echo 'SIGABRT'; exit 134; fi; echo RM11_X86_64_GLIBC_DYNAMIC_OK");
    String b=Box64DynarecDiagnostic.run(ctx);
    ck(b.contains("[PASS INTERPRETER ONLY]") && b.contains("[CRASH SIGNAL]"),"off only: "+b);
    mock(bin,"echo RM11_X86_64_GLIBC_DYNAMIC_OK");
    ck(Box64DynarecDiagnostic.run(ctx).contains("[PASS BOTH]"),"both success");
    mock(bin,"echo 'Using native(wrapped) libc.so.6'; echo 'Ask to run at NULL'; exit 134");
    String c=Box64DynarecDiagnostic.run(ctx);
    ck(c.contains("[FAIL BOTH]") && c.contains("[CRASH SIGNAL]"),"both fail: "+c);
    mock(bin,"echo RM11_X86_64_GLIBC_DYNAMIC_OK; exit 8");
    ck(Box64DynarecDiagnostic.run(ctx).contains("[FAIL BOTH]"),"nonzero marker must fail");
    byte[] guest=Files.readAllBytes(root.resolve("box64_test/hello_glibc_x86_64.elf"));
    guest[18]=(byte)183; Files.write(root.resolve("box64_test/hello_glibc_x86_64.elf"),guest);
    ck(Box64DynarecDiagnostic.run(ctx).contains("[FAIL]"),"ELF audit rejects wrong machine");
  }
}''')
    ]
    (root/'box64_test').mkdir()
    (root/'box64_test/hello_glibc_x86_64.elf').write_bytes(ASSET.read_bytes())
    out=root/'classes';out.mkdir()
    cmd=['javac','-encoding','UTF-8','-d',str(out)]+[str(x) for x in sources]+[
        str(SRC/'ElfRuntimeInspector.java'),str(SRC/'Box64DynamicGlibcTest.java'),
        str(SRC/'Box64DynarecDiagnostic.java')]
    subprocess.run(cmd,check=True,timeout=30)
    subprocess.run(['java','-cp',str(out),'com.rm11.wincore.TestDiagnostic',str(root)],check=True,timeout=50)
print('PASS: V1.6 offline mock tests for both modes, signal, exit, marker, missing Box64, malformed ELF')
