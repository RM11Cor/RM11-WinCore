#!/usr/bin/env python3
"""Offline Java mock tests of V1.7 result handling, NOT device Box64 tests."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / 'app/src/main/java/com/rm11/wincore'
ASSETS = ROOT / 'app/src/main/assets/box64_test'

with tempfile.TemporaryDirectory(prefix='rm11-v17-host-') as td:
    p = Path(td)
    def write(path, content):
        dst = p / path
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(content)
        return dst
    stubs = [
        write('android/content/Context.java', '''package android.content;
import java.io.File;
public class Context {
  final File root; public Context(File r){root=r;}
  public android.content.pm.ApplicationInfo getApplicationInfo(){android.content.pm.ApplicationInfo a=new android.content.pm.ApplicationInfo();a.nativeLibraryDir=root.getAbsolutePath();return a;}
  public android.content.res.AssetManager getAssets(){return new android.content.res.AssetManager(root);}
  public File getCacheDir(){return root;}
}'''),
        write('android/content/pm/ApplicationInfo.java', 'package android.content.pm;public class ApplicationInfo{public String nativeLibraryDir;}'),
        write('android/content/res/AssetManager.java', '''package android.content.res;
import java.io.*;
public class AssetManager {final File root;public AssetManager(File r){root=r;}public InputStream open(String p)throws IOException{return new FileInputStream(new File(root,p));}}'''),
        write('android/os/Build.java', 'package android.os;public class Build{public static String[] SUPPORTED_ABIS={"arm64-v8a"};}'),
        write('com/rm11/wincore/Test17.java', '''package com.rm11.wincore;
import android.content.Context;
import java.nio.file.*;
public class Test17 {
  static void check(boolean b, String s){if(!b)throw new AssertionError(s);}
  static void script(Path p, String s)throws Exception{Files.writeString(p,"#!/bin/sh\\n"+s+"\\n");p.toFile().setExecutable(true);}
  public static void main(String[] args)throws Exception {
    Path root=Path.of(args[0]); Context ctx=new Context(root.toFile());
    Path box=root.resolve("librm11box64.so");
    check(Box64LibcStartupTrial.run(ctx).contains("[NOT BUILT]"), "missing Box64 is not pass");
    String gate="if grep -aq RM11_X86_64_LIBC_WRITE_OK \\"$1\\"; then ";
    script(box,gate+"echo RM11_X86_64_LIBC_WRITE_OK; exit 0; else echo 'Error: Global Symbol __libc_start_main not found'; exit 134; fi");
    check(Box64LibcStartupTrial.runV18Regression(ctx).contains("[NOT PATCHED]"), "receipt is mandatory");
    Path receipt=root.resolve("third_party/box64/RM11-STARTUP-PATCH.txt");
    Files.createDirectories(receipt.getParent());
    Files.writeString(receipt,"RM11 V1.8 trial: patched source for test\\n");
    check(Box64LibcStartupTrial.runV18Regression(ctx).contains("[STILL BROKEN]"), "unresolved libc symbol must not pass");
    String isolate=Box64LibcStartupTrial.run(ctx);
    check(isolate.contains("[ISOLATED]") && isolate.contains("Exit: 134") && isolate.contains("write@PLT"), "isolated: "+isolate);
    script(box,"echo 'Global Symbol __libc_start_main not found'; exit 134");
    check(Box64LibcStartupTrial.run(ctx).contains("[FAIL BOTH]"), "double fail");
    script(box,gate+"echo RM11_X86_64_LIBC_WRITE_OK; else echo RM11_X86_64_GLIBC_DYNAMIC_OK; fi");
    check(Box64LibcStartupTrial.run(ctx).contains("[PASS BOTH]"), "double pass");
    check(Box64LibcStartupTrial.runV18Regression(ctx).contains("[PASS CRT]"), "correct patched CRT pass");
    script(box,gate+"echo RM11_X86_64_LIBC_WRITE_OK; exit 1; else echo RM11_X86_64_GLIBC_DYNAMIC_OK; fi");
    check(Box64LibcStartupTrial.run(ctx).contains("[BASE ONLY]"), "nonzero status fails even with marker");
    check(Box64LibcStartupTrial.runV18Regression(ctx).contains("[PASS CRT]"), "normal CRT can pass despite failed no-CRT control");
    script(box,gate+"echo 'incorrect marker'; else echo RM11_X86_64_GLIBC_DYNAMIC_OK; fi");
    check(Box64LibcStartupTrial.run(ctx).contains("[BASE ONLY]"), "absent marker fails");
    Path guest=root.resolve("box64_test/no_crt_libc_x86_64.elf");
    byte[] content=Files.readAllBytes(guest);content[18]=(byte)183;Files.write(guest,content);
    check(Box64LibcStartupTrial.run(ctx).contains("[FAIL AUDIT/EXEC]"), "wrong architecture rejected");
  }
}'''),
    ]
    out = p/'classes'
    out.mkdir()
    for name in ['hello_glibc_x86_64.elf', 'no_crt_libc_x86_64.elf']:
        f = p/'box64_test'/name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes((ASSETS/name).read_bytes())
    subprocess.run(['javac', '-encoding', 'UTF-8', '-d', str(out),
                    *map(str, stubs), str(SRC/'ElfRuntimeInspector.java'),
                    str(SRC/'Box64LibcStartupTrial.java')], check=True, timeout=30)
    subprocess.run(['java', '-cp', str(out), 'com.rm11.wincore.Test17', str(p)],
                   check=True, timeout=90)
print('PASS: V1.7 host mocks (isolated, both fail, both pass, nonzero, missing marker, wrong ELF)')
