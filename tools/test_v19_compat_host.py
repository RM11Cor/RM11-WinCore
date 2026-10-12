#!/usr/bin/env python3
"""Mocked Java/Android ABI report tests; NOT Box64 or Android translation proof."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT/'app/src/main/java/com/rm11/wincore'
GUEST = ROOT/'app/src/main/assets/box64_test/v19_glibc_compat_x86_64.elf'

with tempfile.TemporaryDirectory(prefix='rm11-v19-host-') as tmp:
    path=Path(tmp)
    def write(name,data):
        file=path/name
        file.parent.mkdir(parents=True,exist_ok=True)
        file.write_text(data)
        return file
    stubs=[
      write('android/content/Context.java', '''package android.content;
import java.io.File;
public class Context {
 final File root; public Context(File r){root=r;}
 public android.content.pm.ApplicationInfo getApplicationInfo(){android.content.pm.ApplicationInfo a=new android.content.pm.ApplicationInfo();a.nativeLibraryDir=root.getAbsolutePath();return a;}
 public android.content.res.AssetManager getAssets(){return new android.content.res.AssetManager(root);}
 public File getCacheDir(){return root;}
}'''),
      write('android/content/pm/ApplicationInfo.java','package android.content.pm;public class ApplicationInfo{public String nativeLibraryDir;}'),
      write('android/content/res/AssetManager.java','''package android.content.res;
import java.io.*;
public class AssetManager {final File root;public AssetManager(File r){root=r;}public InputStream open(String p)throws IOException{return new FileInputStream(new File(root,p));}}'''),
      write('android/os/Build.java','package android.os;public class Build{public static String[] SUPPORTED_ABIS={"arm64-v8a"};}'),
      write('com/rm11/wincore/Test19.java','''package com.rm11.wincore;
import android.content.Context;
import java.nio.file.*;
public class Test19 {
 static void check(boolean b,String what){ if(!b)throw new AssertionError(what); }
 static void script(Path path,String program)throws Exception {
   Files.writeString(path,"#!/bin/sh\\n"+program+"\\n");path.toFile().setExecutable(true);
 }
 public static void main(String[] args)throws Exception {
   Path root=Path.of(args[0]); Context ctx=new Context(root.toFile());
   Path box=root.resolve("librm11box64.so");
   check(Box64AbiCompatibilityV19.run(ctx).contains("[NOT BUILT]"), "missing Box64 must fail");
   check(Box64AbiCompatibilityV19.containsExactLine("noise\\nRM11_V19_MEMORY_OK\\n", "RM11_V19_MEMORY_OK"),"exact match pass");
   check(!Box64AbiCompatibilityV19.containsExactLine("suffix RM11_V19_MEMORY_OK fake", "RM11_V19_MEMORY_OK"),"no substring false pass");
   script(box,"case $2 in memory) echo RM11_V19_MEMORY_OK;; file) echo RM11_V19_FILE_OK;; thread) echo RM11_V19_THREAD_OK;; dlopen) echo RM11_V19_DLOPEN_OK;; esac");
   String pass=Box64AbiCompatibilityV19.run(ctx);
   check(pass.contains("[PASS FOUR]") && pass.contains("4/4"),"4 successes: "+pass);
   script(box,"case $2 in memory) echo RM11_V19_MEMORY_OK; exit 7;; file) echo FileError;exit 8;; thread) echo RM11_V19_THREAD_OK;; dlopen) echo fake;exit 0;; esac");
   String partial=Box64AbiCompatibilityV19.run(ctx);
   check(partial.contains("1/4") && partial.contains("[PARTIAL/FAIL]") && !partial.contains("[PASS FOUR]"),"partial classification: "+partial);
   script(box,"echo 'RM11_V19_MEMORY_OK fake marker'; exit 0");
   check(Box64AbiCompatibilityV19.run(ctx).contains("0/4"),"spoofed embedded marker cannot pass");
   script(box,"echo crashing;exit 134");
   check(Box64AbiCompatibilityV19.run(ctx).contains("0/4"),"nonzero must fail");
   Path elf=root.resolve("box64_test/v19_glibc_compat_x86_64.elf");
   byte[] bytes=Files.readAllBytes(elf);bytes[18]=(byte)183;Files.write(elf,bytes);
   check(Box64AbiCompatibilityV19.run(ctx).contains("[FAIL AUDIT/EXEC]"),"bad arch must fail");
 }
}'''),
    ]
    asset=path/'box64_test/v19_glibc_compat_x86_64.elf'
    asset.parent.mkdir(parents=True,exist_ok=True)
    asset.write_bytes(GUEST.read_bytes())
    classes=path/'classes';classes.mkdir()
    subprocess.run(['javac','-encoding','UTF-8','-d',str(classes),
        *map(str,stubs),str(SRC/'ElfRuntimeInspector.java'),str(SRC/'Box64AbiCompatibilityV19.java')],check=True,timeout=25)
    subprocess.run(['java','-cp',str(classes),'com.rm11.wincore.Test19',str(path)],check=True,timeout=90)
print('PASS: V1.9 Java mock tests: missing Box64, four successes, partial, marker spoof, nonzero exit, incorrect ELF')
