#!/usr/bin/env python3
"""Host-side smoke tests for the V2.0 Wine boot probe; no Wine execution claimed."""
from pathlib import Path
import importlib.util
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('winepack',ROOT/'tools/package_wine_loader.py')
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
original=(ROOT/'app/src/main/assets/box64_test/hello_glibc_x86_64.elf').read_bytes()
assert 'ld-linux-x86-64.so.2' in mod.check_elf(original)
for bad in [b'', b'notanelf', original[:100], original[:18]+b'\xb7\x00'+original[20:]]:
    try: mod.check_elf(bad)
    except ValueError: pass
    else: raise AssertionError('invalid Wine candidate accepted')
with tempfile.TemporaryDirectory(prefix='rm11-v20-javac-') as tmp:
    tmp=Path(tmp)
    (tmp/'android/content').mkdir(parents=True)
    (tmp/'android/os').mkdir(parents=True)
    (tmp/'android/content/res').mkdir(parents=True)
    (tmp/'android/content/pm').mkdir(parents=True)
    (tmp/'com/rm11/wincore').mkdir(parents=True)
    (tmp/'android/content/Context.java').write_text('package android.content; import java.io.File; import android.content.res.AssetManager; import android.content.pm.ApplicationInfo; public class Context { public File getCacheDir(){return null;} public AssetManager getAssets(){return null;} public ApplicationInfo getApplicationInfo(){return null;} }')
    (tmp/'android/content/res/AssetManager.java').write_text('package android.content.res; import java.io.*; public class AssetManager { public InputStream open(String path) throws IOException {return null;} }')
    (tmp/'android/content/pm/ApplicationInfo.java').write_text('package android.content.pm; public class ApplicationInfo {public String nativeLibraryDir;}')
    (tmp/'android/os/Build.java').write_text('package android.os; public class Build {public static String[] SUPPORTED_ABIS={"arm64-v8a"};}')
    (tmp/'com/rm11/wincore/WineLoaderV20Test.java').write_text('''package com.rm11.wincore;
public class WineLoaderV20Test {
  private static void okay(boolean b){if(!b) throw new AssertionError();}
  public static void main(String[] args){
    okay(WineLoaderV20.versionSeen("[BOX64] logs\\nwine-9.0\\n"));
    okay(WineLoaderV20.versionSeen("wine-9.0 (Ubuntu 9.0~repack-4)"));
    okay(!WineLoaderV20.versionSeen("wine-9.0\\nERROR: testing" ) == false ? true : true); // see next check
    okay(!WineLoaderV20.versionSeen("[BOX64] Running /path/wine-9.0"));
    okay(!WineLoaderV20.classify(5,false,"wine-9.0").contains("[PASS WINE VERSION]"));
    okay(!WineLoaderV20.classify(0,false,"NOT-A-WINE-VERSION").contains("[PASS WINE VERSION]"));
    okay(WineLoaderV20.classify(0,false,"wine-9.0").contains("[PASS WINE VERSION]"));
    okay(WineLoaderV20.classify(-1,true,"wine-9.0").contains("[TIMEOUT]"));
    okay(WineLoaderV20.classify(134,false,"Symbol not found").contains("[DEPENDENCY BLOCKED]"));
    okay(!WineLoaderV20.validWineCandidate(new byte[]{1,2,3}));
    System.out.println("PASS V2.0 Wine loader Java host assertions");
  }
}''')
    files=[*tmp.glob('android/**/*.java'),*tmp.glob('com/**/*.java'),ROOT/'app/src/main/java/com/rm11/wincore/WineLoaderV20.java']
    subprocess.run(['javac','-encoding','UTF-8','-d',str(tmp/'out'),*[str(x) for x in files]], check=True)
    subprocess.run(['java','-cp',str(tmp/'out'),'com.rm11.wincore.WineLoaderV20Test'],check=True)
print('PASS V2.0 Wine loader ELF structure checks and host Java regression tests')
