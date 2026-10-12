#!/usr/bin/env python3
"""No Android runtime claim: exercise V2.1 staging with synthetic test packages."""
from pathlib import Path
import importlib.util
import subprocess
import tempfile
import shutil
import hashlib

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('rm11wine21', ROOT/'tools/package_wine_runtime_v21.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
elf = (ROOT/'app/src/main/assets/box64_test/hello_glibc_x86_64.elf').read_bytes()
mod.validate_elf(elf)
try:
    mod.validate_elf(b'none')
except ValueError: pass
else: raise AssertionError('Invalid ELF accepted')

with tempfile.TemporaryDirectory(prefix='rm11-v21-host-') as t:
    tmp = Path(t)
    mod.DEST = tmp/'out'
    mod.V20 = tmp/'v20'
    mod.V20.mkdir()
    version='9.0~rm11-test'
    (mod.V20/'WINE64-PACKAGE-RECEIPT.txt').write_text('Version: '+version+'\n')
    (mod.V20/'LGPL-2.1.txt').write_text('TEST ONLY\n')
    exe = tmp/'exe'
    exe.write_bytes(elf)
    # A valid synthetic PE64 test header, not copyrighted Wine code.
    pe=bytearray(1024); pe[:2]=b'MZ'; pe[0x3c:0x40]=(128).to_bytes(4,'little')
    pe[128:132]=b'PE\x00\x00'; pe[132:134]=(0x8664).to_bytes(2,'little'); pe[152:154]=(0x20b).to_bytes(2,'little')
    mod.validate_pe64(pe)
    for label in ('wine64','libwine','libunwind8','liblzma5'):
        base=tmp/label
        (base/'DEBIAN').mkdir(parents=True)
        (base/'DEBIAN/control').write_text(f'Package: {label}\nVersion: {version}\nArchitecture: amd64\nMaintainer: RM11 Test\nDescription: Synthetic test assets only\n')
        rels = (mod.FILES[:2] if label=='wine64' else
                mod.FILES[2:4] if label=='libwine' else
                mod.FILES[4:6] if label=='libunwind8' else mod.FILES[6:])
        for rel in rels:
            f=base/rel;f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(pe if rel.endswith('.dll') else elf)
        (base/'usr/share/doc'/label).mkdir(parents=True)
        (base/'usr/share/doc'/label/'copyright').write_text('Synthetic test notice')
        subprocess.run(['dpkg-deb','--build',str(base),str(tmp/f'{label}.deb')],check=True,stdout=subprocess.DEVNULL)
    mod.build(tmp/'wine64.deb', tmp/'libwine.deb', tmp/'libunwind8.deb', tmp/'liblzma5.deb')
    # Verify fail-closed on mismatched packages before copying any real binaries.
    broken = tmp/'libwine-bad'
    (broken/'DEBIAN').mkdir(parents=True)
    (broken/'DEBIAN/control').write_text('Package: libwine\nVersion: 0.0-invalid\nArchitecture: amd64\nMaintainer: RM11 Test\nDescription: mismatch test\n')
    subprocess.run(['dpkg-deb','--build',str(broken),str(tmp/'libwine-bad.deb')],check=True,stdout=subprocess.DEVNULL)
    try:
        mod.build(tmp/'wine64.deb', tmp/'libwine-bad.deb', tmp/'libunwind8.deb', tmp/'liblzma5.deb')
    except ValueError as problem:
        assert 'Mismatched Wine versions' in str(problem)
    else:
        raise AssertionError('Mismatched Wine versions accepted')
    lines=(mod.DEST/'COMPONENTS.tsv').read_text().splitlines()
    for rel in mod.FILES:
        data=(mod.DEST/rel).read_bytes()
        assert any(line==rel+'\t'+hashlib.sha256(data).hexdigest()+'\t'+str(len(data)) for line in lines)
    assert len(list(mod.DEST.rglob('*.dll')))==1
    assert len(list(mod.DEST.rglob('ntdll.so')))==1
    assert (mod.DEST/'usr/lib/x86_64-linux-gnu/libunwind.so.8').is_file()
    assert (mod.DEST/'usr/lib/x86_64-linux-gnu/liblzma.so.5').is_file()
    assert (mod.DEST/'LIBUNWIND-COPYRIGHT.txt').is_file()
    assert (mod.DEST/'LIBLZMA-COPYRIGHT.txt').is_file()
    # Host-side Java tests using minimal stubs in place of Android classes.
    (tmp/'android/content/res').mkdir(parents=True)
    (tmp/'android/content/pm').mkdir(parents=True)
    (tmp/'android/os').mkdir(parents=True)
    (tmp/'com/rm11/wincore').mkdir(parents=True)
    (tmp/'android/content/Context.java').write_text('package android.content; import java.io.File; import android.content.res.AssetManager; import android.content.pm.ApplicationInfo; public class Context { public File getCacheDir(){return null;} public AssetManager getAssets(){return null;} public ApplicationInfo getApplicationInfo(){return null;} }')
    (tmp/'android/content/res/AssetManager.java').write_text('package android.content.res; import java.io.*; public class AssetManager { public InputStream open(String path) throws IOException {return null;} }')
    (tmp/'android/content/pm/ApplicationInfo.java').write_text('package android.content.pm; public class ApplicationInfo {public String nativeLibraryDir;}')
    (tmp/'android/os/Build.java').write_text('package android.os; public class Build {public static String[] SUPPORTED_ABIS={"arm64-v8a"};}')
    (tmp/'com/rm11/wincore/WineRuntimeV21Test.java').write_text('''package com.rm11.wincore;
public class WineRuntimeV21Test {
  static void check(boolean b){ if(!b) throw new AssertionError(); }
  public static void main(String[] args){
    String sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    String[] names={"usr/lib/wine/wine64","usr/lib/wine/wineserver64","usr/lib/x86_64-linux-gnu/wine/x86_64-unix/ntdll.so","usr/lib/x86_64-linux-gnu/wine/x86_64-windows/ntdll.dll", "usr/lib/x86_64-linux-gnu/libunwind.so.8", "usr/lib/x86_64-linux-gnu/libunwind-x86_64.so.8", "usr/lib/x86_64-linux-gnu/liblzma.so.5"};
    StringBuilder data=new StringBuilder("Version: 9.0\\n");
    for(String n:names)data.append(n).append("\\t").append(sha).append("\\t123\\n");
    check(WineRuntimeV21.parseManifest(data.toString()).size()==7);
    try{WineRuntimeV21.parseManifest(data.substring(0,data.indexOf(names[3]))); throw new AssertionError(); }catch(IllegalArgumentException expected){}
    check(WineRuntimeV21.classify(0,false,"wine-9.0\\n").contains("[PASS WINE VERSION]"));
    check(!WineRuntimeV21.classify(0,false,"wine-9.0\\nwine: could not load ntdll.so").contains("[PASS WINE VERSION]"));
    check(WineRuntimeV21.classify(1,false,"cannot dlopen: no ntdll").contains("[DEPENDENCY BLOCKED]"));
    check(WineRuntimeV21.classify(1,false,"Error loading needed lib libunwind.so.8").contains("[DEPENDENCY BLOCKED]"));
    check(WineRuntimeV21.classify(-1,true,"").contains("[TIMEOUT]"));
    check(!WineRuntimeV21.classify(1,false,"wine-9.0").contains("[PASS WINE VERSION]"));
    System.out.println("PASS V2.1 Java Wine runtime diagnostics");
  }
}''')
    android=list(tmp.glob('android/**/*.java'))
    java=list(tmp.glob('com/**/*.java'))
    java.extend([ROOT/'app/src/main/java/com/rm11/wincore/WineLoaderV20.java',ROOT/'app/src/main/java/com/rm11/wincore/WineRuntimeV21.java'])
    subprocess.run(['javac','-encoding','UTF-8','-d',str(tmp/'outjava'),*[str(x) for x in android+java]],check=True)
    subprocess.run(['java','-cp',str(tmp/'outjava'),'com.rm11.wincore.WineRuntimeV21Test'],check=True)
print('PASS V2.1.2 package path/version/architecture/hash and Java diagnostic smoke tests')
