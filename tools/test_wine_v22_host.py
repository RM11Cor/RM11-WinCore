#!/usr/bin/env python3
"""Offline tests for Windows PE staging + exact Windows PE result classification.
No Android or Wine execution is claimed by these host checks.
"""
from pathlib import Path
import importlib.util
import hashlib
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('v22',ROOT/'tools/package_wine_exe_v22.py')
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
source=ROOT/'app/src/main/assets/wine_exe_v22'
pe=(source/'rm11_probe.exe').read_bytes()
from build_v22_pe_guest import audit
assert audit(pe)==(source/'PE-SHA256.txt').read_text().strip()

with tempfile.TemporaryDirectory(prefix='rm11-v22-test-') as td:
    t=Path(td);mod.OUT=t/'out';mod.OUT.mkdir()
    mod.V21=t/'wine21';mod.V21.mkdir()
    version='9.0~rm11-synthetic'
    (mod.V21/'COMPONENTS.tsv').write_text('Version: '+version+'\n')
    package=t/'libwine'
    (package/'DEBIAN').mkdir(parents=True)
    (package/'DEBIAN/control').write_text(f'Package: libwine\nVersion: {version}\nArchitecture: amd64\nMaintainer: RM11 Test\nDescription: Synthetic fixtures only\n')
    notice=package/'usr/share/doc/libwine/copyright';notice.parent.mkdir(parents=True);notice.write_text('TEST ONLY\n')
    for item in mod.REQUIRED + ('user32.dll','services.exe','explorer.exe', 'winedevice.exe','plugplay.exe','rpcss.exe') + tuple(f'rm11_fixture_{i:03}.dll' for i in range(101)):
        rel=mod.WIN+item
        dest=package/rel;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(pe)
    # A valid synthetic UNIX Wine module for the package audit.
    unix=package/mod.UNIX/'ntdll.so'
    unix.parent.mkdir(parents=True,exist_ok=True)
    unix.write_bytes((ROOT/'app/src/main/assets/box64_test/hello_glibc_x86_64.elf').read_bytes())
    # Exercise realistic Windows language-table counts: V2.2.1 failed on-device
    # because its valid component manifest exceeded 10,000 bytes.
    extra_nls = tuple(f'c_{x:04}.nls' for x in range(110))
    for name in mod.NLS_REQUIRED + ('c_932.nls',) + extra_nls:
        path=package/mod.NLS_DIR/name
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(("RM11_SYNTHETIC_NLS_"+name).encode()*10)
    wineinf=package/mod.WINE_INF;wineinf.parent.mkdir(parents=True,exist_ok=True)
    wineinf.write_bytes(b"; TEST SYNTHETIC wine.inf\n"*8)
    deb=t/'libwine.deb' 
    subprocess.run(['dpkg-deb','--build',str(package),str(deb)],check=True,stdout=subprocess.DEVNULL)
    mod.package(deb)
    manifest=(mod.OUT/'WINDOWS-COMPONENTS.tsv').read_text()
    assert 10_000 < len(manifest.encode()) <= mod.MAX_MANIFEST_BYTES, 'Test manifest must reproduce the former mobile failure'
    for item in mod.REQUIRED + ('user32.dll','services.exe','explorer.exe','winedevice.exe','plugplay.exe','rpcss.exe'):
        rel=mod.WIN+item
        assert rel+'\t'+hashlib.sha256(pe).hexdigest()+'\t'+str(len(pe)) in manifest
    assert (mod.OUT/'LIBWINE-COPYRIGHT.txt').is_file()
    for name in mod.NLS_REQUIRED+('c_932.nls',):
        rel=mod.NLS_DIR+name
        raw=(package/rel).read_bytes()
        assert rel+'\t'+hashlib.sha256(raw).hexdigest()+'\t'+str(len(raw)) in manifest
        assert (mod.OUT/rel).read_bytes()==raw
    assert (mod.OUT/mod.WINE_INF).is_file()
    # Old distro layout also needs to normalize to canonical usr/share/wine/.
    oldpackage=t/'old-layout';oldpackage.mkdir()
    oldlayout_root=oldpackage/mod.SOURCE_DATA_ROOTS[1]
    oldlayout_root.mkdir(parents=True,exist_ok=True)
    shutil_pkg=__import__('shutil')
    shutil_pkg.copytree(package/'usr/lib',oldpackage/'usr/lib')
    shutil_pkg.copytree(package/'usr/share/doc',oldpackage/'usr/share/doc')
    shutil_pkg.copytree(package/mod.NLS_DIR,oldlayout_root/'nls')
    shutil_pkg.copy2(package/mod.WINE_INF,oldlayout_root/'wine.inf')
    (oldpackage/'DEBIAN').mkdir()
    shutil_pkg.copy2(package/'DEBIAN/control',oldpackage/'DEBIAN/control')
    olddeb=t/'old-layout.deb'
    subprocess.run(['dpkg-deb','--build',str(oldpackage),str(olddeb)],check=True,stdout=subprocess.DEVNULL)
    mod.package(olddeb)
    assert (mod.OUT/mod.NLS_DIR/'locale.nls').is_file()
    assert (mod.OUT/mod.WINE_INF).is_file()
    # Fail closed if the producer cannot supply real matched NLS material.
    (package/mod.NLS_DIR/'locale.nls').unlink()
    missingdeb=t/'no-locale.deb'
    subprocess.run(['dpkg-deb','--build',str(package),str(missingdeb)],check=True,stdout=subprocess.DEVNULL)
    try:mod.package(missingdeb)
    except ValueError as e:assert 'NLS' in str(e)
    else:raise AssertionError('Missing NLS was accepted')
    (mod.V21/'COMPONENTS.tsv').write_text('Version: 0.0-mismatch\n')
    try:mod.package(deb)
    except ValueError as e:assert 'does not match' in str(e)
    else: raise AssertionError('Version mismatch was accepted')
    (mod.V21/'COMPONENTS.tsv').write_text('Version: '+version+'\n')
    bad=t/'invalid'
    (bad/'DEBIAN').mkdir(parents=True)
    (bad/'DEBIAN/control').write_text(f'Package: libwine\nVersion: {version}\nArchitecture: arm64\nMaintainer: RM11 Test\nDescription: Wrong arch\n')
    subprocess.run(['dpkg-deb','--build',str(bad),str(t/'wrong.deb')],check=True,stdout=subprocess.DEVNULL)
    try:mod.package(t/'wrong.deb')
    except ValueError as e:assert 'amd64' in str(e)
    else:raise AssertionError('Wrong Wine package architecture accepted')

    for directory in ('android/content/res','android/content/pm','android/os','com/rm11/wincore'):
        (t/directory).mkdir(parents=True,exist_ok=True)
    (t/'android/content/Context.java').write_text('package android.content;import java.io.File;import android.content.res.AssetManager;import android.content.pm.ApplicationInfo;public class Context { public File getCacheDir(){return null;} public File getFilesDir(){return null;} public AssetManager getAssets(){return null;} public ApplicationInfo getApplicationInfo(){return null;}}')
    (t/'android/content/res/AssetManager.java').write_text('package android.content.res;import java.io.*;public class AssetManager { public InputStream open(String p) throws IOException{return null;}}')
    (t/'android/content/pm/ApplicationInfo.java').write_text('package android.content.pm;public class ApplicationInfo{public String nativeLibraryDir;}')
    (t/'android/os/Build.java').write_text('package android.os;public class Build{public static String[] SUPPORTED_ABIS={"arm64-v8a"};}')
    (t/'com/rm11/wincore/WineFirstExeV22Test.java').write_text('''package com.rm11.wincore;
public class WineFirstExeV22Test {
  static void ck(boolean v){if(!v)throw new AssertionError();}
  public static void main(String[] args) throws Exception{
    String root="usr/lib/x86_64-linux-gnu/wine/x86_64-windows/";
    String sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    StringBuilder s=new StringBuilder("Version: 9.0\\n");
    for(String x:new String[]{"kernel32.dll","kernelbase.dll","wineboot.exe","services.exe","explorer.exe","winedevice.exe","plugplay.exe","rpcss.exe"})s.append(root+x).append("\\t").append(sha).append("\\t1024\\n");
    for(String x:new String[]{"locale.nls","l_intl.nls","c_1252.nls","c_437.nls"})s.append("usr/share/wine/nls/").append(x).append("\\t").append(sha).append("\\t1024\\n");
    s.append("usr/share/wine/wine.inf").append("\\t").append(sha).append("\\t1024\\n");
    ck(WineFirstExeV22.parseManifest(s.toString()).size()==13);
    byte[] manifest=java.nio.file.Files.readAllBytes(java.nio.file.Path.of(args[0]));
    ck(manifest.length>10000 && manifest.length<=WineFirstExeV22.MAX_MANIFEST_BYTES);
    byte[] read=WineFirstExeV22.readAssetBounded(new java.io.ByteArrayInputStream(manifest),"manifest",WineFirstExeV22.MAX_MANIFEST_BYTES);
    ck(java.util.Arrays.equals(manifest,read));
    ck(WineFirstExeV22.parseManifest(new String(read,java.nio.charset.StandardCharsets.UTF_8)).size()>100);
    try{WineFirstExeV22.readAssetBounded(new java.io.ByteArrayInputStream(new byte[WineFirstExeV22.MAX_MANIFEST_BYTES+1]),"manifest",WineFirstExeV22.MAX_MANIFEST_BYTES);throw new AssertionError("Oversized manifest accepted");}
    catch(IllegalArgumentException expected){ck(expected.getMessage().contains("Oversized asset"));}
    try{WineFirstExeV22.parseManifest(s.toString().replace("kernelbase.dll","../bad.dll"));throw new AssertionError();}catch(IllegalArgumentException expected){}
    try{WineFirstExeV22.parseManifest(s.toString().replace("wineboot.exe","fake.exe"));throw new AssertionError();}catch(IllegalArgumentException expected){}
    ck(WineFirstExeV22.classify(0,false,true,"").contains("[PASS WINDOWS EXE]"));
    ck(WineFirstExeV22.classify(0,false,false,"").contains("[NOT PROVEN]"));
    ck(!WineFirstExeV22.classify(0,false,false,"wine-9.0").contains("[PASS WINDOWS EXE]"));
    ck(WineFirstExeV22.classify(1,false,false,"wineserver: failed to start").contains("[BLOCKED]"));
    ck(WineFirstExeV22.classify(-1,true,true,"").contains("[TIMEOUT]"));
    ck(WineFirstExeV22.classify(134,false,false,"Pointer tag was truncated").contains("[MEMORY CRASH]"));
    ck(WineFirstExeV22.classify(134,false,false,"wineserver failed, Pointer tag was truncated").contains("[MEMORY CRASH]"));
    ck(WineFirstExeV22.classify(1,false,false,"failed to load locale.nls").contains("[NLS BLOCKED]"));
    WineFirstExeV22.BootTrace trace = new WineFirstExeV22.BootTrace();
    String part1 = "RM11_WINESERVER_BRIDGE_EN";
    String part2 = "TERED\\nwineserver: starting\\ninit_first_thread(reply_fd=7)\\n";
    trace.observe(part1.getBytes(java.nio.charset.StandardCharsets.UTF_8), part1.length());
    trace.observe(part2.getBytes(java.nio.charset.StandardCharsets.UTF_8), part2.length());
    ck(trace.summary().contains("native_bridge=YES"));
    ck(trace.summary().contains("server_start_line=OBSERVED"));
    ck(trace.summary().contains("init_first_thread_request=YES"));
    ck(trace.summary().contains("[IPC LIMIT]"));
    WineFirstExeV22.HeadTailLog bounded = new WineFirstExeV22.HeadTailLog();
    byte[] longLog = new byte[WineFirstExeV22.MAX_LOG + 32000];
    java.util.Arrays.fill(longLog, (byte)'x');
    byte[] lastMarker = "BOX64(free) SIGABRT Crash-at-end".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    System.arraycopy(lastMarker, 0, longLog, longLog.length-lastMarker.length, lastMarker.length);
    for (int i=0; i<longLog.length; i+=701) {
      int n=Math.min(701,longLog.length-i);
      bounded.append(java.util.Arrays.copyOfRange(longLog,i,i+n),n);
    }
    ck(bounded.text().contains("Crash-at-end"));
    ck(bounded.text().contains("[LOG TRUNCATED:"));
    WineFirstExeV22.HeadTailLog small = new WineFirstExeV22.HeadTailLog();
    byte[] letters="hello world".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    small.append(letters,letters.length);
    ck(small.text().equals("hello world"));
    WineFirstExeV22.HeadTailLog medium = new WineFirstExeV22.HeadTailLog();
    byte[] mid = new byte[WineFirstExeV22.MAX_LOG-100];
    java.util.Arrays.fill(mid,(byte)'b');
    medium.append(mid,mid.length);
    ck(medium.text().length()==mid.length);
    System.out.println("PASS: V2.2.5 bounded head+tail crash evidence preserves exit and both short/large logs");
    System.out.println("PASS: V2.2 Java PE smoke checks and false-positive prevention");
  }
}''')
    android=list((t/'android').rglob('*.java'))
    java=list((t/'com').rglob('*.java'))
    src=ROOT/'app/src/main/java/com/rm11/wincore'
    java.extend([src/'WineFirstExeV22.java',src/'WineRuntimeV21.java',src/'WineLoaderV20.java'])
    subprocess.run(['javac','-encoding','UTF-8','-d',str(t/'outjava'),*[str(p) for p in android+java]],check=True)
    subprocess.run(['java','-cp',str(t/'outjava'),'com.rm11.wincore.WineFirstExeV22Test',str(mod.OUT/'WINDOWS-COMPONENTS.tsv')],check=True)
print('PASS: V2.2 matched Wine Windows DLL packaging + first-party PE integrity + Java host checks')
