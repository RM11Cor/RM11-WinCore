#!/usr/bin/env python3
"""Build a single byte-attested, side-by-side Proton 11 ARM64EC + FEXCore 2610
runtime. Never alter the legacy Wine engine, user prefix or game files.
ZIP is installable through ordinary Java ZipInputStream on Android 16.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import zipfile
import tarfile

PROTON_SHA="ed77f62ec52926b0faca7f2e9decad58865bdc8ec975c63b15903a8da35f8ae6"
FEX_SHA="e6cf7367071301b72cbb64e1b3199624ae4f6304e544f09097427c384a81d530"
SLOT="proton-11.0-2-arm64ec-fex2610-pfx1"
FEX_PATHS={
 "system32/libarm64ecfex.dll":"lib/wine/aarch64-windows/libarm64ecfex.dll",
 "system32/libwow64fex.dll":"lib/wine/aarch64-windows/libwow64fex.dll",
 "aarch64-unix/libarm64ecfex.so":"lib/wine/aarch64-unix/libarm64ecfex.so",
 "aarch64-unix/libwow64fex.so":"lib/wine/aarch64-unix/libwow64fex.so"
}
MAX_PREFIX_FILE=256*1024*1024
MAX_PREFIX_TOTAL=512*1024*1024
SIGNED={
 "libkernix_p11_loader.so":"lib/wine/aarch64-unix/wine",
 "libkernix_p11_server.so":"bin/wineserver",
 "libkernix_p11_ntdll.so":"lib/wine/aarch64-unix/ntdll.so",
 "libkernix_p11_winex11.so":"lib/wine/aarch64-unix/winex11.so",
 "libkernix_p11_win32u.so":"lib/wine/aarch64-unix/win32u.so",
 "libkernix_p11_fex64.so":"FEX:aarch64-unix/libarm64ecfex.so",
 "libkernix_p11_fex32.so":"FEX:aarch64-unix/libwow64fex.so"
}
REQUIRED=[
 "lib/wine/aarch64-windows/ntdll.dll",
 "lib/wine/aarch64-windows/wineboot.exe",
 "lib/wine/aarch64-unix/ntdll.so",
 "share/wine/wine.inf",
 "bin/wineserver",
 "lib/wine/aarch64-unix/wine",
 "lib/wine/aarch64-unix/winex11.so",
 "lib/wine/aarch64-unix/win32u.so"
]
def safe_file(base,rel):
    if not re.fullmatch(r"[A-Za-z0-9_./+\-]+",rel) or ".." in Path(rel).parts:
        raise ValueError("UNTRUSTED_RELATIVE_ENTRY")
    path=base/rel
    resolved=path.resolve(strict=True)
    if not resolved.is_relative_to(base.resolve(strict=True)):
        raise ValueError("ARCHIVE_SYMLINK_ESCAPED_ROOT:"+rel)
    if not resolved.is_file(): raise ValueError("MISSING_REQUIRED:"+rel)
    return resolved

def sha_file(p):
    h=hashlib.sha256()
    with p.open("rb") as f:
        while chunk:=f.read(1024*1024):h.update(chunk)
    return h.hexdigest()

def elf_aarch64(path):
    with path.open("rb") as f: h=f.read(20)
    return (len(h)==20 and h[:4]==b"\x7fELF"
            and h[4:6]==b"\x02\x01" and int.from_bytes(h[18:20],"little")==183)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--proton",required=True)
    p.add_argument("--fex",required=True)
    p.add_argument("--output",required=True)
    p.add_argument("--native",required=True)
    p.add_argument("--manifest",required=True)
    a=p.parse_args()
    proton=Path(a.proton).resolve(strict=True)
    fex=Path(a.fex).resolve(strict=True)
    if proton.is_symlink() or fex.is_symlink(): raise ValueError("SYMLINK_SOURCE_ROOT")
    for name in REQUIRED:safe_file(proton,name)
    for name in FEX_PATHS:safe_file(fex,name)
    all_files=[]
    for folder in ["bin","lib","share"]:
        base=proton/folder
        if not base.is_dir():raise ValueError("MISSING_PROTON_RUNTIME_FOLDER:"+folder)
        for entry in base.rglob("*"):
            if entry.is_file():
                name=entry.relative_to(proton).as_posix()
                # Archives for linking source plugins are not needed at
                # run time; retain all actual binaries and data unmodified.
                if name.endswith((".a",".la")):continue
                all_files.append((name,safe_file(proton,name)))
    for extra in ("profile.json","prefixPack.txz"):
        if (proton/extra).is_file():all_files.append((extra,safe_file(proton,extra)))
    existing={n for n,_ in all_files}
    # The FEX pair comes from ONE verified FEX 2610 unixlib archive.
    all_files=[(n,p) for n,p in all_files if n not in set(FEX_PATHS.values())]
    all_files += [(dst,safe_file(fex,src)) for src,dst in FEX_PATHS.items()]
    if len(all_files)>8000:raise ValueError("EXCESSIVE_RUNTIME_ENTRIES")
    if len({n for n,_ in all_files})!=len(all_files):raise ValueError("DUPLICATE_RUNTIME_ENTRY")
    # The upstream prefix template is an xz tar with four symlinks
    # hardcoded to com.winlator.cmod. NEVER transplant these host links.
    # Only copy byte-identical regular files; create an app-private C:
    # link in Java, with D/E/Z reserved for a later device-specific mount.
    template=proton/"prefixPack.txz"
    expected_links={
       ".wine/dosdevices/c:":"../drive_c",
       ".wine/dosdevices/d:":"/storage/emulated/0/Download",
       ".wine/dosdevices/e:":"/data/data/com.winlator.cmod/storage",
       ".wine/dosdevices/z:":"/data/user/0/com.winlator.cmod/files/imagefs/home/xuser-1/../.."
    }
    prefix_names=[]
    prefix_size=0
    with tarfile.open(template,"r:xz") as tf:
        for entry in tf.getmembers():
            if entry.name==".wine" or entry.name==".wine/":continue
            if not entry.name.startswith(".wine/"):
                raise ValueError("PROTON_PREFIX_UNKNOWN_ROOT")
            rel=entry.name[6:]
            if not rel or rel.startswith("/") or ".." in Path(rel).parts:
                raise ValueError("PROTON_PREFIX_TRAVERSAL")
            if entry.issym():
                if entry.name not in expected_links or entry.linkname!=expected_links[entry.name]:
                    raise ValueError("PROTON_PREFIX_UNKNOWN_SYMLINK")
                continue
            if entry.isdir():continue
            if not entry.isfile():raise ValueError("PROTON_PREFIX_SPECIAL_FILE")
            # AppleDouble entries (._*) are redundant Mac metadata and
            # may contain colons; they are NOT part of Wine's registry.
            if any(part.startswith("._") for part in Path(rel).parts):continue
            if "\\\\" in rel or ":" in rel or len("prefix/"+rel)>240:
                raise ValueError("PROTON_PREFIX_UNSAFE_FILENAME")
            prefix_names.append(rel)
            prefix_size+=entry.size
            if entry.size>MAX_PREFIX_FILE or prefix_size>MAX_PREFIX_TOTAL:
                raise ValueError("PROTON_PREFIX_SIZE_LIMIT")
    if not {"system.reg","user.reg","userdef.reg"}.issubset(prefix_names):
        raise ValueError("PROTON_PREFIX_MISSING_REGISTRY")
    if not any(x.startswith("drive_c/windows/system32/") for x in prefix_names):
        raise ValueError("PROTON_PREFIX_MISSING_SYSTEM32")
    if len(prefix_names)<150 or len(prefix_names)>2000:
        raise ValueError("PROTON_PREFIX_UNEXPECTED_ENTRY_COUNT")
    if len(set(prefix_names))!=len(prefix_names):
        raise ValueError("PROTON_PREFIX_DUPLICATE_ENTRY")
    output=Path(a.output)
    output.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(output,"w",zipfile.ZIP_DEFLATED,compresslevel=6,allowZip64=True) as z:
        for name,path in sorted(all_files):
            if path.stat().st_size>250*1024*1024:raise ValueError("OVERSIZED_RUNTIME_FILE")
            z.write(path,arcname="wine/"+name)
        with tarfile.open(template,"r:xz") as tf:
            for rel in sorted(prefix_names):
                entry=tf.getmember(".wine/"+rel)
                with tf.extractfile(entry) as source, z.open("prefix/"+rel,"w") as out:
                    shutil.copyfileobj(source,out,1024*1024)
    dest=Path(a.native)
    dest.mkdir(parents=True,exist_ok=True)
    natives=[]
    for apk_name,src in SIGNED.items():
        source=safe_file(fex,src[4:]) if src.startswith("FEX:") else safe_file(proton,src)
        if not elf_aarch64(source):raise ValueError("NATIVE_NOT_ELF_AARCH64:"+src)
        target=dest/apk_name
        shutil.copyfile(source,target)
        natives.append({"name":apk_name,"source":src,"sha256":sha_file(target),"bytes":target.stat().st_size})
    manifest={
      "schema":"kernix.proton-fex.bundle.v49122",
      "slot":SLOT,
      "proton_source":"The412Banner/proton-wine/build-bionic-layers-20261030-v16/proton-11.0-2-arm64ec.wcp",
      "proton_source_sha256":PROTON_SHA,
      "fex_source":"The412Banner/Nightlies/FexCore/FEXCore-2610-unix.wcp",
      "fex_source_sha256":FEX_SHA,
      "zip_name":output.name,
      "zip_sha256":sha_file(output),
      "zip_bytes":output.stat().st_size,
      "entry_count":len(all_files)+len(prefix_names),
      "prefix_entry_count":len(prefix_names),
      "prefix_template_source":"prefixPack.txz",
      "prefix_external_host_links_copied":False,
      "prefix_device_mounts_created":False,
      "signed_native":natives,
      "runtime_activation":"NOT_ACTIVATED_UNTIL_ANDROID_SIGNED_LOADER_AND_PREFIX_ISOLATION_VALIDATED",
      "legacy_game_files_modified":False,
      "legacy_prefix_modified":False
    }
    Path(a.manifest).write_text(json.dumps(manifest,indent=2)+"\n")
    print("KERNIX_PROTON_FEX_VERIFIED_PACKAGE_PASS",len(all_files),output.stat().st_size)
if __name__=="__main__":main()
