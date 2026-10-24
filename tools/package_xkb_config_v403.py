#!/usr/bin/env python3
"""Bundle X keyboard configuration for native X.Org in RM11.

Termux:X11 JNI start() returns JNI_FALSE when XKB_CONFIG_ROOT is missing.
RM11's Android sandbox has no Termux /usr, so bundle this with its license.
"""
import argparse
import hashlib
import json
import stat
import subprocess
import zipfile
from pathlib import Path

NEEDED = ["rules/evdev","keycodes/evdev","types/complete",
          "compat/complete","symbols/pc","symbols/us"]
LIMIT_FILES=9000
LIMIT_UNCOMPRESSED=75*1024*1024

def pack(args):
    root=args.root.resolve()
    assert root.is_dir(), f"missing XKB config root: {root}"
    for name in NEEDED:
        path=root/name
        assert path.is_file() and not path.is_symlink(), f"missing required XKB file {name}"
    assert args.copyright.is_file(), "xkb-data copyright notice missing"
    copyright_text=args.copyright.read_text(encoding="utf-8",errors="replace")
    assert len(copyright_text)>600, "xkb-data attribution unexpectedly short"
    entries=[]
    total=0
    for p in sorted(root.rglob("*")):
        if p.is_symlink():
            raise RuntimeError(f"xkb-data contains unsupported symlink: {p}")
        if not p.is_file():
            continue
        rel=p.relative_to(root).as_posix()
        assert not rel.startswith("/") and ".." not in Path(rel).parts
        if len(rel)>260: raise RuntimeError(f"excessively long XKB path: {rel}")
        total+=p.stat().st_size
        assert total<=LIMIT_UNCOMPRESSED, "xkb-data too large"
        entries.append((rel,p))
    assert 100<=len(entries)<=LIMIT_FILES, f"unexpected XKB files: {len(entries)}"
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(args.output,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=7) as z:
        for rel,path in entries:
            info=zipfile.ZipInfo(rel,date_time=(2020,1,1,0,0,0))
            info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=0o100644<<16
            z.writestr(info,path.read_bytes(),compress_type=zipfile.ZIP_DEFLATED,compresslevel=7)
    with zipfile.ZipFile(args.output) as z:
        for rel in NEEDED:
            assert z.read(rel)==(root/rel).read_bytes(),f"mismatched XKB file: {rel}"
        assert len(z.namelist())==len(entries), "missing or duplicate XKB entries"
    result=subprocess.run(["dpkg-query","-W","-f="+chr(36)+"{Version}","xkb-data"],
                          check=False,capture_output=True,text=True)
    manifest={
        "schema":"rm11.v403.xkb-android-bundle.v1",
        "source":"Ubuntu xkb-data distribution /usr/share/X11/xkb",
        "package_version":result.stdout.strip() if result.returncode==0 else "unknown",
        "files":len(entries),
        "uncompressed_bytes":total,
        "sha256":hashlib.sha256(args.output.read_bytes()).hexdigest(),
        "required_files":NEEDED,
        "output_asset":"assets/x11/xkb-data.zip",
        "license_asset":"assets/x11/xkb-data-copyright.txt",
        "purpose":"Native X.Org XKB_CONFIG_ROOT; no root or Termux app required",
    }
    args.metadata.parent.mkdir(parents=True,exist_ok=True)
    args.metadata.write_text(json.dumps(manifest,indent=2)+"\n")
    args.license.parent.mkdir(parents=True,exist_ok=True)
    args.license.write_text(copyright_text)
    print("RM11_V403_XKB_BUNDLE_READY",json.dumps(manifest))

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,required=True)
    p.add_argument("--copyright",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--metadata",type=Path,required=True)
    p.add_argument("--license",type=Path,required=True)
    pack(p.parse_args())
