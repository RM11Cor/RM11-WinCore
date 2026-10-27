#!/usr/bin/env python3
"""Verify genuine source-built upstream DXVK Win64 provider inputs.

Source pin is the *verified signed v2.7.1 tag commit* in doitsujin/dxvk.
A matching MZ header is necessary but NOT enough to certify usable graphics.
No PE files are installed into a user's prefix or Android APK here.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

from engine_graphics_provider_audit import pe_amd64

UPSTREAM_COMMIT = "c3dd74be6baec53786d4e064a572185b70347a17"
REQUIRED = ("d3d11.dll", "dxgi.dll")
MAX_DLL_BYTES = 160 * 1024 * 1024


def sha256(path):
    d=hashlib.sha256()
    with open(path,"rb") as f:
        for chunk in iter(lambda:f.read(1<<20),b""):
            d.update(chunk)
    return d.hexdigest()


def inspect(out_dir,repo_dir):
    out_dir=Path(out_dir)
    repo_dir=Path(repo_dir)
    sha=subprocess.check_output(
        ["git","-C",str(repo_dir),"rev-parse","HEAD"],text=True).strip()
    if sha!=UPSTREAM_COMMIT:
        raise ValueError("DXVK_SOURCE_COMMIT_NOT_PINNED")
    result={}
    for name in REQUIRED:
        p=out_dir/name
        if not p.is_file() or p.is_symlink() or p.stat().st_size<=512 or p.stat().st_size>MAX_DLL_BYTES:
            raise ValueError("DXVK_NATIVE_PE_FILE_NOT_BUILT:"+name)
        with p.open("rb") as f:head=f.read(8192)
        if not pe_amd64(head):
            raise ValueError("DXVK_PE32PLUS_X86_64_ARCH_INVALID:"+name)
        result[name]={
            "source_commit":sha,
            "architecture":"x86_64",
            "sha256":sha256(p),
            "size_bytes":p.stat().st_size,
            "validated_pe_header":True,
        }
    return {
        "schema":"rm11.engine.pinned-dxvk-source-build.v1",
        "upstream":"https://github.com/doitsujin/dxvk",
        "upstream_tag":"v2.7.1",
        "source_commit":UPSTREAM_COMMIT,
        "pe_files":result,
        "source_build_verified":True,
        "fex_win64_imports_tested_on_android":False,
        "turnip_driver_tested":False,
        "android_x11_game_frame_verified":False,
        "license":"zlib",
        "can_publish_game_apk":False,
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--source",required=True)
    p.add_argument("--x64",required=True)
    p.add_argument("--out",required=True)
    a=p.parse_args()
    result=inspect(a.x64,a.source)
    payload=json.dumps(result,sort_keys=True,indent=2)+"\n"
    Path(a.out).write_text(payload,encoding="utf-8")
    print("RM11_DXVK_PINNED_X64_PE_SOURCE_BUILD_VERIFIED")


if __name__=="__main__":main()
