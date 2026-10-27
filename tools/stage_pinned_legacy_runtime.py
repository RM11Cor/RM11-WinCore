#!/usr/bin/env python3
"""Stage legacy Wine runtime bytes from a SHA-pinned *published* RM11 APK.

Provides only byte-for-byte compatibility inputs for source-build integration.
Never calls the old runtime a repaired Wine/FEX/DXVK engine. No user files,
no writes to a real Android prefix, no runtime executions, no network access.
"""
import argparse
import hashlib
import json
import os
import shutil
import tempfile
import zipfile
from pathlib import Path

PINNED_SHA256 = "1f6c511e6949080e9ec41b6b08ae724cccc49d5c10491db16db9bb32371e34e8"
PINNED_FILES = {
    "lib/arm64-v8a/libwineprobe.so":
        "app/src/main/jniLibs/arm64-v8a/libwineprobe.so",
    "lib/arm64-v8a/libwineserverrm11.so":
        "app/src/main/jniLibs/arm64-v8a/libwineserverrm11.so",
    "assets/runtime/rm11-wine-stack.zip":
        "app/src/main/assets/runtime/rm11-wine-stack.zip",
}
MAX_ITEM_BYTES = 700 * 1024 * 1024


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024*1024), b""):
            h.update(block)
    return h.hexdigest()


def stage(pinned_apk, repository_root, expected_sha):
    repo=Path(repository_root).resolve()
    apk=Path(pinned_apk)
    if not expected_sha or len(expected_sha)!=64 or sha256(apk)!=expected_sha:
        raise ValueError("LEGACY_BASELINE_APK_SHA_MISMATCH")
    manifest={}
    with zipfile.ZipFile(apk) as source:
        names=source.namelist()
        for name,target in PINNED_FILES.items():
            if names.count(name)!=1:
                raise ValueError("PINNED_RUNTIME_ENTRY_MISSING_OR_DUPLICATED:"+name)
            info=source.getinfo(name)
            if info.file_size<=0 or info.file_size>MAX_ITEM_BYTES:
                raise ValueError("PINNED_RUNTIME_ENTRY_INVALID_SIZE:"+name)
            out=(repo/target).resolve()
            if not out.is_relative_to(repo):
                raise ValueError("PINNED_RUNTIME_TARGET_ESCAPES_REPOSITORY")
            if out.exists() or out.is_symlink():
                raise ValueError("PINNED_RUNTIME_SOURCE_TREE_NOT_CLEAN:"+target)
            out.parent.mkdir(parents=True, exist_ok=True)
            if out.parent.is_symlink():
                raise ValueError("PINNED_RUNTIME_TARGET_SYMLINK")
            fd,tmp=tempfile.mkstemp(prefix=".rm11-legacy-runtime-",dir=out.parent)
            written=0
            h=hashlib.sha256()
            try:
                with os.fdopen(fd,"wb") as output, source.open(name,"r") as origin:
                    for chunk in iter(lambda: origin.read(1024*1024),b""):
                        written+=len(chunk)
                        if written>MAX_ITEM_BYTES:
                            raise ValueError("PINNED_RUNTIME_DECOMPRESSION_LIMIT")
                        output.write(chunk)
                        h.update(chunk)
                if written!=info.file_size:
                    raise ValueError("PINNED_RUNTIME_TRUNCATED")
                os.replace(tmp,out)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
            manifest[name]={"sha256":h.hexdigest(),"size_bytes":written,
                            "source":"SIGNED_PINNED_RELEASE_V489","target":target}
    return {
        "schema":"rm11.engine.pinned-legacy-runtime-stage.v1",
        "baseline_apk_sha256":expected_sha,
        "pinned_runtime_components":manifest,
        "build_source_stage_only":True,
        "engine_activation":False,
        "complete_windows_game_engine":False,
        "published_apk":False,
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("baseline_apk")
    p.add_argument("repository_root")
    p.add_argument("--expected-sha256",default=PINNED_SHA256)
    p.add_argument("--out",required=True)
    args=p.parse_args()
    result=stage(args.baseline_apk,args.repository_root,args.expected_sha256)
    Path(args.out).write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("RM11_ENGINE_PINNED_LEGACY_RUNTIME_SOURCE_STAGED count="+
          str(len(result["pinned_runtime_components"])))


if __name__=="__main__":main()
