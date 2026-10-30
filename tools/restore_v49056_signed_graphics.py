#!/usr/bin/env python3
"""Restore unchanged source-attested graphics providers from signed v4.90.56.

Use when public GitHub Actions artifact download is rate-limited (HTTP 503
egress quota). Preserve every provider SHA and activation=OFF; never invent
replacement graphics or activate a new Vulkan driver.
"""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile
from stage_engine_graphics_apk import audit_apk, NATIVE_NAMES, DXVK_NAMES

MAX_FILE=180*1024*1024
def stage(signed_apk:Path,app:Path):
    verified=audit_apk(signed_apk)
    if verified["component_count"]!=9 or verified["safe_to_release"] is not False:
        raise ValueError("SIGNED_BASELINE_GRAPHICS_INTEGRITY_UNPROVEN")
    with zipfile.ZipFile(signed_apk) as z:
        source_manifest="assets/engine/engine-bundle-manifest.json"
        mf=json.loads(z.read(source_manifest))
        outputs={
            source_manifest:app/"src/main/assets/engine/engine-bundle-manifest.json"
        }
        for name in DXVK_NAMES:
            path="assets/engine/providers/dxvk/x64/"+name
            outputs[path]=app/"src/main"/path
        for name in NATIVE_NAMES:
            path="lib/arm64-v8a/"+name
            outputs[path]=app/"src/main/jniLibs/arm64-v8a"/name
        if len(outputs)!=10:
            raise ValueError("GRAPHICS_RESTORE_SET_INCORRECT")
        for name,dst in outputs.items():
            if dst.exists() or dst.is_symlink():
                raise ValueError("GRAPHICS_RESTORE_EXISTING_PATH_REFUSED:"+name)
            info=z.getinfo(name)
            if info.file_size<100 or info.file_size>MAX_FILE or info.is_dir():
                raise ValueError("GRAPHICS_RESTORE_INVALID_ITEM:"+name)
            dst.parent.mkdir(parents=True,exist_ok=True)
            with z.open(info) as source,dst.open("xb") as output:
                dig=hashlib.sha256()
                while chunk:=source.read(1024*1024):
                    dig.update(chunk)
                    output.write(chunk)
            if name!=source_manifest:
                filename=name.rsplit("/",1)[-1]
                if name.startswith("lib/"):
                    expected=mf["native_components"][filename]["sha256"]
                else:
                    expected=mf["dxvk"]["pe_files"][filename]["sha256"]
                if dig.hexdigest()!=expected:
                    raise ValueError("GRAPHICS_RESTORE_SHA_MISMATCH:"+name)
    print("RM11_V49057_SAME_SOURCE_GRAPHICS_RESTORED_FROM_SIGNED_V49056")
    print("RM11_V49057_GRAPHICS_PROVIDER_ACTIVATION_STILL_DISABLED")


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--signed-apk",type=Path,required=True)
    p.add_argument("--app",type=Path,default=Path("app"))
    a=p.parse_args()
    stage(a.signed_apk,a.app)


if __name__=="__main__":main()
