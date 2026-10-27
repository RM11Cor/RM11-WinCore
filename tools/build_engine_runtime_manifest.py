#!/usr/bin/env python3
"""Build a signed-APK-embedded vNext process/runtime identity manifest.

This is a fail-closed component-identity bridge, NOT an activator. Runtime
engine/graphics activation remains OFF until Android device proof. The
manifest is packaged by AGP and protected by the APK signature; it MUST NOT
be loaded from the writable Wine prefix, a game directory, or a ZIP upload.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

PINNED_BASELINE = "1f6c511e6949080e9ec41b6b08ae724cccc49d5c10491db16db9bb32371e34e8"
SHARED_LIBS = {
    "supervisor": ("librm11_engine_supervisor.so", "lib/arm64-v8a/librm11_engine_supervisor.so"),
    "wine_loader": ("libwineprobe.so", "lib/arm64-v8a/libwineprobe.so"),
    "wine_server": ("libwineserverrm11.so", "lib/arm64-v8a/libwineserverrm11.so"),
}
WINE_ASSET = "assets/runtime/rm11-wine-stack.zip"


def filehash(path):
    sha=hashlib.sha256()
    with Path(path).open("rb") as stream:
        for buf in iter(lambda:stream.read(1024*1024),b""):
            sha.update(buf)
    return sha.hexdigest()


def create(stage_report,supervisor_path,output):
    report=json.loads(Path(stage_report).read_text(encoding="utf-8"))
    if report.get("baseline_apk_sha256")!=PINNED_BASELINE:
        raise ValueError("ENGINE_BASELINE_NOT_PINNED")
    components=report.get("pinned_runtime_components")
    if not isinstance(components,dict):
        raise ValueError("ENGINE_LEGACY_RUNTIME_UNVERIFIED")
    file_supervisor=Path(supervisor_path)
    if file_supervisor.name!="librm11_engine_supervisor.so" or not file_supervisor.is_file():
        raise ValueError("ENGINE_SUPERVISOR_SOURCE_NOT_NDK_ELF")
    if file_supervisor.read_bytes()[:4]!=b"\x7fELF":
        raise ValueError("ENGINE_SUPERVISOR_SOURCE_NOT_ELF")
    sha_supervisor=filehash(file_supervisor)
    files={
        "supervisor":{"native_library":"librm11_engine_supervisor.so","apk_path":"lib/arm64-v8a/librm11_engine_supervisor.so","sha256":sha_supervisor},
    }
    for name,label in [("lib/arm64-v8a/libwineprobe.so","wine_loader"),
                       ("lib/arm64-v8a/libwineserverrm11.so","wine_server"),
                       (WINE_ASSET,"wine_stack")]:
        record=components.get(name)
        if not isinstance(record,dict):
            raise ValueError("ENGINE_PINNED_LEGACY_FILE_MISSING:"+name)
        sha=record.get("sha256")
        if not isinstance(sha,str) or re.fullmatch("[0-9a-f]{64}",sha) is None:
            raise ValueError("ENGINE_LEGACY_HASH_MISSING:"+name)
        files[label]={"apk_path":name,"sha256":sha}
        if label!="wine_stack":
            files[label]["native_library"]=name.split("/")[-1]
    data={
        "schema":"rm11.engine.native-manifest.v1",
        "android_package":"com.rm11.autocore",
        "arch":"arm64-v8a",
        "release_source_apk_sha256":PINNED_BASELINE,
        "components":files,
        "activation":"DISABLED_UNTIL_HARDWARE_WINE_FRAME_PROOF",
        "actual_device_execution":"UNVERIFIED",
        "dxvk_turnip_frame_proof":"UNVERIFIED",
        "legacy_wine_only":True,
        "safe_to_release_as_game_fix":False,
    }
    path=Path(output)
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(data,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    return data


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--legacy-report",required=True)
    p.add_argument("--native-supervisor",required=True)
    p.add_argument("--out",required=True)
    a=p.parse_args()
    result=create(a.legacy_report,a.native_supervisor,a.out)
    print("RM11_ENGINE_SIGNED_APK_MANIFEST_STAGED activation="+result["activation"])


if __name__=="__main__":main()
