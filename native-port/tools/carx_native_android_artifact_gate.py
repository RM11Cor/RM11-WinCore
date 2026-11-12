#!/usr/bin/env python3
"""Fail-closed native Android Unity 6000.3.8f1 source/export artifact gate.

NO CarX source or game files shipped by this repository. A Windows folder
is not a Unity source project. Valid ARM64 ELF Unity binaries alone do NOT
prove game identity, rights, gameplay, Android asset completeness or a frame.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import zipfile
from pathlib import Path
from typing import Any

SCHEMA="rm11carx.authorized-android-unity-source-and-elf-gate.v1"
UNITY_VERSION="6000.3.8f1"
MAX_ZIP_ENTRIES=100_000
MAX_ZIP_TOTAL_UNCOMPRESSED=32 * 1024**3
MAX_NATIVE_LIBRARY_BYTES=512 * 1024**2
NATIVE_LIBS=(
    "lib/arm64-v8a/libunity.so",
    "lib/arm64-v8a/libil2cpp.so",
    "lib/arm64-v8a/libmain.so",
)
SENSITIVE_PC=("GameAssembly.dll","UnityPlayer.dll","CarX Street.exe",
              "CarX Street Launcher.exe")

class GateError(Exception):
    pass

def ensure(condition:bool,reason:str)->None:
    if not condition:
        raise GateError(reason)

def norm(path:str)->str:
    return path.replace("\\","/")

def source_project(root:Path)->dict[str,Any]:
    ensure(root.is_dir() and not root.is_symlink(),"not a local Unity source folder")
    version=root/"ProjectSettings/ProjectVersion.txt"
    ensure(version.is_file() and not version.is_symlink(),
           "missing Unity ProjectSettings/ProjectVersion.txt: extracted PC files are NOT a Unity source project")
    first=version.read_text(encoding="utf-8",errors="replace")[:1024]
    found=re.search(r"(?m)^m_EditorVersion:\s*([0-9A-Za-z.]+)\s*$",first)
    ensure(found is not None,"Unity version not declared")
    ensure(found.group(1)==UNITY_VERSION,
           "Unity project version mismatch; require original matching "+UNITY_VERSION)
    gameplay=root/"Assets/CarXStreetNativePort/Gameplay"
    scenes=root/"Assets/CarXStreetNativePort/Scenes"
    ensure(gameplay.is_dir() and scenes.is_dir(),
           "missing rights-cleared Unity game source/scene integration directories")
    scripts=list(gameplay.rglob("*.cs"))
    scene_files=list(scenes.rglob("*.unity"))
    ensure(bool(scripts) and bool(scene_files),
           "source scripts and real Unity scene files must both exist")
    ensure(len(scripts)<50000 and len(scene_files)<10000,"project file listing exceeds source bounds")
    all_files=scripts+scene_files
    ensure(all(f.is_file() and not f.is_symlink() for f in all_files),
           "symlink in Unity game source evidence rejected")
    legacy_pc=root/"Assets/StreamingAssets/aa/StandaloneWindows64"
    ensure(not legacy_pc.exists(),
           "Windows64 AssetBundles cannot be relabeled as Android resources")
    return {
        "mode":"unity_editor_project",
        "original_user_input_format":"Unity ProjectSettings + C# scripts + Unity scenes",
        "editor_version":UNITY_VERSION,
        "project_source_structure_present":True,
        "gameplay_source_file_count":len(scripts),
        "unity_scene_file_count":len(scene_files),
        "correct_source_project_structure_for_export":True,
        "ownership_or_permission_proven_by_file_scan":False,
        "actual_carx_gameplay_source_identity_proven":False,
        "android_il2cpp_build_completed":False,
        "original_game_first_frame_proven":False,
    }

def arm64_elf_header(raw:bytes)->bool:
    if len(raw)<64 or raw[:4]!=b"\x7fELF":
        return False
    if raw[4]!=2 or raw[5]!=1 or raw[6]!=1: # ELF64 little endian version1
        return False
    kind,machine,elf_version=struct.unpack_from("<HHI",raw,16)
    return kind==3 and machine==183 and elf_version==1

def android_apk(apk:Path)->dict[str,Any]:
    ensure(apk.is_file() and not apk.is_symlink(),"missing signed/unsigned Android APK file")
    with zipfile.ZipFile(apk,"r") as z:
        entries=z.infolist()
        ensure(0<len(entries)<=MAX_ZIP_ENTRIES,"APK archive entries over bound")
        total=0
        by_name={}
        for info in entries:
            path=info.filename
            ensure(not path.startswith("/") and "\\" not in path and
                   ".." not in path.split("/"),
                   "unsafe APK path traversal or malformed entry")
            ensure(path not in by_name,"ambiguous duplicate APK archive member")
            by_name[path]=info
            total+=info.file_size
            ensure(total<=MAX_ZIP_TOTAL_UNCOMPRESSED,"oversized APK uncompressed contents")
            ensure(not any(path.endswith("/"+name) or path==name
                           for name in SENSITIVE_PC),
                   "Windows PE CarX game logic accidentally copied into candidate Android APK")
        ensure("AndroidManifest.xml" in by_name,
               "not an Android application package manifest")
        results={}
        for filename in NATIVE_LIBS:
            ensure(filename in by_name,"missing authentic target Unity IL2CPP ARM64 lib: "+filename)
            info=by_name[filename]
            ensure(64<=info.file_size<=MAX_NATIVE_LIBRARY_BYTES,
                   "unbounded or truncated native library: "+filename)
            with z.open(info) as f:
                prefix=f.read(64)
            ensure(arm64_elf_header(prefix),
                   "library is NOT actual Android-compatible ARM64 ELF shared object: "+filename)
            results[filename]={"ELF64_AArch64_shared_object_header":True,
                               "source_library_bytes":info.file_size}
        data_candidates=[
            filename for filename in by_name
            if filename.startswith("assets/bin/Data/") and
               filename!="assets/bin/Data/" and not filename.endswith("/")
        ]
        ensure(bool(data_candidates),
               "APK has no Unity runtime Data assets at assets/bin/Data")
        return {
            "mode":"compiled_android_candidate_apk",
            "android_arm64_unity_libraries_header_verified":True,
            "arm64_unity_native_libraries":results,
            "unity_data_file_count":len(data_candidates),
            "no_original_windows_executable_copied":True,
            "gameplay_code_identity_verified":False,
            "original_pc_game_content_compatibility_proven":False,
            "original_game_first_frame_proven":False,
            "android_signed_certificate_verified":False,
            "comment":"ELF native headers alone are not a valid CarX PC port or proof of game provenance. Verify actual Android signatures, code execution, Unity scene and controller on device.",
        }

def inspect(mode:str,input_path:Path)->dict[str,Any]:
    output={
        "schema":SCHEMA,
        "scope":"native Unity-source-to-Android build candidate evidence; never Windows binary conversion",
        "user_pc_windows_files_cannot_be_recompiled_from_dll_alone":True,
        "original_carx_pc_android_port_proven":False,
        "original_game_frame_rendered":False,
        "original_game_code_executed":False,
        "permission_and_game_identity_not_certified_by_header_scan":True,
    }
    if mode=="project":
        output.update(source_project(input_path))
    elif mode=="apk":
        output.update(android_apk(input_path))
    else:
        raise GateError("unsupported gate mode")
    return output

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode",choices=["project","apk"])
    p.add_argument("path",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    try:
        report=inspect(args.mode,args.path)
    except (GateError,OSError,ValueError,zipfile.BadZipFile) as err:
        p.exit(2,f"CARX_NATIVE_SOURCE_GATE_BLOCKED: {err}\n")
    text=json.dumps(report,ensure_ascii=False,indent=2,sort_keys=True)+"\n"
    if args.out:
        args.out.write_text(text,encoding="utf-8")
    else:
        print(text)
    return 0

if __name__=="__main__":
    raise SystemExit(main())
