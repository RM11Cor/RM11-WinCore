#!/usr/bin/env python3
"""Fail-closed independent static DXVK+Turnip *provider* audit of a source APK.

Graphics binary identity is NOT GPU/Android display evidence.
Unlike name-only DXVK checks, this requires SHA-pinned exact DLL bytes and
compatible 64-bit PE/ELF headers. Builtin Wine d3d11/dxgi are not DXVK.
The manifest is signed only once this APK is release-signed, and the issuer
has to pin the upstream DXVK/Mesa commit separately during supply-chain CI.
"""
import argparse
import hashlib
import json
import re
import struct
import zipfile
from pathlib import Path

MAX_ENTRIES=50000
MAX_MANIFEST_BYTES=32768
MAX_COMPONENT_BYTES=200*1024*1024
DXVK=("dxgi.dll","d3d11.dll")
PROVIDER_MANIFEST="assets/engine/engine-bundle-manifest.json"
DXVK_ROOT="assets/engine/providers/dxvk/x64/"
TURNIP_ROOT="lib/arm64-v8a/"
SHA64=re.compile(r"[a-f0-9]{64}\Z")
SOURCE_COMMIT=re.compile(r"[a-f0-9]{40}\Z")


def pe_amd64(blob):
    if len(blob)<512 or blob[:2]!=b"MZ":
        return False
    pe_offset=struct.unpack_from("<I",blob,0x3c)[0]
    if pe_offset<64 or pe_offset>4096 or len(blob)<pe_offset+26:
        return False
    if blob[pe_offset:pe_offset+4]!=b"PE\x00\x00":
        return False
    machine=struct.unpack_from("<H",blob,pe_offset+4)[0]
    optional=struct.unpack_from("<H",blob,pe_offset+24)[0]
    return machine==0x8664 and optional==0x20b


def elf_aarch64(blob):
    if (len(blob)<64 or blob[:4]!=b"\x7fELF"
            or blob[4]!=2 or blob[5]!=1):
        return False
    file_type,machine=struct.unpack_from("<HH",blob,16)
    return file_type==3 and machine==183


def read_component(apk,path,expected_sha):
    if not isinstance(path,str) or not isinstance(expected_sha,str):
        return False,"INVALID_METADATA"
    if SHA64.fullmatch(expected_sha) is None or path not in apk.namelist():
        return False,"ABSENT_OR_UNPINNED"
    info=apk.getinfo(path)
    if info.file_size<512 or info.file_size>MAX_COMPONENT_BYTES:
        return False,"INVALID_BINARY_SIZE"
    h=hashlib.sha256()
    head=bytearray()
    try:
        with apk.open(info) as stream:
            while block:=stream.read(1<<20):
                if len(head)<8192:
                    head.extend(block[:8192-len(head)])
                h.update(block)
    except (RuntimeError,ValueError,zipfile.BadZipFile,EOFError):
        return False,"UNREADABLE_BINARY"
    if h.hexdigest()!=expected_sha:
        return False,"HASH_MISMATCH"
    return True,bytes(head)


def inspect(apk_path):
    checks={
        "dxvk_pe_d3d11":"MISSING_PROVEN_PROVIDER",
        "dxvk_pe_dxgi":"MISSING_PROVEN_PROVIDER",
        "turnip_android_native":"MISSING_PROVEN_PROVIDER",
        "turnip_hardware_wsi":"UNVERIFIED_ON_DEVICE",
        "android_x11_guest_frame":"UNVERIFIED_ON_DEVICE",
        "fex_dxvk_actual_load":"UNVERIFIED_ON_DEVICE",
    }
    detail={"schema":"rm11.engine.graphics-provider-closure.v1",
            "component_checks":checks,"unverified_runtime":[]}
    with zipfile.ZipFile(apk_path,"r") as apk:
        names=apk.namelist()
        if len(names)>MAX_ENTRIES or len(set(names))!=len(names):
            raise ValueError("GRAPHICS_APK_ENTRIES_UNSAFE")
        if PROVIDER_MANIFEST not in names:
            detail["static_provider_gate"]="BLOCKED_NO_SIGNED_PROVIDER_MANIFEST"
            detail["unverified_runtime"]=["DXVK_LOADED","GPU_PRESENTED","ANDROID_X11_FRAME"]
            detail["release_eligible"]=False
            return detail
        info=apk.getinfo(PROVIDER_MANIFEST)
        if info.file_size>MAX_MANIFEST_BYTES:
            raise ValueError("GRAPHICS_PROVIDER_MANIFEST_TOO_LARGE")
        try:
            manifest=json.loads(apk.read(info).decode("utf-8"))
        except (ValueError,UnicodeError):
            raise ValueError("GRAPHICS_PROVIDER_MANIFEST_INVALID")
        if not isinstance(manifest,dict) or manifest.get("schema")!="rm11.engine.bundle.v1":
            raise ValueError("GRAPHICS_PROVIDER_SCHEMA_UNTRUSTED")
        dxvk=manifest.get("dxvk",{})
        gpu=manifest.get("gpu",{})
        if not isinstance(dxvk,dict) or not isinstance(gpu,dict):
            raise ValueError("GRAPHICS_PROVIDER_FIELDS_INVALID")
        pefiles=dxvk.get("pe_files",{})
        if not isinstance(pefiles,dict):
            raise ValueError("GRAPHICS_DXVK_PEFILES_INVALID")
        dxvk_source_ok=(dxvk.get("provider")=="dxvk" and
                        isinstance(dxvk.get("source_commit"),str) and
                        SOURCE_COMMIT.fullmatch(dxvk["source_commit"]) is not None)
        for dll in DXVK:
            key="dxvk_pe_"+dll[:-4]
            data=pefiles.get(dll,{})
            if not isinstance(data,dict) or not dxvk_source_ok:
                checks[key]="SOURCE_PROVENANCE_UNVERIFIED"
                continue
            path=data.get("apk_path")
            if (path!=DXVK_ROOT+dll or path not in names or
                    data.get("architecture")!="x86_64"):
                checks[key]="DXVK_SIGNED_PATH_OR_ABI_DECLARATION_INVALID"
                continue
            ok,header=read_component(apk,path,data.get("sha256"))
            checks[key]=( "PE32PLUS_AMD64_HASH_VERIFIED" if ok and pe_amd64(header)
                         else "BINARY_HASH_OR_PE_ARCH_INVALID")
        # Official Mesa release tarballs have a content SHA256, not an
        # invented Git commit. Accept the exact upstream archive pin as
        # stronger source identity alongside the legacy commit format.
        turnip_commit=(gpu.get("source_archive_sha256")==
                       "efd4bb08cdb7c365a812cd4e6c9202ab55b2f22cdcd13c7d6c4f9647b799a4ef"
                       or (isinstance(gpu.get("source_commit"),str) and
                           SOURCE_COMMIT.fullmatch(gpu["source_commit"]) is not None))
        turnip_path=gpu.get("apk_library")
        if (gpu.get("driver")!="turnip" or not turnip_commit or
                not isinstance(turnip_path,str) or
                not turnip_path.startswith(TURNIP_ROOT) or
                not turnip_path.endswith(".so") or
                "/" in turnip_path[len(TURNIP_ROOT):] or
                gpu.get("architecture")!="aarch64" or
                gpu.get("libc")!="bionic"):
            checks["turnip_android_native"]="TURNIP_METADATA_OR_NATIVE_PATH_INVALID"
        else:
            ok,header=read_component(apk,turnip_path,gpu.get("sha256"))
            checks["turnip_android_native"]=(
                "AARCH64_ELF_HASH_VERIFIED" if ok and elf_aarch64(header)
                else "BINARY_HASH_OR_ELF_ARCH_INVALID")
        # A manifest's 'wsi: hardware' is a CLAIM and no proof that the
        # Android Vulkan HAL / WSI -> Lorie X11 surface transition works.
        detail["declared_gpu_wsi"]=gpu.get("wsi","UNKNOWN")
        detail["upstream_provenance_declared"]=dxvk_source_ok and turnip_commit
        structural=(
            checks["dxvk_pe_dxgi"]=="PE32PLUS_AMD64_HASH_VERIFIED" and
            checks["dxvk_pe_d3d11"]=="PE32PLUS_AMD64_HASH_VERIFIED" and
            checks["turnip_android_native"]=="AARCH64_ELF_HASH_VERIFIED"
        )
        detail["static_provider_gate"]=(
            "PROVIDER_BINARIES_STRUCTURALLY_VERIFIED"
            if structural else "BLOCKED_MISSING_OR_MISMATCHED_PROVIDERS")
        detail["unverified_runtime"]=[
            "DXVK_NATIVE_DLL_OVERRIDES_APPLIED",
            "FEX_TRANSLATES_WIN64_DIRECT3D_CALLS",
            "TURNIP_HARDWARE_ADRENO_DEVICE_ENUMERATED",
            "VULKAN_X11_SWAPCHAIN_PRESENTED",
            "WINDOW_PIXELS_REACHED_ANDROID_SURFACE",
        ]
        detail["release_eligible"]=False
        detail["hardware_rendering_proven"]=False
        detail["candidate_apk_or_prefix_modified"]=False
        return detail


def main():
    p=argparse.ArgumentParser()
    p.add_argument("apk")
    p.add_argument("--out")
    p.add_argument("--require-structural-provider",action="store_true")
    a=p.parse_args()
    result=inspect(a.apk)
    text=json.dumps(result,sort_keys=True,indent=2)+"\n"
    print(text)
    if a.out:
        Path(a.out).write_text(text,encoding="utf-8")
    if a.require_structural_provider and (
        result["static_provider_gate"]!="PROVIDER_BINARIES_STRUCTURALLY_VERIFIED"
    ):
        raise SystemExit(2)


if __name__=="__main__":
    main()
