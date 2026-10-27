#!/usr/bin/env python3
"""Static ABI/provenance check for Mesa Turnip Android KGSL source output.

This is NOT Android X11 hardware frame proof. ET_DYN and Bionic-compatible
dynamic dependencies are necessary; native Android Vulkan HAL integration
and VK_KHR_* runtime capability tests are still outstanding.
"""
import argparse
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path

MESA_26_2_0_TARBALL_SHA256="efd4bb08cdb7c365a812cd4e6c9202ab55b2f22cdcd13c7d6c4f9647b799a4ef"
MAX_BINARY=150*1024*1024


def validate(file_path,readelf_text):
    p=Path(file_path)
    if not p.is_file() or p.is_symlink() or p.stat().st_size<4096 or p.stat().st_size>MAX_BINARY:
        raise ValueError("TURNIP_ANDROID_BINARY_MISSING_OR_INVALID")
    with p.open("rb") as f:head=f.read(64)
    if len(head)<64 or head[:6]!=b"\x7fELF\x02\x01":
        raise ValueError("TURNIP_NOT_ELF64_LITTLE_ENDIAN")
    typ,machine=struct.unpack_from("<HH",head,16)
    if typ!=3 or machine!=183:
        raise ValueError("TURNIP_NOT_AARCH64_ET_DYN")
    # 'NEEDED' lines from the NDK llvm-readelf -d output are strong static
    # indicators of libc/toolchain origin, not proof of actual dlopen().
    needed=re.findall(r"\(NEEDED\).*?\[([^\]]+)\]",readelf_text)
    if any(x.startswith(("libc.so.6","ld-linux","libpthread.so.0","libstdc++.so.6"))
           or "GLIBC" in x for x in needed):
        raise ValueError("TURNIP_GLIBC_BINARY_IN_ANDROID_NATIVE_DIR")
    if not needed:
        raise ValueError("TURNIP_NO_DYNAMIC_DEPENDENCIES_INSPECTED")
    if "libc.so" not in needed:
        raise ValueError("TURNIP_ANDROID_BIONIC_LIBC_DEPENDENCY_NOT_VISIBLE")
    with p.open("rb") as f:
        digest=hashlib.file_digest(f,"sha256").hexdigest()
    return {
        "schema":"rm11.engine.turnip-android-elf.v1",
        "mesa_release":"26.2.0",
        "mesa_upstream_tar_sha256":MESA_26_2_0_TARBALL_SHA256,
        "elf_sha256":digest,
        "architecture":"aarch64",
        "libc_target":"bionic",
        "mesa_freedreno_kmd":"kgsl",
        "dynamic_needed":sorted(set(needed)),
        "static_elf_abi_verified":True,
        # The AOSP libhardware.so is normally a VNDK-SP/private HAL
        # dependency rather than a public application NDK library.
        # Android linker namespaces can reject it on targetSdk 35,
        # even with a genuine Bionic ARM64 ELF. Don't assert dlopen().
        "app_linker_namespace_gate":(
            "BLOCKED_PRIVATE_AOSP_LIBHARDWARE_DEPENDENCY"
            if "libhardware.so" in needed
            else "UNVERIFIED_APP_NAMESPACE_LOADABILITY"),
        "app_native_dlopen_succeeded":False,
        "android_vulkan_device_enumerated":False,
        "vulkan_x11_wsi_available":False,
        "actual_adreno_hardware_frame_presented":False,
        "safe_to_publish_engine_apk":False,
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--elf",required=True)
    p.add_argument("--readelf",required=True)
    p.add_argument("--out",required=True)
    args=p.parse_args()
    text=Path(args.readelf).read_text(encoding="utf-8",errors="replace")
    report=validate(args.elf,text)
    Path(args.out).write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("RM11_TURNIP_AARCH64_ANDROID_BIONIC_STATIC_ELF_GATE_PASS")


if __name__=="__main__":main()
