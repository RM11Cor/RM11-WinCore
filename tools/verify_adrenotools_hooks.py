#!/usr/bin/env python3
"""Static AArch64 Android ELF proof for pinned libadrenotools hooks.

Successful linkage DOES NOT mean custom Turnip injection worked in Wine
children, Android app namespaces, Vulkan X11, or the Android Surface.
"""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

HOOKS = (
    "libadrenotools.so",
    "libmain_hook.so",
    "libhook_impl.so",
    "libfile_redirect_hook.so",
    "libgsl_alloc_hook.so",
)
BAD_DEPENDENCIES = {"libhardware.so", "libc.so.6", "libstdc++.so.6"}


def verify(files, needs):
    result = {}
    for name in HOOKS:
        p = Path(files) / name
        report = Path(needs) / (name + ".needed")
        if p.is_symlink() or not p.is_file() or p.stat().st_size < 4096:
            raise ValueError("RM11_ADRENO_HOOK_MISSING:" + name)
        b = p.read_bytes()
        if b[:6] != b"\x7fELF\x02\x01" or len(b) < 64:
            raise ValueError("RM11_ADRENO_HOOK_NOT_ELF64:" + name)
        typ, machine = struct.unpack_from("<HH", b, 16)
        if typ != 3 or machine != 183:
            raise ValueError("RM11_ADRENO_HOOK_NOT_AARCH64_DYN:" + name)
        if not report.is_file():
            raise ValueError("RM11_ADRENO_NEEDED_NOT_INSPECTED:" + name)
        dynamic = report.read_text(encoding="utf-8")
        required = sorted(set(re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", dynamic)))
        if not required or "libc.so" not in required:
            raise ValueError("RM11_ADRENO_NOT_BIONIC_LINKAGE:" + name)
        if set(required) & BAD_DEPENDENCIES:
            raise ValueError("RM11_ADRENO_PRIVATE_OR_GLIBC_LIBRARY:" + name)
        result[name] = {"sha256": hashlib.sha256(b).hexdigest(),
                        "needed": required, "architecture": "aarch64"}
    return {
        "schema": "rm11.adrenotools.android-linkproof.v1",
        "upstream_commit": "8fae8ce254dfc1344527e05301e43f37dea2df80",
        "license": "BSD-2-Clause",
        "binaries": result,
        "source_link_abi_verified": True,
        "wine_child_namespace_integration_verified": False,
        "physical_adreno_enumeration_verified": False,
        "hardware_android_frame_verified": False,
        "safe_to_publish_apk": False,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--libdir", required=True)
    p.add_argument("--readelf-dir", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()
    data = verify(args.libdir, args.readelf_dir)
    Path(args.out).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    print("RM11_ADRENOTOOLS_ANDROID_ELF_LINKPROOF_ONLY_NO_APK")


if __name__ == "__main__":
    main()
