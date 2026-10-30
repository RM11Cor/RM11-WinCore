#!/usr/bin/env python3
"""Byte-level ABI audit of RM11's pinned Wine PE/Unix bus pair.

Outputs hashes and machine architectures. It deliberately DOES NOT claim to
know a matching Wine source commit from file names or inferred version text:
a source commit must come from signed build provenance or exact reproducible
source verification. Run before adding a Wine-specific HID bus adapter.
"""
import argparse
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path

REQUIRED = (
    "lib/wine/aarch64-unix/winebus.so",
    "lib/wine/aarch64-windows/winebus.sys",
    "lib/wine/i386-windows/winebus.sys",
)
ARCH = {0xAA64: "ARM64", 0xA641: "ARM64EC", 0x8664: "AMD64",
        0x014c: "I386", 0xA64E: "ARM64X"}


def elf_arch(data):
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ValueError("bad_elf_header")
    if data[4] != 2 or data[5] != 1:
        raise ValueError("native_winebus_must_be_elf64_le")
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine != 183:
        raise ValueError("native_winebus_must_be_aarch64")
    return "AARCH64_ELF64"


def pe_arch(data):
    if len(data) < 128 or data[:2] != b"MZ":
        raise ValueError("bad_pe_dos_header")
    off = struct.unpack_from("<I", data, 0x3c)[0]
    if off + 26 > len(data) or data[off:off + 4] != b"PE\x00\x00":
        raise ValueError("bad_pe_signature")
    machine = struct.unpack_from("<H", data, off + 4)[0]
    return ARCH.get(machine, f"UNKNOWN_0x{machine:04X}")


def audit(wine_zip_bytes):
    with zipfile.ZipFile(io.BytesIO(wine_zip_bytes)) as z:
        names = set(z.namelist())
        files = []
        for name in REQUIRED:
            if name not in names:
                raise ValueError("missing_required_winebus:" + name)
            info = z.getinfo(name)
            if info.file_size < 4096 or info.file_size > 32 * 1024 * 1024:
                raise ValueError("bad_winebus_size:" + name)
            blob = z.read(name)
            arch = elf_arch(blob) if name.endswith(".so") else pe_arch(blob)
            files.append({
                "path": name,
                "sha256": hashlib.sha256(blob).hexdigest(),
                "bytes": len(blob),
                "machine": arch
            })
        more = sorted(n for n in names if
            any(n.endswith("/" + x) for x in
                ("winehid.sys", "hidclass.sys", "winexinput.sys")))
    return {
        "schema": "rm11.pinned_winebus_abi.v1",
        "evidence": "actual bundled PE/ELF bytes",
        "winebus_files": files,
        "related_pnp_files": more,
        "source_revision": None,
        "source_revision_verified": False,
        "winebus_unix_pe_abi_match": "UNVERIFIED_REQUIRES_MATCHED_SOURCE",
        "rm11_hid_adapter_packaging_allowed": False,
    }


def main():
    parser = argparse.ArgumentParser()
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--wine-stack", type=Path)
    input_group.add_argument("--apk", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.apk:
        with zipfile.ZipFile(args.apk) as apk:
            data = apk.read("assets/runtime/rm11-wine-stack.zip")
    else:
        data = args.wine_stack.read_bytes()
    result = audit(data)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("RM11_PINNED_WINEBUS_BINARIES_SHA256_ARCH_AUDITED")
    for entry in result["winebus_files"]:
        print(entry["path"], entry["machine"], entry["sha256"])
    print("RM11_NATIVE_BUS_SOURCE_ABI_MATCH_UNVERIFIED_STOP_BEFORE_PACKAGE")


if __name__ == "__main__":
    main()
