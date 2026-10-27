#!/usr/bin/env python3
"""Read-only machine-ABI audit of the actual signed RM11 runtime payload.

An asset filename is not evidence of compatible ELF/PE machine format.
This audit unpacks nothing on device, executes nothing and never claims game
rendering. APK digest is supplied by caller's pinned GitHub release checksum.
"""
import argparse
import hashlib
import io
import json
import os
import struct
import tempfile
import zipfile
from pathlib import Path
from pe_chpe import inspect_arm64ec, MAX_PE_BYTES

ELF_AARCH64 = 183
PE_ARM64EC = 0xA641
PE_ARM64X = 0xA64E
PE_ARM64 = 0xAA64
PE_AMD64 = 0x8664
PE_I386 = 0x014C
MAX_ARCHIVE_BYTES = 650 * 1024 * 1024
NATIVE_APK_FILES = {
    "wine_loader": "lib/arm64-v8a/libwineprobe.so",
    "wineserver": "lib/arm64-v8a/libwineserverrm11.so",
    "x11_wine_client": "lib/arm64-v8a/libwine_winex11.so",
    "xorg_lorie": "lib/arm64-v8a/libXlorie.so",
}
FEX_PE_SUFFIXES = {
    "arm64ec_module": "/libarm64ecfex.dll",
    "wow64_module": "/libwow64fex.dll",
}


def read_elf_header(header):
    if (len(header) < 64 or header[:4] != b"\x7fELF"
            or header[4] != 2 or header[5] != 1):
        return {"format": "INVALID_ELF64_LITTLE_ENDIAN", "abi_ok": False}
    etype, machine = struct.unpack_from("<HH", header, 16)
    return {
        "format": "ELF64",
        "elf_type": etype,
        "machine": machine,
        "architecture": "AARCH64" if machine == ELF_AARCH64 else "OTHER",
        "abi_ok": etype in (2, 3) and machine == ELF_AARCH64,
    }


def read_pe_header(header, expected=None):
    if len(header) < 64 or header[:2] != b"MZ":
        return {"format": "INVALID_DOS_MZ", "abi_ok": False}
    offset, = struct.unpack_from("<I", header, 0x3C)
    if offset < 0x40 or offset > 4096 or len(header) < offset + 26:
        return {"format": "INVALID_PE_OFFSET", "abi_ok": False}
    if header[offset:offset + 4] != b"PE\x00\x00":
        return {"format": "INVALID_PE_SIGNATURE", "abi_ok": False}
    machine, = struct.unpack_from("<H", header, offset + 4)
    magic, = struct.unpack_from("<H", header, offset + 24)
    names = {PE_ARM64EC: "ARM64EC", PE_ARM64X: "ARM64X",
             PE_ARM64: "ARM64", PE_AMD64: "AMD64", PE_I386: "I386"}
    return {
        "format": "PE",
        "pe_magic": magic,
        "machine": machine,
        "architecture": names.get(machine, "OTHER"),
        "abi_ok": magic == 0x20B and (
            machine in expected if expected is not None else True
        ),
    }


def audit(path):
    path = Path(path)
    with path.open("rb") as file:
        sha = hashlib.file_digest(file, "sha256").hexdigest()
    native = {}
    fex = {}
    unresolved = []
    with zipfile.ZipFile(path, "r") as apk:
        for label, name in NATIVE_APK_FILES.items():
            if name not in apk.namelist():
                native[label] = {"format": "MISSING", "abi_ok": False}
                continue
            with apk.open(name) as binary:
                native[label] = read_elf_header(binary.read(64))
        target = "assets/runtime/rm11-wine-stack.zip"
        if target not in apk.namelist():
            unresolved.append("PINNED_WINE_STACK_ARCHIVE_NOT_FOUND")
        else:
            meta = apk.getinfo(target)
            if meta.file_size > MAX_ARCHIVE_BYTES:
                unresolved.append("PINNED_WINE_STACK_ARCHIVE_OVERSIZED")
            else:
                try:
                    with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as tmp:
                        with apk.open(meta) as src:
                            size = 0
                            for block in iter(lambda: src.read(1024 * 1024), b""):
                                size += len(block)
                                if size > MAX_ARCHIVE_BYTES:
                                    raise ValueError("NESTED_ARCHIVE_LIMIT")
                                tmp.write(block)
                        tmp.seek(0)
                        with zipfile.ZipFile(tmp) as nested:
                            entries = nested.namelist()
                            for key, suffix in FEX_PE_SUFFIXES.items():
                                matches = [s for s in entries
                                           if s.replace("\\", "/").lower().endswith(suffix)]
                                if len(matches) != 1:
                                    fex[key] = {"format": "AMBIGUOUS_OR_MISSING",
                                                "matches": len(matches),
                                                "abi_ok": False}
                                    continue
                                with nested.open(matches[0]) as pe:
                                    if key == "arm64ec_module":
                                        image = pe.read(MAX_PE_BYTES + 1)
                                        # A final ARM64EC PE legitimately says
                                        # AMD64 in the COFF machine header.
                                        # CHPE load config proves its hybrid ABI.
                                        fex[key] = read_pe_header(
                                            image[:8192], {PE_AMD64})
                                        fex[key].update(inspect_arm64ec(image))
                                    else:
                                        header = pe.read(8192)
                                        fex[key] = read_pe_header(
                                            header, {PE_ARM64, PE_ARM64X})
                except (OSError, zipfile.BadZipFile, RuntimeError,
                        ValueError) as exc:
                    unresolved.append("NESTED_RUNTIME_UNREADABLE_" + type(exc).__name__)
    native_ok = all(v["abi_ok"] for v in native.values())
    fex_ok = (not unresolved and all(
        v.get("abi_ok") for v in fex.values())
        and len(fex) == len(FEX_PE_SUFFIXES))
    return {
        "schema": "rm11.engine.abi.audit.v1",
        "apk_sha256": sha,
        "native_elf": native,
        "guest_fex_pe": fex,
        "unresolved": unresolved,
        "native_abi_closure": "STRUCTURALLY_COMPATIBLE" if native_ok else "BLOCKED",
        "guest_translation_abi": "STRUCTURALLY_COMPATIBLE" if fex_ok else "BLOCKED",
        "game_rendering_claim": "UNVERIFIED",
        "would_publish_apk": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("apk")
    parser.add_argument("--out")
    parser.add_argument("--require-abi-ready", action="store_true")
    args = parser.parse_args()
    result = audit(args.apk)
    doc = json.dumps(result, indent=2, sort_keys=True) + "\n"
    print(doc)
    if args.out:
        Path(args.out).write_text(doc, encoding="utf-8")
    if args.require_abi_ready and (
        result["native_abi_closure"] != "STRUCTURALLY_COMPATIBLE" or
        result["guest_translation_abi"] != "STRUCTURALLY_COMPATIBLE"
    ):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
