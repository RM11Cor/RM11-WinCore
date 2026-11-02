#!/usr/bin/env python3
"""KERNIX source provenance and Android ARM64 ELF pre-install gate.

This is NOT a component builder, installer, Bionic dynamic-linker test, or a
proof of Android compatibility. A source commit (40 hex) is not a binary SHA256.
"""
import argparse
import hashlib
import hmac
import json
import re
import struct
from pathlib import Path

SOURCES = {
    "fex": ("FEX-Emu/FEX", "MIT"),
    "dxvk": ("doitsujin/dxvk", "Zlib"),
    "vkd3d": ("HansKristian-Work/vkd3d-proton", "LGPL-2.1"),
}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_FILE_BYTES = 2 * 1024**3


def validate_source_lock(manifest):
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema", "recorded_utc", "note", "components"
    } or manifest["schema"] != "kernix.upstream-source-lock.v1":
        raise ValueError("INVALID_SOURCE_LOCK_SCHEMA")
    components = manifest["components"]
    if not isinstance(components, list) or not components or len(components) > len(SOURCES):
        raise ValueError("INVALID_SOURCE_COUNT")
    seen = set()
    for item in components:
        if not isinstance(item, dict) or set(item) != {
            "kind", "repository", "git_commit", "license_spdx", "android_binary_built"
        }:
            raise ValueError("INVALID_SOURCE_ENTRY")
        kind = item["kind"]
        if kind not in SOURCES or kind in seen:
            raise ValueError("UNKNOWN_OR_DUPLICATE_SOURCE")
        seen.add(kind)
        if (item["repository"], item["license_spdx"]) != SOURCES[kind]:
            raise ValueError("UNEXPECTED_SOURCE_OR_LICENSE")
        if not isinstance(item["git_commit"], str) or not HEX40.fullmatch(item["git_commit"]):
            raise ValueError("UNPINNED_SOURCE_COMMIT")
        if item["android_binary_built"] is not False:
            raise ValueError("UNVERIFIED_BUILD_CLAIM")
    return {item["kind"]: item["git_commit"] for item in components}


def attest_arm64_elf(path, expected_sha256):
    """Verify on-disk ELF architecture and byte-for-byte digest, fail closed."""
    if not isinstance(expected_sha256, str) or not HEX64.fullmatch(expected_sha256):
        raise ValueError("INVALID_EXPECTED_SHA256")
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise ValueError("MISSING_OR_SYMLINKED_ELF")
    size = p.stat().st_size
    if size < 120 or size > MAX_FILE_BYTES:
        raise ValueError("INVALID_ELF_FILE_SIZE")
    with p.open("rb") as stream:
        header = stream.read(64)
        if header[:4] != b"\x7fELF" or header[4:7] != b"\x02\x01\x01":
            raise ValueError("NOT_LITTLE_ENDIAN_ELF64")
        e_type, e_machine, e_version = struct.unpack_from("<HHI", header, 16)
        if e_type not in (2, 3) or e_machine != 183 or e_version != 1:
            raise ValueError("NOT_ARM64_NATIVE_ELF")
        phoff = struct.unpack_from("<Q", header, 32)[0]
        ehsize, phentsize, phnum = struct.unpack_from("<HHH", header, 52)
        if ehsize != 64 or phentsize != 56 or not (1 <= phnum <= 4096):
            raise ValueError("INVALID_ELF_PROGRAM_HEADERS")
        if phoff < 64 or phoff + phentsize * phnum > size:
            raise ValueError("ELF_PROGRAM_HEADERS_OUT_OF_BOUNDS")
        stream.seek(phoff)
        has_load = False
        for _ in range(phnum):
            ph = stream.read(56)
            if len(ph) != 56:
                raise ValueError("TRUNCATED_PROGRAM_HEADER")
            p_type = struct.unpack_from("<I", ph)[0]
            p_offset, p_filesz, p_memsz = struct.unpack_from("<QQQ", ph, 8)[0], struct.unpack_from("<Q", ph, 32)[0], struct.unpack_from("<Q", ph, 40)[0]
            if p_type == 1:
                has_load = True
                if p_filesz > p_memsz or p_offset > size or p_filesz > size - p_offset:
                    raise ValueError("INVALID_ELF_LOAD_SEGMENT")
        if not has_load:
            raise ValueError("ELF_WITHOUT_LOAD_SEGMENT")
        stream.seek(0)
        digest = hashlib.sha256()
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    actual = digest.hexdigest()
    if not hmac.compare_digest(actual, expected_sha256):
        raise ValueError("SHA256_MISMATCH")
    return {
        "schema": "kernix.arm64-elf-attestation.v1",
        "file": p.name,
        "size_bytes": size,
        "sha256": actual,
        "elf_machine": "AArch64",
        "host_abi": "arm64",
        "elf_structure_verified": True,
        "binary_sha256_verified": True,
        "android_bionic_link_verified": False,
        "device_qualified": False,
        "installed_in_kernix": False,
        "note": "Static ELF check only. Android linker, dependencies, Vulkan and device behavior remain untested."
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    lock = sub.add_parser("sources")
    lock.add_argument("manifest", nargs="?", default="components/upstream-source-lock.json")
    elf = sub.add_parser("elf")
    elf.add_argument("path")
    elf.add_argument("--sha256", required=True)
    args = parser.parse_args()
    if args.action == "sources":
        data = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        result = {"source_commits": validate_source_lock(data), "runtime_built": False}
    else:
        result = attest_arm64_elf(args.path, args.sha256)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
