#!/usr/bin/env python3
"""Fail-closed audit of a source-built Wine Linux runtime tar vs its SHA256 manifest.

Reads the archive without extracting it. This does not prove provenance,
Android/Bionic compatibility, FEX integration, or execution on a phone.
"""
import argparse
import hashlib
import json
import re
import struct
import tarfile
from pathlib import PurePosixPath, Path

SCHEMA = "kernix.wine11-linux-x86_64-stage.v1"
PREFIX = "opt/kernix-wine-linux-x64/"
LICENSE = PREFIX + "share/doc/kernix-upstream/WINE-LICENSE.txt"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_ENTRIES = 100000
MAX_BYTES = 8 * 1024**3


def _path(name):
    if not isinstance(name, str) or len(name) > 512 or not name.startswith(PREFIX):
        raise ValueError("UNEXPECTED_ARCHIVE_PATH")
    parts = name.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise ValueError("UNSAFE_ARCHIVE_PATH")
    return name


def _kind(header, read_pe):
    if header[:4] == b"\\x7fELF":
        if len(header) < 20 or header[4:6] != b"\\x02\\x01":
            raise ValueError("INVALID_ELF_HEADER")
        if struct.unpack_from("<H", header, 18)[0] != 62:
            raise ValueError("WRONG_ELF_ABI")
        return "elf-x86_64-linux"
    if header[:2] == b"MZ":
        if len(header) < 64:
            raise ValueError("INVALID_PE_HEADER")
        offset = struct.unpack_from("<I", header, 60)[0]
        signature = read_pe(offset)
        if signature[:4] != b"PE\\x00\\x00" or len(signature) != 6:
            raise ValueError("INVALID_PE_SIGNATURE")
        if struct.unpack_from("<H", signature, 4)[0] != 0x8664:
            raise ValueError("WRONG_PE_ABI")
        return "pe-x86_64-windows"
    return "data"


def verify(archive, manifest):
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        raise ValueError("INVALID_STAGE_SCHEMA")
    if (manifest.get("source") != "wine-mirror/wine"
        or not isinstance(manifest.get("upstream_commit"), str)
        or not HEX40.fullmatch(manifest["upstream_commit"])
        or manifest.get("host") != "ubuntu-24.04-x86_64-glibc"
        or manifest.get("android_bionic_compatible") is not False
        or manifest.get("is_android_package") is not False
        or manifest.get("fex_arm64_tested") is not False
        or manifest.get("windows_game_tested") is not False):
        raise ValueError("INVALID_STAGE_PROVENANCE_OR_CLAIMS")
    entries = manifest.get("files")
    if not isinstance(entries, list) or not (1 <= len(entries) <= MAX_ENTRIES):
        raise ValueError("INVALID_STAGE_FILE_LIST")
    expected = {}
    total = 0
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("INVALID_STAGE_ENTRY")
        name = _path(entry.get("path"))
        if name in expected:
            raise ValueError("DUPLICATE_MANIFEST_PATH")
        if entry.get("kind") == "symlink":
            if set(entry) != {"path", "kind", "target"} or not isinstance(entry["target"], str):
                raise ValueError("INVALID_SYMLINK_RECORD")
        else:
            if set(entry) != {"path", "kind", "size", "sha256"}:
                raise ValueError("INVALID_FILE_RECORD")
            if entry["kind"] not in ("data", "elf-x86_64-linux", "pe-x86_64-windows"):
                raise ValueError("INVALID_FILE_KIND")
            if type(entry["size"]) is not int or not (1 <= entry["size"] <= 2 * 1024**3):
                raise ValueError("INVALID_FILE_SIZE")
            if not isinstance(entry["sha256"], str) or not HEX64.fullmatch(entry["sha256"]):
                raise ValueError("INVALID_FILE_SHA256")
            total += entry["size"]
            if total > MAX_BYTES:
                raise ValueError("STAGE_TOO_LARGE")
        expected[name] = entry
    if LICENSE not in expected or expected[LICENSE]["kind"] != "data":
        raise ValueError("UPSTREAM_LICENSE_MISSING_FROM_RUNTIME")
    seen = set()
    elf = pe = 0
    with tarfile.open(archive, "r:gz") as tf:
        for member in tf:
            if member.isdir():
                # GNU tar includes parent directories; no need to manifest them.
                name = member.name.rstrip("/")
                if name not in ("opt", "opt/kernix-wine-linux-x64"):
                    _path(name)
                continue
            name = _path(member.name)
            if name in seen or name not in expected:
                raise ValueError("DUPLICATE_OR_EXTRA_ARCHIVE_ENTRY")
            seen.add(name)
            entry = expected[name]
            if member.issym():
                if entry["kind"] != "symlink" or member.linkname != entry["target"]:
                    raise ValueError("SYMLINK_TARGET_MISMATCH")
                continue
            if not member.isfile() or entry["kind"] == "symlink":
                raise ValueError("UNSUPPORTED_ARCHIVE_MEMBER")
            if member.size != entry["size"]:
                raise ValueError("ARCHIVE_SIZE_MISMATCH")
            f = tf.extractfile(member)
            if f is None:
                raise ValueError("UNREADABLE_ARCHIVE_FILE")
            h = hashlib.sha256()
            head = f.read(min(4096, member.size))
            h.update(head)
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
            if h.hexdigest() != entry["sha256"]:
                raise ValueError("ARCHIVE_SHA256_MISMATCH")
            def pe_header(offset):
                if offset < 64 or offset > member.size - 6:
                    return b""
                with tf.extractfile(member) as stream:
                    stream.seek(offset)
                    return stream.read(6)
            kind = _kind(head, pe_header)
            if kind != entry["kind"]:
                raise ValueError("ARCHIVE_ABI_OR_KIND_MISMATCH")
            elf += kind == "elf-x86_64-linux"
            pe += kind == "pe-x86_64-windows"
    if seen != set(expected):
        raise ValueError("MISSING_ARCHIVE_ENTRIES")
    if elf != manifest.get("elf_x86_64_files") or pe != manifest.get("pe_x86_64_files"):
        raise ValueError("ABI_FILE_COUNT_MISMATCH")
    if not elf or not pe:
        raise ValueError("MISSING_ELF_OR_PE")
    return {"schema": "kernix.wine-stage-archive-audit.v1",
            "verified_files": len(seen), "verified_bytes": total,
            "elf_x86_64": elf, "pe_x86_64": pe,
            "all_regular_files_sha256_verified": True,
            "license_in_archive": True,
            "android_bionic_compatible": False, "runtime_tested": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()
    result = verify(args.archive, json.loads(Path(args.manifest).read_text()))
    print(json.dumps(result, indent=2))
