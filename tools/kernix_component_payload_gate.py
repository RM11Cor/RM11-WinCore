#!/usr/bin/env python3
"""Verify an independently built KERNIX component staging tree.

No install, extraction, game execution, trusted origin or Android compatibility
claim is implied. Every file must be explicit; no symlinks, hardlinks or extras.
"""
import argparse
import hashlib
import hmac
import json
import re
import stat
import struct
from pathlib import Path

from kernix_native_artifact_gate import attest_arm64_elf, HEX40, HEX64
from kernix_component_registry import KINDS

MAX_FILES = 512
MAX_TOTAL = 4 * 1024**3
SAFE_PATH = re.compile(r"^[A-Za-z0-9_.+/-]{1,240}$")
KINDS_ALLOWED = set(KINDS) | {"box64"}
PE_MACHINES = {"x86": 0x14c, "x86_64": 0x8664, "arm64": 0xaa64}


def safe_path(path):
    if not isinstance(path, str) or not SAFE_PATH.fullmatch(path):
        raise ValueError("UNSAFE_BUNDLE_PATH")
    parts = path.split("/")
    if any(part in ("", ".", "..") or part.startswith(".") for part in parts):
        raise ValueError("UNSAFE_BUNDLE_PATH")
    if len(parts) > 16:
        raise ValueError("PATH_TOO_DEEP")
    return path


def attest_pe(path, expected, arch):
    if arch not in PE_MACHINES:
        raise ValueError("UNKNOWN_PE_MACHINE")
    p = Path(path)
    if not p.is_file() or p.is_symlink():
        raise ValueError("BAD_PE_PATH")
    with p.open("rb") as f:
        header = f.read(64)
        if len(header) < 64 or header[:2] != b"MZ":
            raise ValueError("NOT_PE")
        offset = struct.unpack_from("<I", header, 60)[0]
        if offset < 64 or offset > p.stat().st_size - 24:
            raise ValueError("INVALID_PE_OFFSET")
        f.seek(offset)
        data = f.read(24)
        if data[:4] != b"PE\0\0" or struct.unpack_from("<H", data, 4)[0] != PE_MACHINES[arch]:
            raise ValueError("PE_MACHINE_MISMATCH")
    actual = hashlib.sha256(p.read_bytes()).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise ValueError("PE_SHA256_MISMATCH")
    return actual


def verify_tree(root, manifest):
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema", "component", "source", "files", "license_paths"
    } or manifest["schema"] != "kernix.component-payload.v1":
        raise ValueError("INVALID_PAYLOAD_SCHEMA")
    comp = manifest["component"]
    if not isinstance(comp, dict) or set(comp) != {"id", "kind", "version"}:
        raise ValueError("INVALID_COMPONENT_DESCRIPTOR")
    if not isinstance(comp["id"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,79}", comp["id"]):
        raise ValueError("INVALID_COMPONENT_ID")
    if comp["kind"] not in KINDS_ALLOWED or not isinstance(comp["version"], str) or not comp["version"]:
        raise ValueError("INVALID_COMPONENT_KIND_OR_VERSION")
    source = manifest["source"]
    if not isinstance(source, dict) or set(source) != {"repository", "git_commit", "license_spdx"}:
        raise ValueError("INVALID_SOURCE_DESCRIPTOR")
    if not isinstance(source["repository"], str) or not re.fullmatch(r"[\w.-]+/[\w.-]+", source["repository"]):
        raise ValueError("INVALID_REPOSITORY")
    if not isinstance(source["git_commit"], str) or not HEX40.fullmatch(source["git_commit"]):
        raise ValueError("SOURCE_NOT_PINNED")
    if not isinstance(source["license_spdx"], str) or not re.fullmatch(r"[A-Za-z0-9.+-]{2,40}", source["license_spdx"]):
        raise ValueError("INVALID_LICENSE_ID")

    files = manifest["files"]
    licenses = manifest["license_paths"]
    if not isinstance(files, list) or not (1 <= len(files) <= MAX_FILES):
        raise ValueError("INVALID_FILES")
    if not isinstance(licenses, list) or not licenses or len(set(map(str, licenses))) != len(licenses):
        raise ValueError("INVALID_LICENSE_FILES")
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("BAD_STAGING_ROOT")
    root = root.resolve()
    expected = set()
    total = 0
    validated = []
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "size_bytes", "sha256", "format", "machine"}:
            raise ValueError("INVALID_FILE_ENTRY")
        relative = safe_path(entry["path"])
        if relative in expected:
            raise ValueError("DUPLICATE_FILE")
        expected.add(relative)
        digest = entry["sha256"]
        size = entry["size_bytes"]
        fmt, machine = entry["format"], entry["machine"]
        if not isinstance(digest, str) or not HEX64.fullmatch(digest):
            raise ValueError("INVALID_FILE_DIGEST")
        if not isinstance(size, int) or isinstance(size, bool) or not (1 <= size <= 2 * 1024**3):
            raise ValueError("INVALID_FILE_SIZE")
        total += size
        if total > MAX_TOTAL:
            raise ValueError("BUNDLE_TOO_LARGE")
        path = root / relative
        # lstat every ancestor: do not silently follow a symlink to outside root.
        cur = root
        for part in relative.split("/"):
            cur = cur / part
            if cur.is_symlink():
                raise ValueError("SYMLINK_NOT_ALLOWED")
        if not path.is_file() or not stat.S_ISREG(path.stat().st_mode) or path.stat().st_nlink != 1:
            raise ValueError("NONREGULAR_OR_LINKED_FILE")
        if path.stat().st_size != size:
            raise ValueError("FILE_SIZE_MISMATCH")
        if fmt == "elf" and machine == "arm64":
            attest_arm64_elf(path, digest)
        elif fmt == "pe" and machine in PE_MACHINES:
            attest_pe(path, digest, machine)
        elif fmt == "data" and machine == "none":
            with path.open("rb") as f:
                h = hashlib.sha256()
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            if not hmac.compare_digest(h.hexdigest(), digest):
                raise ValueError("FILE_SHA256_MISMATCH")
        else:
            raise ValueError("INVALID_FORMAT_MACHINE_PAIR")
        validated.append(relative)
    if not set(licenses).issubset(expected):
        raise ValueError("MISSING_LICENSE_NOTICE")
    if any(not isinstance(p, str) or not p.startswith("licenses/") for p in licenses):
        raise ValueError("LICENSE_WRONG_LOCATION")
    observed = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("SYMLINK_NOT_ALLOWED")
        if path.is_file():
            observed.add(path.relative_to(root).as_posix())
        elif not path.is_dir():
            raise ValueError("UNEXPECTED_NONFILE")
    if observed != expected:
        raise ValueError("EXTRA_OR_MISSING_FILES")
    return {
        "schema": "kernix.payload-audit.v1",
        "component_id": comp["id"],
        "file_count": len(files),
        "byte_count": total,
        "all_files_hashed": True,
        "elf_pe_header_checked": True,
        "android_bionic_link_verified": False,
        "source_reproducibility_verified": False,
        "runtime_tested": False,
        "installed": False,
        "note": "Staging-tree integrity only; do not add to verified runtime registry without actual build, linkage and device validation."
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", required=True)
    p.add_argument("--manifest", required=True)
    a=p.parse_args()
    with open(a.manifest, encoding="utf-8") as fh:
        manifest=json.load(fh)
    print(json.dumps(verify_tree(a.root,manifest),indent=2))


if __name__ == "__main__":
    main()
