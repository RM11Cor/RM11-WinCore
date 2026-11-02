#!/usr/bin/env python3
"""Audit Linux ELF DT_NEEDED and PT_INTERP in source-built Wine staging.

Records guest Linux/rootfs dependency evidence only. Does not resolve or
execute libraries, establish FEX compatibility, or attest Android/Bionic.
"""
import argparse
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path, PurePosixPath

PREFIX = "opt/kernix-wine-linux-x64/"
SCHEMA = "kernix.wine11-linux-x86_64-stage.v1"
SONAME = re.compile(r"[A-Za-z0-9_.+@-]{1,200}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def parse_dynamic(output):
    needed, search_paths = [], {}
    for line in output.splitlines():
        if "(NEEDED)" in line:
            match = re.search(r"Shared library: \[([^\]]+)\]", line)
            if not match or not SONAME.fullmatch(match.group(1)):
                raise ValueError("INVALID_DT_NEEDED")
            needed.append(match.group(1))
        for tag in ("RPATH", "RUNPATH"):
            if f"({tag})" in line:
                match = re.search(r"Library (?:rpath|runpath): \[([^\]]*)\]", line)
                if not match or tag in search_paths:
                    raise ValueError("INVALID_DYNAMIC_SEARCH_PATH")
                search_paths[tag] = match.group(1)
    return sorted(set(needed)), search_paths


def parse_program_headers(output):
    matches = re.findall(r"\[Requesting program interpreter: ([^\]\n]+)\]", output)
    if len(matches) > 1 or ("INTERP" in output and not matches):
        raise ValueError("INVALID_PT_INTERP")
    if matches and (not matches[0].startswith("/") or "\x00" in matches[0]):
        raise ValueError("INVALID_PT_INTERP")
    return matches[0] if matches else None


def _readelf(path, flag):
    result = subprocess.run(
        ["readelf", "-W", flag, str(path)],
        check=True, capture_output=True, text=True, timeout=20,
    )
    return result.stdout


def audit(stage_root, manifest):
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        raise ValueError("INVALID_STAGE_SCHEMA")
    if (manifest.get("source") != "wine-mirror/wine"
            or manifest.get("host") != "ubuntu-24.04-x86_64-glibc"
            or manifest.get("android_bionic_compatible") is not False):
        raise ValueError("INVALID_STAGE_PROVENANCE")
    root = Path(stage_root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("INVALID_STAGE_ROOT")
    root = root.resolve()
    entries = manifest.get("files")
    if not isinstance(entries, list) or len(entries) > 100000:
        raise ValueError("INVALID_STAGE_ENTRIES")
    bundled = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError("INVALID_STAGE_ENTRY")
        bundled.add(PurePosixPath(entry["path"]).name)
    report = []
    seen = set()
    for entry in entries:
        if entry.get("kind") != "elf-x86_64-linux":
            continue
        rel = entry["path"]
        parts = rel.split("/")
        if (not rel.startswith(PREFIX) or len(rel) > 512
                or any(part in ("", ".", "..") for part in parts) or rel in seen):
            raise ValueError("INVALID_ELF_PATH")
        seen.add(rel)
        size, digest = entry.get("size"), entry.get("sha256")
        if (type(size) is not int or size <= 0 or size > 2 * 1024**3
                or not isinstance(digest, str) or not HEX64.fullmatch(digest)):
            raise ValueError("INVALID_ELF_RECORD")
        path = root
        for part in parts:
            path = path / part
            if path.is_symlink():
                raise ValueError("SYMLINK_ELF_PATH")
        if not path.is_file() or path.stat().st_size != size:
            raise ValueError("ELF_SIZE_MISMATCH")
        h = hashlib.sha256()
        with path.open("rb") as f:
            head = f.read(20)
            h.update(head)
            for block in iter(lambda: f.read(1024 * 1024), b""):
                h.update(block)
        if (head[:6] != b"\x7fELF\x02\x01"
                or struct.unpack_from("<H", head, 18)[0] != 62):
            raise ValueError("WRONG_ELF_ABI")
        if h.hexdigest() != digest:
            raise ValueError("ELF_SHA256_MISMATCH")
        needed, paths = parse_dynamic(_readelf(path, "-d"))
        interpreter = parse_program_headers(_readelf(path, "-l"))
        report.append({
            "path": rel, "sha256": digest, "needed": needed,
            "interpreter": interpreter, "dynamic_search_paths": paths,
        })
    if not report or len(report) != manifest.get("elf_x86_64_files"):
        raise ValueError("ELF_COUNT_MISMATCH")
    needed_all = sorted({n for item in report for n in item["needed"]})
    return {
        "schema": "kernix.wine-linux-x64-elf-dependencies.v1",
        "source": manifest["source"],
        "upstream_commit": manifest.get("upstream_commit"),
        "host": manifest["host"],
        "elf_files_audited": len(report),
        "needed_sonames": needed_all,
        "not_named_in_staged_files": sorted(set(needed_all) - bundled),
        "interpreters": sorted({i["interpreter"] for i in report if i["interpreter"]}),
        "files": sorted(report, key=lambda item: item["path"]),
        "sha256_verified": True,
        "rootfs_dependency_resolution_tested": False,
        "fex_arm64_tested": False,
        "android_bionic_compatible": False,
        "windows_game_tested": False,
        "note": "Static Linux x86_64 ELF dependencies only. SONAME filename matching is a hint, not proof of guest rootfs resolution.",
    }


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--stage", required=True)
    p.add_argument("--manifest", required=True)
    a = p.parse_args()
    print(json.dumps(audit(a.stage, json.loads(Path(a.manifest).read_text())), indent=2))
