#!/usr/bin/env python3
"""Compile static Linux x86_64 guest-rootfs requirements from a Wine ELF audit.

This does not install a rootfs, execute FEX, or verify Android compatibility.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

COMMIT = "db11d0fe6a169c457e23d007e20404643d067aa8"
PREFIX = "opt/kernix-wine-linux-x64/"
HASH = re.compile(r"[0-9a-f]{64}\Z")
SONAME = re.compile(r"[A-Za-z0-9_.+@-]{1,200}\Z")


def compile_contract(report):
    if not isinstance(report, dict) or report.get("schema") != "kernix.wine-linux-x64-elf-dependencies.v1":
        raise ValueError("INVALID_SCHEMA")
    if (report.get("source") != "wine-mirror/wine" or report.get("upstream_commit") != COMMIT
            or report.get("host") != "ubuntu-24.04-x86_64-glibc"
            or report.get("sha256_verified") is not True):
        raise ValueError("UNVERIFIED_PROVENANCE")
    for key in ("rootfs_dependency_resolution_tested", "fex_arm64_tested",
                "android_bionic_compatible", "windows_game_tested"):
        if report.get(key) is not False:
            raise ValueError("UNPROVEN_RUNTIME_CLAIM")
    files, count = report.get("files"), report.get("elf_files_audited")
    if (not isinstance(files, list) or type(count) is not int
            or not 0 < count <= 10000 or len(files) != count):
        raise ValueError("INVALID_ELF_COUNT")
    names, loaders, paths, search_evidence = set(), set(), set(), []
    for item in files:
        if not isinstance(item, dict):
            raise ValueError("INVALID_ELF_RECORD")
        path, digest, needed = item.get("path"), item.get("sha256"), item.get("needed")
        if (not isinstance(path, str) or not path.startswith(PREFIX)
                or len(path) > 512 or path in paths
                or any(p in ("", ".", "..") for p in path.split("/"))
                or not isinstance(digest, str) or not HASH.fullmatch(digest)):
            raise ValueError("INVALID_ELF_RECORD")
        paths.add(path)
        if (not isinstance(needed, list) or len(needed) > 100
                or any(not isinstance(n, str) or not SONAME.fullmatch(n) for n in needed)
                or needed != sorted(set(needed))):
            raise ValueError("INVALID_ELF_NEEDED")
        names.update(needed)
        interpreter = item.get("interpreter")
        if interpreter is not None:
            if (not isinstance(interpreter, str) or not interpreter.startswith("/")
                    or len(interpreter) > 256 or "\x00" in interpreter
                    or any(p in ("", ".", "..") for p in interpreter[1:].split("/"))):
                raise ValueError("INVALID_INTERPRETER")
            loaders.add(interpreter)
        search = item.get("dynamic_search_paths")
        if (not isinstance(search, dict) or any(k not in ("RPATH", "RUNPATH")
                or not isinstance(v, str) or len(v) > 4096 or "\x00" in v
                for k, v in search.items())):
            raise ValueError("INVALID_SEARCH_PATH")
        if search:
            search_evidence.append({"path": path, "dynamic_search_paths": dict(sorted(search.items()))})
    external = report.get("not_named_in_staged_files")
    if (report.get("needed_sonames") != sorted(names)
            or not isinstance(external, list) or len(external) > 10000
            or any(not isinstance(n, str) or not SONAME.fullmatch(n) for n in external)
            or external != sorted(set(external))
            or any(n not in names for n in external)
            or report.get("interpreters") != sorted(loaders)):
        raise ValueError("INCONSISTENT_DEPENDENCIES")
    digest = hashlib.sha256(json.dumps(report, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "schema": "kernix.wine-linux-x64-guest-rootfs-contract.v1",
        "wine_source": "wine-mirror/wine", "wine_source_commit": COMMIT,
        "dependency_report_sha256": digest, "wine_elf_files_audited": count,
        "required_guest_interpreters": sorted(loaders),
        "external_guest_soname_candidates": external,
        "staged_soname_name_candidates": sorted(names - set(external)),
        "elf_dynamic_search_path_evidence": sorted(search_evidence, key=lambda item: item["path"]),
        "host_abi": "linux-x86_64-glibc",
        "guest_rootfs_pinned": False, "guest_rootfs_resolved": False,
        "fex_arm64_tested": False, "android_bionic_compatible": False,
        "windows_game_tested": False, "upstream_wine_license_must_be_preserved": True,
        "note": "Static SONAME filenames are not proof of ELF loader resolution, symbol versions or FEX execution.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    print(json.dumps(compile_contract(json.loads(Path(args.report).read_text())), indent=2))
