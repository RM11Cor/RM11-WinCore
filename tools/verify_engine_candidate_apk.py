#!/usr/bin/env python3
"""Fail-closed packaging comparator for a non-distributed RM11 engine APK candidate.

The verified legacy APK must be byte-equivalent at the uncompressed entry
level after zipalign/apksigner, except the *single* new APK-native executable
and signing-only META-INF entries. No activity or original Wine resource can
be silently replaced. An internal signed candidate is never released here.
"""
import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path

ENGINE_PATH = "lib/arm64-v8a/librm11_engine_supervisor.so"
NATIVE_CRITICAL = (
    "lib/arm64-v8a/libwineprobe.so",
    "lib/arm64-v8a/libwineserverrm11.so",
    "lib/arm64-v8a/libwine_winex11.so",
    "lib/arm64-v8a/libXlorie.so",
    "assets/runtime/rm11-wine-stack.zip",
)
MAX_TOTAL_ENTRIES = 25000


def file_sha(path):
    with open(path, "rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def entry_sha(archive, name):
    digest = hashlib.sha256()
    with archive.open(name) as inp:
        for block in iter(lambda: inp.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def excluded_signature(name):
    return name.startswith("META-INF/") and (
        name.upper().endswith((".SF", ".RSA", ".DSA", ".EC"))
        or name.upper().startswith("META-INF/MANIFEST.MF")
    )


def analyze(baseline, candidate, new_library, abi_report=None):
    baseline = Path(baseline)
    candidate = Path(candidate)
    new_library = Path(new_library)
    digest_new = file_sha(new_library)
    with zipfile.ZipFile(baseline, "r") as old, \
            zipfile.ZipFile(candidate, "r") as built:
        old_entries = old.infolist()
        new_entries = built.infolist()
        if len(old_entries) > MAX_TOTAL_ENTRIES or len(new_entries) > MAX_TOTAL_ENTRIES:
            raise ValueError("APK_ENTRY_COUNT_EXCEEDS_LIMIT")
        original = {e.filename: e for e in old_entries if not excluded_signature(e.filename)}
        current = {e.filename: e for e in new_entries if not excluded_signature(e.filename)}
        if len(original) != len([e for e in old_entries if not excluded_signature(e.filename)]):
            raise ValueError("BASE_APK_DUPLICATE_ENTRY")
        if len(current) != len([e for e in new_entries if not excluded_signature(e.filename)]):
            raise ValueError("CANDIDATE_APK_DUPLICATE_ENTRY")
        if ENGINE_PATH in original:
            raise ValueError("PREEXISTING_ENGINE_EXECUTABLE_COLLISION")
        if set(current).difference(original) != {ENGINE_PATH}:
            raise ValueError("APK_CONTAINS_UNEXPECTED_ADDED_PATHS")
        if set(original).difference(current):
            raise ValueError("ORIGINAL_APK_RESOURCES_REMOVED")
        changed = []
        for name, old_meta in original.items():
            fresh = current[name]
            if old_meta.file_size != fresh.file_size or old_meta.CRC != fresh.CRC:
                changed.append(name)
        if changed:
            raise ValueError("ORIGINAL_APK_ENTRY_CONTENT_CHANGED:" + changed[0][:150])
        supervisor = current[ENGINE_PATH]
        if supervisor.compress_type != zipfile.ZIP_STORED:
            raise ValueError("ENGINE_NATIVE_LIB_IS_NOT_STORED")
        if supervisor.file_size < 4096 or supervisor.file_size > 16 * 1024 * 1024:
            raise ValueError("ENGINE_BINARY_SIZE_INVALID")
        if entry_sha(built, ENGINE_PATH) != digest_new:
            raise ValueError("ENGINE_NATIVE_BYTES_CHANGED_IN_PACKAGING")
        if any(name not in original for name in NATIVE_CRITICAL):
            raise ValueError("PINNED_LEGACY_WINE_COMPONENT_MISSING")
        critical_hashes = {}
        for name in NATIVE_CRITICAL:
            before = entry_sha(old, name)
            after = entry_sha(built, name)
            if before != after:
                raise ValueError("CRITICAL_WINE_RUNTIME_REPLACED")
            critical_hashes[name] = before
        # Don't try to treat preserved old app components as an integrated
        # replacement engine. The old Windows ELF/PE chain is not changed.
        result = {
            "schema": "rm11.engine.internal-apk-candidate.v1",
            "old_apk_sha256": file_sha(baseline),
            "candidate_apk_sha256": file_sha(candidate),
            "supervisor_apk_path": ENGINE_PATH,
            "supervisor_sha256": digest_new,
            "supervisor_zip_compression": "STORED",
            "original_resources_preserved": True,
            "original_resources_count": len(original),
            "original_critical_component_hashes": critical_hashes,
            "new_file_count": 1,
            "activation_flag": "OFF",
            "guest_rendered_frames": "UNVERIFIED",
            "android_native_supervisor_execution": "UNVERIFIED",
            "candidate_may_be_released": False,
        }
        if abi_report:
            details = json.loads(Path(abi_report).read_text(encoding="utf-8"))
            if (details.get("status") != "ELF_STRUCTURE_READY_FOR_ANDROID_DEVICE_PROOF"
                    or details.get("sha256") != digest_new
                    or details.get("safe_to_activate_engine") is not False):
                raise ValueError("ENGINE_ABI_OR_SHA_NOT_CERTIFIED_FOR_STATIC_PACKAGING")
        return result


def main():
    p = argparse.ArgumentParser()
    p.add_argument("legacy_apk")
    p.add_argument("candidate_apk")
    p.add_argument("native_library")
    p.add_argument("--abi-report")
    p.add_argument("--out")
    args = p.parse_args()
    result = analyze(args.legacy_apk, args.candidate_apk, args.native_library,
                     args.abi_report)
    output = json.dumps(result, sort_keys=True, indent=2) + "\n"
    print(output)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")


if __name__ == "__main__":
    main()
