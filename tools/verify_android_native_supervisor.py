#!/usr/bin/env python3
"""Static release gate for Android NDK-built PIE Wine native subreaper.

Signed APK packaging and execution on Android are NOT proven by this audit.
This checks the prospective ELF machine, interpreter and 16 KiB alignment.
Never execute untrusted binaries in CI or on the user's phone.
"""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

MAX_BYTES = 16 * 1024 * 1024
ELF64 = b"\x7fELF\x02\x01\x01"
PT_LOAD = 1
PT_INTERP = 3


def audit_bytes(data: bytes) -> dict:
    checks = {}
    if len(data) < 64 or data[:7] != ELF64:
        return {"status": "BLOCKED", "checks": {"elf64_le": False}}
    checks["elf64_le"] = True
    elf_type, machine = struct.unpack_from("<HH", data, 16)
    checks["pie_elf_type_dyn"] = elf_type == 3
    checks["machine_aarch64"] = machine == 183
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    checks["program_headers_bounded"] = (
        1 <= phnum <= 256 and phentsize >= 56
        and phoff >= 64 and phoff + phnum * phentsize <= len(data)
    )
    if not checks["program_headers_bounded"]:
        return {"status": "BLOCKED", "checks": checks}
    interpreter = None
    aligned_loads = 0
    load_segments = 0
    for i in range(phnum):
        offset = phoff + i * phentsize
        p_type = struct.unpack_from("<I", data, offset)[0]
        p_offset, p_filesz, p_align = struct.unpack_from("<QQQ", data, offset + 8)[0], \
            struct.unpack_from("<Q", data, offset + 32)[0], \
            struct.unpack_from("<Q", data, offset + 48)[0]
        if p_offset + p_filesz > len(data):
            checks["program_header_file_ranges"] = False
            return {"status": "BLOCKED", "checks": checks}
        if p_type == PT_INTERP:
            raw = data[p_offset:p_offset + p_filesz]
            try:
                interpreter = raw.rstrip(b"\x00").decode("ascii")
            except UnicodeError:
                interpreter = "INVALID"
        if p_type == PT_LOAD:
            load_segments += 1
            if p_align >= 16384 and (p_align & (p_align - 1)) == 0:
                aligned_loads += 1
    checks["program_header_file_ranges"] = True
    checks["bionic_dynamic_linker64"] = interpreter == "/system/bin/linker64"
    checks["load_segments_present"] = load_segments > 0
    checks["load_segments_16k_aligned"] = (
        load_segments > 0 and aligned_loads == load_segments
    )
    return {
        "status": "ELF_STRUCTURE_READY_FOR_ANDROID_DEVICE_PROOF"
        if all(checks.values()) else "BLOCKED",
        "checks": checks,
        "interpreter": interpreter,
        "load_segments": load_segments,
        "aligned_load_segments": aligned_loads,
    }


def audit(path: Path):
    path = Path(path)
    if not re.fullmatch(r"lib[a-z0-9_]+\.so", path.name):
        return {"status": "BLOCKED", "reason": "INVALID_APK_NATIVE_FILENAME"}
    if path.stat().st_size > MAX_BYTES:
        return {"status": "BLOCKED", "reason": "FILE_SIZE_EXCEEDS_STATIC_CHECK_LIMIT"}
    with path.open("rb") as f:
        content = f.read()
    result = audit_bytes(content)
    result["filename"] = path.name
    result["sha256"] = hashlib.sha256(content).hexdigest()
    result["android_executable_test"] = "NOT_PERFORMED"
    result["android_package_test"] = "NOT_PERFORMED"
    result["game_rendering_proof"] = "UNVERIFIED"
    result["safe_to_activate_engine"] = False
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("--out")
    args = parser.parse_args()
    result = audit(Path(args.binary))
    data = json.dumps(result, indent=2, sort_keys=True) + "\n"
    print(data)
    if args.out:
        Path(args.out).write_text(data, encoding="utf-8")
    if result["status"] != "ELF_STRUCTURE_READY_FOR_ANDROID_DEVICE_PROOF":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
