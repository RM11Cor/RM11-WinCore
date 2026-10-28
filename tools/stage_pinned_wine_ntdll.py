#!/usr/bin/env python3
"""Repair missing APK-native Wine 11 ntdll from signed SHA-pinned Wine bundle.

The same ntdll bytes were previously used by RM11 v2.4.19; the new source
builder accidentally staged only launcher/server/Wine ZIP, omitting ntdll ELF.
Never patch game assets, overwrite app/user Wine prefix, or rebuild Wine.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

NTDLL_MEMBER = "lib/wine/aarch64-unix/ntdll.so"
NTDLL_DEST = "libwine_ntdll.so"
MAX_NTDLL = 40 * 1024 * 1024
MIN_NTDLL = 100_000
ANDROID_SYSTEM = {
    "libc.so", "libdl.so", "libm.so", "liblog.so", "libandroid.so",
    "libz.so", "libEGL.so", "libGLESv2.so", "libvulkan.so",
    "libstdc++.so", "libatomic.so", "libOpenSLES.so",
    "libjnigraphics.so", "libmediandk.so", "libaaudio.so",
}
NEEDED_RE = re.compile(r"\(NEEDED\).*Shared library: \[([^\]]+)\]")


def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_elf(data):
    if not (MIN_NTDLL <= len(data) <= MAX_NTDLL):
        raise ValueError("PINNED_WINE_NTDLL_SIZE_INVALID")
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01" or data[16:20] != b"\x03\x00\xb7\x00":
        raise ValueError("PINNED_WINE_NTDLL_NOT_AARCH64_ET_DYN")
    return hashlib.sha256(data).hexdigest()


def checked_read(z, name):
    if z.namelist().count(name) != 1:
        raise ValueError("PINNED_WINE_ENTRY_MISSING_OR_DUPLICATED:" + name)
    item = z.getinfo(name)
    if item.is_dir() or item.file_size <= 0 or item.file_size > MAX_NTDLL:
        raise ValueError("PINNED_WINE_ENTRY_SIZE_OR_TYPE_INVALID:" + name)
    if (item.external_attr >> 16) & 0o170000 == 0o120000:
        raise ValueError("PINNED_WINE_ENTRY_SYMLINK_REJECTED:" + name)
    data = z.read(name)
    if len(data) != item.file_size:
        raise ValueError("PINNED_WINE_ENTRY_TRUNCATED:" + name)
    return data


def stage(archive, legacy_report, outdir, expected_dir=None):
    archive, legacy_report, outdir = map(Path, (archive, legacy_report, outdir))
    evidence = json.loads(legacy_report.read_text(encoding="utf-8"))
    source = evidence["pinned_runtime_components"]["assets/runtime/rm11-wine-stack.zip"]
    if evidence.get("schema") != "rm11.engine.pinned-legacy-runtime-stage.v1" or \
       evidence.get("baseline_apk_sha256") != \
            "1f6c511e6949080e9ec41b6b08ae724cccc49d5c10491db16db9bb32371e34e8" or \
       sha256_file(archive) != source["sha256"]:
        raise ValueError("PINNED_WINE_STACK_IDENTITY_MISMATCH")
    outdir.mkdir(parents=True, exist_ok=True)
    if outdir.is_symlink():
        raise ValueError("PINNED_NTDLL_TARGET_SYMLINK_DIR")
    if expected_dir is not None and outdir.resolve() != Path(expected_dir).resolve():
        raise ValueError("PINNED_NTDLL_OUTDIR_NOT_EXPECTED")
    target = outdir / NTDLL_DEST
    if target.exists() or target.is_symlink():
        raise ValueError("PINNED_NTDLL_TARGET_ALREADY_EXISTS")
    with zipfile.ZipFile(archive) as z:
        data = checked_read(z, NTDLL_MEMBER)
        digest = check_elf(data)
    fd, temp = tempfile.mkstemp(prefix=".rm11-ntdll-", dir=outdir)
    try:
        with os.fdopen(fd, "wb") as w:
            w.write(data)
            w.flush()
            os.fsync(w.fileno())
        os.replace(temp, target)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    if sha256_file(target) != digest:
        raise ValueError("PINNED_NTDLL_COPY_SHA_MISMATCH")
    return {"schema": "rm11.signed-native-ntdll-repair.v1",
            "apk_path": "lib/arm64-v8a/libwine_ntdll.so",
            "signed_source": "SHA256_PINNED_V4_0_89_RUNTIME_ZIP",
            "runtime_member": NTDLL_MEMBER,
            "sha256": digest, "size_bytes": len(data),
            "wine_prefix_mutated": False, "engine_activation": False}


def audit_elf(target, report):
    target = Path(target)
    dynamic = subprocess.run(["readelf", "-dW", str(target)],
                             capture_output=True, text=True, check=True).stdout
    symbols = subprocess.run(["readelf", "-WsW", str(target)],
                             capture_output=True, text=True, check=True).stdout
    if not re.search(r"\b__wine_main\b", symbols):
        raise ValueError("PINNED_NTDLL_WINE_MAIN_SYMBOL_MISSING")
    needed = sorted(set(NEEDED_RE.findall(dynamic)))
    unknown = [lib for lib in needed if lib not in ANDROID_SYSTEM]
    if unknown:
        raise ValueError("PINNED_NTDLL_UNSTAGED_NON_SYSTEM_NEEDED:" + ",".join(unknown))
    report["elf_symbol_wine_main"] = True
    report["needed_android_system_libraries"] = needed
    return report


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--wine-stack", type=Path, required=True)
    p.add_argument("--legacy-report", type=Path, required=True)
    p.add_argument("--outdir", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    args = p.parse_args()
    result = stage(args.wine_stack, args.legacy_report, args.outdir)
    result = audit_elf(args.outdir / NTDLL_DEST, result)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("RM11_SIGNED_APK_NATIVE_NTDLL_FROM_PINNED_WINE_STACK_VERIFIED", result["sha256"])


if __name__ == "__main__":
    main()
