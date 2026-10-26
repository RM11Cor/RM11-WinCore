#!/usr/bin/env python3
"""Offline ABI contract between original Wine ARM64 win32u and NDK FreeType.

Input comes solely from the SHA256-pinned signed RM11 APK. No native code is
run or dlopen()ed. This cannot prove that fonts render or that wineserver stays
alive; it only checks whether original Wine's stored FT_* function names are
exported by the native FreeType ELF shipped in the same APK.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


def arm64_elf(content: bytes, label: str) -> None:
    if len(content) < 4096 or content[:4] != b"\x7fELF" or content[4] != 2:
        raise ValueError(label + " is not 64-bit ELF")
    if int.from_bytes(content[18:20], "little") != 183:
        raise ValueError(label + " is not ELF AArch64")


def expected_wine_functions(data: bytes) -> list[str]:
    # Wine's dlsym lookup strings live as NUL-terminated FT_* names in ELF.
    names = set()
    for name in re.findall(rb"(?<![A-Za-z0-9_])(FT_[A-Za-z][A-Za-z0-9_]{2,})\x00", data):
        names.add(name.decode("ascii"))
    return sorted(names)


def elf_dynamic_exports(readelf: str, path: Path) -> list[str]:
    output = subprocess.check_output(
        [readelf, "--wide", "--dyn-syms", str(path)], text=True
    )
    exported = set()
    for line in output.splitlines():
        if not re.match(r"^\s*\d+:", line):
            continue
        columns = line.split()
        if len(columns) < 8:
            continue
        if columns[6] == "UND":
            continue
        name = columns[7].split("@", 1)[0]
        if re.fullmatch(r"FT_[A-Za-z][A-Za-z0-9_]*", name):
            exported.add(name)
    return sorted(exported)


def inspect(wine_path: Path, font_path: Path, readelf: str) -> dict:
    wine = wine_path.read_bytes()
    font = font_path.read_bytes()
    arm64_elf(wine, "Wine win32u")
    arm64_elf(font, "FreeType")
    requested = expected_wine_functions(wine)
    exported = elf_dynamic_exports(readelf, font_path)
    missing = sorted(set(requested).difference(exported))
    vital = {"FT_Init_FreeType", "FT_Load_Glyph", "FT_Render_Glyph"}
    unclassified = len(requested) < 12 or not vital.issubset(set(requested))
    return {
        "schema": "rm11.wine.freetype.abi-audit.v1",
        "scope": "STATIC_READ_ONLY_SIGNED_APK_NO_RUNTIME_DLOPEN",
        "wine_win32u_sha256": hashlib.sha256(wine).hexdigest(),
        "signed_native_freetype_sha256": hashlib.sha256(font).hexdigest(),
        "wine_elf_machine": "AARCH64",
        "wine_freetype_soname_present": "libfreetype.so" if b"libfreetype.so\x00" in wine else
            ("libfreetype.so.6" if b"libfreetype.so.6\x00" in wine else "NOT_DETECTED"),
        "wine_ft_lookups_detected": len(requested),
        "freetype_ft_symbols_exported": len(exported),
        "wine_requested_ft_symbols": requested,
        "missing_ft_symbols": missing,
        "audit_result": "SOURCE_LOOKUPS_INSUFFICIENT" if unclassified else
            ("DYNAMIC_SYMBOL_GAP" if missing else "DYNAMIC_SYMBOL_NAMES_COVERED"),
        "font_pixels_verified": False,
        "native_linker_redirect_verified": False,
        "wine_server_stability_verified": False,
        "note": "Static symbol coverage does not determine actual dlopen, dlsym, ABI calling safety, FreeType initialization, or visual glyph rendering.",
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--wine", type=Path, required=True)
    p.add_argument("--font", type=Path, required=True)
    p.add_argument("--readelf", default="readelf")
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    result = inspect(args.wine, args.font, args.readelf)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("RM11_V442_FONT_ABI_AUDIT_RESULT", result["audit_result"])
    print("RM11_V442_WINE_FREETYPE_SONAME", result["wine_freetype_soname_present"])
    print("RM11_V442_REQUESTED_FT_COUNT", result["wine_ft_lookups_detected"])
    print("RM11_V442_MISSING_FT_FUNCTIONS", ",".join(result["missing_ft_symbols"]) or "NONE")
    print("RM11_V442_DOES_NOT_ACTIVATE_FREETYPE_OR_MODIFY_APK")


if __name__ == "__main__":
    main()
