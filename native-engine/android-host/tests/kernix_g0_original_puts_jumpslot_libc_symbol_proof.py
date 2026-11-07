#!/usr/bin/env python3
"""Strict original GNU puts JUMP_SLOT post-write symbol provenance on Linux ARM64.

Source-pinned ELF + real read-only hardware-watch evidence only. Does NOT
prove the guest writer RIP, all main relocations, RELRO sealing or Android.
"""
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path

ROOT = Path("dist/original-source-pinned-root")
DIST = Path("dist")
MAIN = ROOT / "bin/kernix-g2e-dynamic-guest"
LIBC = ROOT / "lib/x86_64-linux-gnu/libc.so.6"
INPUT = DIST / "original-puts-jumpslot-hardware-writer-evidence.json"
LOG = DIST / "original-main-puts-jumpslot-watch.log"
OUTPUT = DIST / "original-puts-jumpslot-source-versioned-libc-symbol-evidence.json"
MAIN_SHA = "9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412"
LIBC_SHA = "7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906"


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def elf_rx_source_bytes(data, vma, count):
    require(data[:6] == bytes.fromhex("7f454c460201")
            and struct.unpack_from("<H", data, 18)[0] == 62,
            "source libc is not original x86_64 ELF64")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    entry_size, n = struct.unpack_from("<HH", data, 54)
    require(entry_size == 56 and 1 <= n <= 64
            and phoff + entry_size * n <= len(data),
            "source libc PT_LOAD header bounds invalid")
    candidate = []
    for i in range(n):
        kind, flags, off, va, _, filebytes, membytes, _ = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + i * entry_size)
        if (kind == 1 and flags & 5 == 5 and flags & 2 == 0
                and va <= vma and vma - va + count <= filebytes
                and off <= len(data) and filebytes <= len(data) - off):
            candidate.append(off + vma - va)
    require(len(candidate) == 1, "original libc symbol must map to one RX file range")
    location = candidate[0]
    bytes_at_symbol = data[location:location + count]
    require(bytes_at_symbol != bytes(count), "original libc source symbol code empty")
    return location, bytes_at_symbol


def symbols():
    main_rels = subprocess.run(
        ["readelf", "-W", "-r", str(MAIN)],
        text=True, capture_output=True, check=True, timeout=15).stdout
    candidates = [line for line in main_rels.splitlines()
                  if "R_X86_64_JUMP_SLOT" in line]
    require(len(candidates) == 1, "source main expected one JUMP_SLOT")
    row = candidates[0].split()
    require(int(row[0], 16) == 0x3FD0, "puts source GOT target changed")
    imports = [v for v in row if v.startswith("puts@")]
    require(imports == ["puts@GLIBC_2.2.5"],
            "original source main puts imported symbol version changed")
    libc_dyn = subprocess.run(
        ["readelf", "-W", "--dyn-syms", str(LIBC)],
        text=True, capture_output=True, check=True, timeout=15).stdout
    regex = (r"(?m)^\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+"
             r"FUNC\s+GLOBAL\s+DEFAULT\s+(\S+)\s+"
             r"puts@@GLIBC_2\.2\.5\s*$")
    matches = list(re.finditer(regex, libc_dyn))
    require(len(matches) == 1, "expected one default original libc puts@@GLIBC_2.2.5")
    vma = int(matches[0].group(1), 16)
    size = int(matches[0].group(2), 10)
    require(matches[0].group(3) != "UND" and size > 0,
            "original libc puts export not a defined callable function")
    return imports[0], "puts@@GLIBC_2.2.5", vma, size


def allowed(expected_vma, actual_offset, source_import, libc_export, in_rx):
    return (expected_vma == actual_offset == 0x87BC0
            and source_import == "puts@GLIBC_2.2.5"
            and libc_export == "puts@@GLIBC_2.2.5"
            and bool(in_rx))


def main():
    bmain = MAIN.read_bytes()
    blibc = LIBC.read_bytes()
    require(len(bmain) == 15976
            and hashlib.sha256(bmain).hexdigest() == MAIN_SHA,
            "main ELF not SHA256 pinned")
    require(len(blibc) == 2118168
            and hashlib.sha256(blibc).hexdigest() == LIBC_SHA,
            "libc ELF not SHA256 pinned")
    witness = json.loads(INPUT.read_text())
    require(witness.get("original_puts_JUMP_SLOT_hardware_write_observed") is True,
            "source-only GOT does not establish real hardware write")
    require(witness.get("source_JUMP_SLOT_symbol") == "puts"
            and witness.get("source_bind_now_requested") is True
            and witness.get("source_JUMP_SLOT_guest_target") == "0x800003fd0"
            and witness.get("source_file_backed_GOT_initial") == "0x1030",
            "original puts PLT source evidence inconsistent")
    live = int(witness["original_puts_JUMP_SLOT_postwrite_value"], 16)
    require(live == 0x804087BC0,
            "real puts hardware pointer unexpectedly changed")

    log = LOG.read_text(errors="replace")
    base_log = re.search(
        r"KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_LIBC_MMAP9_LARGE_PRIVATE_RO_SOURCE_"
        r"\d+_REQUEST_0x[0-9a-f]+_FD100_OFFSET0_WX_SAFE_EOF_GUARD_PASS "
        r"guest_base=([0-9a-fA-F]+)", log)
    require(base_log is not None, "real original guest libc load base not witnessed")
    libc_base = int(base_log.group(1), 16)
    require(libc_base == 0x804000000 and libc_base < live,
            "source guest libc mapped outside original witnessed load base")
    offset = live - libc_base

    imported, exported, va, symbol_bytes = symbols()
    file_off, code = elf_rx_source_bytes(blibc, va, 12)
    require(symbol_bytes >= 12, "original libc puts function too short")
    require(allowed(va, offset, imported, exported, [file_off]),
            "guest puts GOT value not source-correct versioned libc export")
    negatives = [
        (va + 1, offset, imported, exported, [file_off]),
        (va, offset + 8, imported, exported, [file_off]),
        (va, offset, "puts@GLIBC_2.34", exported, [file_off]),
        (va, offset, imported, "puts@@GLIBC_2.34", [file_off]),
        (va, offset, "putchar@GLIBC_2.2.5", exported, [file_off]),
        (va, offset, imported, exported, []),
    ]
    require(all(not allowed(*case) for case in negatives),
            "corrupt original source/version/pointer evidence accepted")

    evidence = dict(witness)
    evidence.update({
        "schema": "kernix.g0.original-puts-jumpslot-source-libc-symbol.v1",
        "source_original_libc_sha256": LIBC_SHA,
        "original_main_puts_imported_symbol_version": imported,
        "original_libc_versioned_export": exported,
        "original_libc_export_st_value": hex(va),
        "original_guest_libc_witness_load_base": hex(libc_base),
        "original_source_puts_guest_pointer_offset": hex(offset),
        "original_libc_puts_RX_source_file_offset": hex(file_off),
        "original_libc_puts_source_12bytes": code.hex(),
        "original_puts_versioned_libc_symbol_verified": True,
        "exact_original_guest_writer_RIP_proven": False,
        "all_original_main_relocations_proven": False,
        "original_main_RELRO_sealed": False,
        "android_bionic_or_gameplay_proven": False,
    })
    OUTPUT.write_text(json.dumps(evidence, indent=2) + "\n")
    print("KERNIX_G0_PUTS_JUMP_SLOT_REAL_GOT_POINTER_MATCHES_SHA_PINNED_VERSIONED_LIBC_SOURCE_PASS"
          + " guest_pointer=" + hex(live) + " puts_st_value=" + hex(va)
          + " version=GLIBC_2.2.5")
    print("KERNIX_G0_PUTS_JUMP_SLOT_LIBC_SOURCE_SIX_NEGATIVE_CONTROLS_PASS")
    print("KERNIX_G0_PUTS_JUMP_SLOT_GUEST_RIP_AND_FULL_RELRO_CLOSURE_NOT_PROVEN")


if __name__ == "__main__":
    main()
