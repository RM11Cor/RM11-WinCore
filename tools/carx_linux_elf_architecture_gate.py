#!/usr/bin/env python3
"""Read-only CarX Street official Linux depot ELF architecture and ABI audit.

Uses only small ELF64 headers, program headers, and bounded DT_NEEDED names
from user-owned original files. No proprietary game code executes or leaves
the device. ELF/AArch64 alone is NOT Android/Bionic compatibility proof.
"""
from __future__ import annotations
import argparse
import json
import struct
from pathlib import Path
from typing import Any

SCHEMA = "rm11carx.linux-elf-arm64-original-abi-feasibility-gate.v1"
MAX_FILE_BYTES = 1_073_741_824
MAX_PROGRAM_HEADERS = 512
MAX_PROGRAM_HEADER_BYTES = 131_072
MAX_DYNAMIC_BYTES = 131_072
MAX_DYLIB_NAMES = 256
MAX_SONAME_LENGTH = 256

EM_AARCH64 = 183
EM_X86_64 = 62
EM_ARM = 40
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_STRSZ = 10
DT_RPATH = 15
DT_RUNPATH = 29

class FormatError(Exception):
    pass

def need(test: bool, reason: str) -> None:
    if not test:
        raise FormatError(reason)

def machine_name(mach: int) -> str:
    return {EM_AARCH64: "AArch64", EM_X86_64: "x86_64",
            EM_ARM: "ARM32"}.get(mach, f"other_{mach}")

def ascii_z(data: bytes, maximum: int = MAX_SONAME_LENGTH) -> str:
    end = data.find(b"\x00")
    need(0 < end <= maximum, "dependency string missing bounded NUL")
    word = data[:end]
    need(all(32 <= x <= 126 for x in word), "non-printable dynamic dependency")
    return word.decode("ascii")

def inspect_file(path: Path) -> dict[str, Any]:
    need(path.is_file() and not path.is_symlink(),
         "require regular owned ELF file, no symlinks")
    length = path.stat().st_size
    need(64 <= length <= MAX_FILE_BYTES, "invalid ELF file length")
    with path.open("rb") as f:
        head = f.read(64)
        need(len(head) == 64 and head[:4] == b"\x7fELF",
             "not a genuine ELF header")
        need(head[4] == 2, "only 64-bit ELF is supported")
        need(head[5] in (1, 2), "invalid ELF endian byte")
        need(head[6] == 1, "invalid ELF version")
        endian = "<" if head[5] == 1 else ">"
        # e_ident[0:16], type, machine, version, entry, phoff, shoff,
        # flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx
        (elf_type, machine, version, entry, phoff, shoff,
         flags, ehsize, phentsize, phnum, shentsize, shnum,
         shstrndx) = struct.unpack_from(endian+"HHIQQQIHHHHHH", head, 16)
        need(ehsize == 64 and version == 1, "invalid ELF64 header size/version")
        need(1 <= phnum <= MAX_PROGRAM_HEADERS and phentsize == 56,
             "unsupported or unbounded ELF64 program-header table")
        need(phoff >= 64 and phoff + phnum * phentsize <= length and
             phnum * phentsize <= MAX_PROGRAM_HEADER_BYTES,
             "program headers beyond real file")
        f.seek(phoff)
        raw = f.read(phnum * phentsize)
        need(len(raw) == phnum * phentsize,
             "truncated ELF64 program header bytes")
        loads: list[tuple[int,int,int]] = []
        dynamic: tuple[int,int] | None = None
        interp: tuple[int,int] | None = None
        for i in range(phnum):
            ptype, pflags, p_off, vaddr, paddr, filesz, memsz, align = \
                struct.unpack_from(endian+"IIQQQQQQ", raw, i * phentsize)
            need(p_off <= length and filesz <= length - p_off,
                 "ELF program segment extends past file")
            if ptype == PT_LOAD:
                loads.append((vaddr, p_off, filesz))
            elif ptype == PT_DYNAMIC:
                need(dynamic is None, "multiple conflicting PT_DYNAMIC ranges")
                dynamic = (p_off, filesz)
            elif ptype == PT_INTERP:
                need(interp is None, "multiple PT_INTERP ranges")
                interp = (p_off, filesz)
        interpreter = ""
        if interp:
            off, size = interp
            need(2 <= size <= 4096,
                 "unbounded ELF runtime interpreter")
            f.seek(off)
            interpreter = ascii_z(f.read(size), max(0, min(4095, size-1)))
        libs: list[str] = []
        rpaths: list[str] = []
        if dynamic:
            off, size = dynamic
            need(size <= MAX_DYNAMIC_BYTES and size % 16 == 0,
                 "invalid or unbounded ELF64 dynamic table")
            f.seek(off)
            rawdyn = f.read(size)
            need(len(rawdyn) == size, "truncated PT_DYNAMIC contents")
            needed_offsets: list[int] = []
            rpath_offsets: list[int] = []
            string_addr: int | None = None
            string_size: int | None = None
            for i in range(0, len(rawdyn), 16):
                tag, value = struct.unpack_from(endian+"QQ", rawdyn, i)
                if tag == DT_NULL:
                    break
                if tag == DT_NEEDED:
                    need(len(needed_offsets) < MAX_DYLIB_NAMES,
                         "too many ELF DT_NEEDED dependencies")
                    needed_offsets.append(value)
                elif tag in (DT_RPATH, DT_RUNPATH):
                    rpath_offsets.append(value)
                elif tag == DT_STRTAB:
                    string_addr = value
                elif tag == DT_STRSZ:
                    string_size = value
            if needed_offsets or rpath_offsets:
                need(string_addr is not None and string_size is not None
                     and 0 < string_size <= MAX_DYNAMIC_BYTES,
                     "cannot resolve bounded ELF string-table address")
                source_offset = None
                for vaddr, fileoff, filesz in loads:
                    if vaddr <= string_addr and string_addr - vaddr < filesz:
                        source_offset = fileoff + string_addr - vaddr
                        break
                need(source_offset is not None and
                     source_offset + string_size <= length,
                     "DT_STRTAB not backed by real PT_LOAD bytes")
                f.seek(source_offset)
                strings = f.read(string_size)
                need(len(strings) == string_size, "truncated ELF dynamic strings")
                for val in needed_offsets + rpath_offsets:
                    need(val < len(strings), "ELF dependency outside string table")
                    string = ascii_z(strings[val:])
                    if val in needed_offsets:
                        libs.append(string)
                    else:
                        rpaths.append(string)
        is_arm64 = machine == EM_AARCH64
        android_like_sonames = {"libandroid.so", "liblog.so",
                                "libc++_shared.so"}
        linux_glibc = any(x in libs for x in ("libc.so.6", "libm.so.6",
                                               "libpthread.so.0",
                                               "libdl.so.2", "libstdc++.so.6"))
        return {
            "file_size": length,
            "elf64": True,
            "cpu_architecture": machine_name(machine),
            "machine_code": machine,
            "elf_type": elf_type,
            "endianness": "little" if endian == "<" else "big",
            "interpreter": interpreter,
            "shared_library_names": libs[:MAX_DYLIB_NAMES],
            "runpaths": rpaths[:24],
            "glibc_or_gnucxx_dependency_detected": linux_glibc,
            "android_library_dependency_hints": [
                x for x in libs if x in android_like_sonames],
            "original_linux_aarch64_machine_code_present": is_arm64,
            "android_bionic_abi_verified": False,
            "android_dlopen_succeeded": False,
            "original_carx_game_code_executed_on_android": False,
        }

def inspect_directory(root: Path) -> dict[str, Any]:
    # The Linux depot is structured differently from Windows and macOS.
    candidates = [
        ("game_il2cpp", "GameAssembly.so"),
        ("unity_engine", "UnityPlayer.so"),
        ("game_launcher", "CarX Street.x86_64"),
        ("eac_launcher", "eac_launcher"),
        ("steam_sdk", "libsteam_api.so"),
        ("eos_sdk", "libEOSSDK-Linux-Shipping.so"),
    ]
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "probe_scope": "read-only original ELF64 headers, Linux dependencies",
        "files": {},
        "original_linux_files_available": False,
        "linux_arm64_game_logic_and_unity_engine_both_proven": False,
        "original_android_game_logic_present": False,
        "original_game_frame_presented": False,
        "no_original_game_execution_in_inspector": True,
    }
    for key, relative in candidates:
        source = root / relative
        if not source.is_file() or source.is_symlink():
            report["files"][key] = {
                "relative_path": relative, "present": False}
            continue
        try:
            report["files"][key] = {
                "relative_path": relative, **inspect_file(source)}
        except (FormatError, OSError, ValueError, struct.error) as e:
            report["files"][key] = {
                "relative_path": relative, "elf64": False,
                "validation_error": str(e)[:150]}
    a = report["files"]["game_il2cpp"]
    b = report["files"]["unity_engine"]
    report["original_linux_files_available"] = bool(a.get("elf64") and b.get("elf64"))
    report["linux_arm64_game_logic_and_unity_engine_both_proven"] = bool(
        a.get("original_linux_aarch64_machine_code_present") and
        b.get("original_linux_aarch64_machine_code_present"))
    report["android_game_abi_and_native_code_verified"] = False
    report["next_gate"] = (
        "An ELF source file can still be Linux-x86_64 or Linux-glibc-specific. "
        "Only a licensed genuine Android ELF/AArch64/Bionic CarX engine+game build "
        "and Android assets close this native port gate."
    )
    return report

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("user_owned_official_linux_carx_directory", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if not args.user_owned_official_linux_carx_directory.is_dir():
        parser.error("Specify a local original game directory")
    report = inspect_directory(args.user_owned_official_linux_carx_directory)
    raw = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.out:
        args.out.write_text(raw, encoding="utf-8")
    else:
        print(raw)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
