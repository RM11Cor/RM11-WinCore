#!/usr/bin/env python3
"""CarX Street macOS Apple-Silicon native-code viability gate (stdlib only).

Inspect user-owned local binaries, not Steam downloads. No extraction,
decryption, code-signature bypass, memory dumping, or executable launch.

Read just bounded Mach-O/fat headers and Mach-O load commands to establish:
* actual architecture (ARM64 / x86-64), Mach-O file type and slice offsets;
* loaded Mach-O dependent libraries and macOS version/platform tags;
* hard distinction between macOS ARM64 Mach-O and Android ARM64 ELF/Bionic.

"arm64" on Apple Silicon is NOT proof an Android .so/game binary exists.
"""
from __future__ import annotations
import argparse
import json
import os
import re
import struct
from pathlib import Path
from typing import Any

SCHEMA = "rm11carx.macos-macho-arm64-source-executability-gate.v1"
MAX_FILE_BYTES = 1_073_741_824
MAX_FAT_ARCH = 64
MAX_CMDS = 8192
MAX_CMDS_BYTES = 1_048_576
MAX_PATHS = 64

# Mach-O CPU constants (not bytes), using unsigned representations
CPU_ARM64 = 0x0100000C
CPU_X86_64 = 0x01000007
CPU_X86 = 7
CPU_ARM = 12
LC_REQ_DYLD = 0x80000000
DYLIB_CMDS = {0xC, 0xD, 0x18, 0x1F, 0x20, 0x23, 0x80000018,
              0x8000001F, 0x80000023}
RPATH_CMDS = {0x1C, 0x8000001C}
LC_BUILD_VERSION = 0x32
LC_VERSION_MIN_MACOSX = 0x24
TYPE_NAMES = {1: "MH_OBJECT", 2: "MH_EXECUTE", 6: "MH_DYLIB", 8: "MH_BUNDLE"}
PLATFORMS = {1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS",
             6: "macCatalyst", 7: "iOSSimulator", 8: "tvOSSimulator"}

MACH_MAGIC = {
    b"\xcf\xfa\xed\xfe": ("<", True),
    b"\xfe\xed\xfa\xcf": (">", True),
    b"\xce\xfa\xed\xfe": ("<", False),
    b"\xfe\xed\xfa\xce": (">", False),
}
FAT_MAGIC = {
    b"\xca\xfe\xba\xbe": (">", False),
    b"\xbe\xba\xfe\xca": ("<", False),
    b"\xca\xfe\xba\xbf": (">", True),
    b"\xbf\xba\xfe\xca": ("<", True),
}

class FormatError(Exception):
    pass

def require(condition: bool, reason: str) -> None:
    if not condition:
        raise FormatError(reason)

def cpu_name(v: int) -> str:
    return {
        CPU_ARM64: "ARM64",
        CPU_X86_64: "x86_64",
        CPU_X86: "x86",
        CPU_ARM: "ARM32",
    }.get(v, f"other_0x{v:x}")

def ver(v: int) -> str:
    return f"{v >> 16}.{(v >> 8) & 255}.{v & 255}"

def printable_load_string(command: bytes, offset: int) -> str:
    if offset < 8 or offset >= len(command):
        return ""
    value = command[offset:offset + 512].split(b"\0", 1)[0]
    if not value:
        return ""
    # Refrain from exporting arbitrary bytes, control characters, secrets.
    if any(c < 32 or c >= 127 for c in value):
        return "[unprintable or non-ascii dylib dependency]"
    return value.decode("ascii", "strict")

def parse_thin(f, start: int, size: int, file_size: int) -> dict[str, Any]:
    require(0 <= start <= file_size and 32 <= size <= file_size - start,
            "invalid Mach-O slice offset and size")
    f.seek(start)
    magic = f.read(4)
    require(magic in MACH_MAGIC, "slice missing Mach-O magic")
    endian, is64 = MACH_MAGIC[magic]
    header_len = 32 if is64 else 28
    f.seek(start)
    header = f.read(header_len)
    require(len(header) == header_len, "truncated Mach-O header")
    _, cpu, cpu_subtype, file_type, ncmds, cmds_size, flags = struct.unpack(
        endian + "7I", header[:28])
    require(0 <= ncmds <= MAX_CMDS and 0 <= cmds_size <= MAX_CMDS_BYTES,
            "unbounded Mach-O load command count/bytes")
    require(header_len + cmds_size <= size, "load commands extend beyond Mach-O slice")
    f.seek(start + header_len)
    cmds = f.read(cmds_size)
    require(len(cmds) == cmds_size, "truncated Mach-O load commands")
    libs, rpaths, platforms, min_versions = [], [], [], []
    offset = 0
    for _ in range(ncmds):
        require(offset + 8 <= len(cmds), "truncated load command header")
        kind, cmdsize = struct.unpack_from(endian + "2I", cmds, offset)
        require(cmdsize >= 8 and offset + cmdsize <= len(cmds),
                "invalid Mach-O load command size")
        command = cmds[offset:offset + cmdsize]
        base_kind = kind & ~LC_REQ_DYLD
        if kind in DYLIB_CMDS or base_kind in DYLIB_CMDS:
            if cmdsize >= 24:
                string_offset = struct.unpack_from(endian + "I", command, 8)[0]
                dependency = printable_load_string(command, string_offset)
                if dependency and len(libs) < 96:
                    libs.append(dependency)
        if kind in RPATH_CMDS or base_kind in RPATH_CMDS:
            if cmdsize >= 12:
                string_offset = struct.unpack_from(endian + "I", command, 8)[0]
                value = printable_load_string(command, string_offset)
                if value and len(rpaths) < 32:
                    rpaths.append(value)
        if base_kind == LC_BUILD_VERSION:
            require(cmdsize >= 24, "truncated Mach-O build_version")
            platform, minimum, sdk = struct.unpack_from(endian + "3I", command, 8)
            platforms.append(PLATFORMS.get(platform, f"other_{platform}"))
            min_versions.append({"minimum_os": ver(minimum), "sdk": ver(sdk)})
        if base_kind == LC_VERSION_MIN_MACOSX:
            require(cmdsize >= 16, "truncated minimum macOS version command")
            minimum, sdk = struct.unpack_from(endian + "2I", command, 8)
            platforms.append("macOS")
            min_versions.append({"minimum_os": ver(minimum), "sdk": ver(sdk)})
        offset += cmdsize
    require(offset <= len(cmds), "load-command cursor overflow")
    # If platform metadata is absent, don't invent a macOS min version.
    apple_deps = sorted({
        x for x in libs if x.startswith("/System/Library/") or
        x.startswith("/usr/lib/") or "Metal.framework" in x or
        "AppKit.framework" in x or "Foundation.framework" in x
    })
    return {
        "architecture": cpu_name(cpu),
        "cpu_type": f"0x{cpu:x}",
        "cpu_subtype": f"0x{cpu_subtype:x}",
        "mach_o_64_bit": is64,
        "file_type": TYPE_NAMES.get(file_type, f"other_{file_type}"),
        "slice_offset": start,
        "slice_size": size,
        "load_commands": ncmds,
        "platforms_declared": sorted(set(platforms)),
        "platform_versions_declared": min_versions[:8],
        "dynamic_library_dependencies": libs[:96],
        "apple_system_dependency_count": len(apple_deps),
        "apple_system_dependency_examples": apple_deps[:16],
        "rpaths": rpaths,
        "android_elf_bionic_binary": False,
        "android_direct_load_supported": False,
    }

def inspect_file(file: Path) -> dict[str, Any]:
    if not file.is_file() or file.is_symlink():
        raise FormatError("path must be a regular local non-symlink file")
    size = file.stat().st_size
    require(28 <= size <= MAX_FILE_BYTES,
            "file not within bounded Mach-O inspection size")
    with file.open("rb") as f:
        magic = f.read(4)
        if magic in MACH_MAGIC:
            slices = [parse_thin(f, 0, size, size)]
        elif magic in FAT_MAGIC:
            endian, is64 = FAT_MAGIC[magic]
            f.seek(4)
            raw = f.read(4)
            require(len(raw) == 4, "truncated fat Mach-O header")
            narch = struct.unpack(endian + "I", raw)[0]
            require(1 <= narch <= MAX_FAT_ARCH, "invalid fat Mach-O architecture count")
            stride = 32 if is64 else 20
            f.seek(8)
            headers = f.read(narch * stride)
            require(len(headers) == narch * stride, "truncated universal file slice table")
            slices = []
            for i in range(narch):
                if is64:
                    cpu, subtype, off, archsize, align, reserved = struct.unpack_from(
                        endian + "2I2Q2I", headers, i * stride)
                else:
                    cpu, subtype, off, archsize, align = struct.unpack_from(
                        endian + "5I", headers, i * stride)
                require(off >= 8 + narch * stride and 28 <= archsize <= size - off,
                        "universal architecture points outside real file")
                part = parse_thin(f, off, archsize, size)
                require(part["cpu_type"] == f"0x{cpu:x}",
                        "universal slice CPU type mismatch")
                slices.append(part)
        else:
            raise FormatError("not a Mach-O or universal Mach-O file")
    return {
        "file_size": size,
        "mach_o_valid": True,
        "architectures": [s["architecture"] for s in slices],
        "native_macos_arm64_code_present": any(s["architecture"] == "ARM64" for s in slices),
        "architectures_are_real_header_evidence": True,
        "android_elf_bionic_code_present": False,
        "slices": slices,
    }

def inspect_directory(root: Path) -> dict[str, Any]:
    targets = [
        ("game_il2cpp", "CarX Street.app/Contents/Frameworks/GameAssembly.dylib"),
        ("unity_engine", "CarX Street.app/Contents/Frameworks/UnityPlayer.dylib"),
        ("game_launcher", "CarX Street.app/Contents/MacOS/CarX Street"),
        ("native_plugin", "CarX Street.app/Contents/PlugIns/NativeCarX.bundle/Contents/MacOS/NativeCarX"),
        ("steam_sdk", "CarX Street.app/Contents/PlugIns/libsteam_api.dylib"),
        ("eos_sdk", "CarX Street.app/Contents/PlugIns/libEOSSDK-Mac-Shipping.dylib"),
    ]
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "input_type": "user_supplied_game_binary_directory",
        "inspects_original_binary_headers_only": True,
        "downloads_original_game": False,
        "executes_original_game_code": False,
        "has_mac_game_binaries": False,
        "fully_native_android_game_port_proven": False,
        "source_category": "UNVERIFIED_LOCAL_USER_SAMPLES",
        "files": {},
    }
    for key, rel in targets:
        file = root / rel
        if file.exists() and file.is_file() and not file.is_symlink():
            try:
                report["files"][key] = {"relative_path": rel, **inspect_file(file)}
            except (FormatError, OSError, ValueError, struct.error) as e:
                report["files"][key] = {
                    "relative_path": rel,
                    "mach_o_valid": False,
                    "validation_error": str(e)[:150],
                }
        else:
            report["files"][key] = {
                "relative_path": rel, "present": False, "architectures": []
            }
    game = report["files"]["game_il2cpp"]
    engine = report["files"]["unity_engine"]
    report["has_mac_game_binaries"] = (
        bool(game.get("mach_o_valid")) and bool(engine.get("mach_o_valid"))
    )
    report["mac_arm64_game_code_and_engine_headers_both_proven"] = (
        bool(game.get("native_macos_arm64_code_present")) and
        bool(engine.get("native_macos_arm64_code_present"))
    )
    report["mac_os_specific_abi_requires_port_or_runtime_bridge"] = True
    report["apple_metal_to_android_vulkan_compatibility_proven"] = False
    report["android_bionic_elf_compatible_game_logic_proven"] = False
    report["original_game_scene_or_frame_rendered"] = False
    report["next_gate"] = (
        "Even confirmed ARM64 Mach-O GameAssembly + UnityPlayer cannot be dlopen'd "
        "as Android ELF. Evaluate authorized rebuild/source, macOS platform ABI, "
        "Apple frameworks and Metal renderer requirements. No native PC port claim."
    )
    return report

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("local_user_owned_mac_game_folder", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    root: Path = args.local_user_owned_mac_game_folder
    if not root.is_dir() or root.is_symlink():
        parser.error("Supply an existing locally owned and unmodified Steam macOS game folder")
    report = inspect_directory(root)
    encoded = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.out:
        args.out.write_text(encoded, encoding="utf-8")
    else:
        print(encoded)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
