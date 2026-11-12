#!/usr/bin/env python3
"""Synthetic-only negative controls for the real local Mach-O header parser.

NOT original CarX binary evidence. It rejects fabricated ARCH claims and
keeps macOS ARM64 distinct from Android ELF/Bionic.
"""
from __future__ import annotations
import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "gate", ROOT / "tools/carx_macho_architecture_gate.py")
gate = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(gate)

CPU_ARM64 = 0x0100000c
CPU_X86_64 = 0x01000007

def dylib_cmd(name: str) -> bytes:
    raw = name.encode("ascii") + b"\x00"
    padded = raw + b"\0" * ((8 - len(raw) % 8) % 8)
    cmdsize = 24 + len(padded)
    return struct.pack("<6I", 0xc, cmdsize, 24, 0, 0, 0) + padded

def rpath_cmd(name: str) -> bytes:
    raw = name.encode("ascii") + b"\0"
    padded = raw + b"\0" * ((8 - len(raw) % 8) % 8)
    return struct.pack("<3I", 0x8000001c, 12 + len(padded), 12) + padded

def build_cmd(platform: int = 1) -> bytes:
    return struct.pack("<6I", 0x32, 24, platform, 0x000D0000,
                       0x000F0000, 0)

def thin(cpu=CPU_ARM64, filetype=6, version=1) -> bytes:
    commands = [dylib_cmd("/System/Library/Frameworks/Metal.framework/Metal"),
                dylib_cmd("@rpath/libCarX.bundle"),
                rpath_cmd("@executable_path/../Frameworks"),
                build_cmd(version)]
    body = b"".join(commands)
    return (b"\xcf\xfa\xed\xfe" +
            struct.pack("<6I", cpu, 0, filetype, len(commands), len(body), 0) +
            struct.pack("<I", 0) + body + bytes(128))

def fat32(cpu_a=CPU_X86_64, cpu_b=CPU_ARM64) -> bytes:
    a, b = thin(cpu_a), thin(cpu_b)
    first = 48
    second = first + len(a)
    return (b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) +
            struct.pack(">5I", cpu_a, 0, first, len(a), 0) +
            struct.pack(">5I", cpu_b, 0, second, len(b), 0) + a + b)

class GateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def store(self, raw: bytes, name="binary") -> Path:
        p = self.root / name
        p.write_bytes(raw)
        return p

    def test_native_mac_arm64_is_not_android_elf(self):
        result = gate.inspect_file(self.store(thin()))
        self.assertTrue(result["native_macos_arm64_code_present"])
        self.assertFalse(result["android_elf_bionic_code_present"])
        self.assertFalse(result["slices"][0]["android_direct_load_supported"])
        self.assertEqual(result["slices"][0]["platforms_declared"], ["macOS"])
        self.assertEqual(result["slices"][0]["platform_versions_declared"][0]["minimum_os"],"13.0.0")
        self.assertIn("Metal.framework",result["slices"][0]["apple_system_dependency_examples"][0])

    def test_thin_x86_is_not_native_android_arm64(self):
        result=gate.inspect_file(self.store(thin(cpu=CPU_X86_64)))
        self.assertFalse(result["native_macos_arm64_code_present"])
        self.assertEqual(result["architectures"], ["x86_64"])

    def test_fat_arm_and_x86_not_android_elf(self):
        result=gate.inspect_file(self.store(fat32()))
        self.assertEqual(result["architectures"], ["x86_64","ARM64"])
        self.assertTrue(result["native_macos_arm64_code_present"])
        self.assertFalse(result["android_elf_bionic_code_present"])

    def test_two_separate_native_mac_headers_are_still_not_port(self):
        paths=[
            ("CarX Street.app/Contents/Frameworks/GameAssembly.dylib",thin()),
            ("CarX Street.app/Contents/Frameworks/UnityPlayer.dylib",thin()),
        ]
        for rel,contents in paths:
            dst=self.root/rel
            dst.parent.mkdir(parents=True,exist_ok=True)
            dst.write_bytes(contents)
        report=gate.inspect_directory(self.root)
        self.assertTrue(report["has_mac_game_binaries"])
        self.assertTrue(report["mac_arm64_game_code_and_engine_headers_both_proven"])
        self.assertFalse(report["android_bionic_elf_compatible_game_logic_proven"])
        self.assertFalse(report["fully_native_android_game_port_proven"])
        self.assertFalse(report["original_game_scene_or_frame_rendered"])

    def test_only_game_assembly_is_insufficient(self):
        dst=self.root/"CarX Street.app/Contents/Frameworks/GameAssembly.dylib"
        dst.parent.mkdir(parents=True)
        dst.write_bytes(thin())
        report=gate.inspect_directory(self.root)
        self.assertFalse(report["mac_arm64_game_code_and_engine_headers_both_proven"])
        self.assertFalse(report["has_mac_game_binaries"])

    def test_wrong_elf_header_rejected(self):
        with self.assertRaises(gate.FormatError):
            gate.inspect_file(self.store(b"\x7fELF"+bytes(64)))

    def test_no_macho_magic_rejected(self):
        with self.assertRaises(gate.FormatError):
            gate.inspect_file(self.store(b"MZ"+bytes(64)))

    def test_truncated_thin_rejected(self):
        with self.assertRaises(gate.FormatError):
            gate.inspect_file(self.store(b"\xcf\xfa\xed\xfe" + bytes(4)))

    def test_thin_declared_command_exceeds_file_rejected(self):
        malformed = bytearray(thin())
        struct.pack_into("<I",malformed,20,200000)
        with self.assertRaises(gate.FormatError):
            gate.inspect_file(self.store(malformed))

    def test_fat_overlapping_header_rejected(self):
        bad = bytearray(fat32())
        struct.pack_into(">I",bad,16,8)
        with self.assertRaises(gate.FormatError):
            gate.inspect_file(self.store(bad))

    def test_fat_cpu_mismatch_rejected(self):
        bad = bytearray(fat32())
        struct.pack_into(">I",bad,8,CPU_ARM64)
        with self.assertRaises(gate.FormatError):
            gate.inspect_file(self.store(bad))

    def test_fat_truncated_table_rejected(self):
        with self.assertRaises(gate.FormatError):
            gate.inspect_file(self.store(b"\xca\xfe\xba\xbe"+struct.pack(">I",8)+bytes(64)))

    def test_fake_metal_loader_cannot_change_platform_proof(self):
        bad = thin(version=2)
        result = gate.inspect_file(self.store(bad))
        self.assertEqual(result["slices"][0]["platforms_declared"], ["iOS"])
        self.assertTrue(result["native_macos_arm64_code_present"])
        self.assertFalse(result["android_elf_bionic_code_present"])

    def test_reject_symlink(self):
        origin = self.store(thin())
        fake = self.root/"alias"
        fake.symlink_to(origin)
        with self.assertRaises(gate.FormatError):
            gate.inspect_file(fake)

    def test_absent_original_user_mac_files_are_not_fake_success(self):
        report=gate.inspect_directory(self.root)
        self.assertFalse(report["has_mac_game_binaries"])
        self.assertFalse(report["mac_arm64_game_code_and_engine_headers_both_proven"])
        self.assertFalse(report["fully_native_android_game_port_proven"])

if __name__=="__main__":
    unittest.main(verbosity=2)
