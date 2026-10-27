#!/usr/bin/env python3
"""Pure host tests; no assumption that existing RM11 game rendering works."""
import io
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from engine_abi_audit import (
    PE_AMD64, PE_ARM64EC, audit, read_elf_header, read_pe_header
)


def make_elf(machine=183):
    data = bytearray(64)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<HH", data, 16, 3, machine)
    return bytes(data)


def make_pe(machine=PE_ARM64EC):
    data = bytearray(512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", data, 0x84, machine)
    struct.pack_into("<H", data, 0x98, 0x20B)
    return bytes(data)


def apk_at(path, native_machine=183, guest_machine=PE_ARM64EC):
    with io.BytesIO() as nested:
        with zipfile.ZipFile(nested, "w") as engine:
            engine.writestr("opt/wine/lib/wine/aarch64-windows/libarm64ecfex.dll",
                            make_pe(guest_machine))
            engine.writestr("opt/wine/lib/wine/aarch64-windows/libwow64fex.dll",
                            make_pe(PE_ARM64EC))
        with zipfile.ZipFile(path, "w") as apk:
            for name in ("libwineprobe.so", "libwineserverrm11.so",
                         "libwine_winex11.so", "libXlorie.so"):
                apk.writestr("lib/arm64-v8a/" + name, make_elf(native_machine))
            apk.writestr("assets/runtime/rm11-wine-stack.zip", nested.getvalue())


class AbiTests(unittest.TestCase):
    def test_reject_x86_64_elf_named_like_aarch64(self):
        info = read_elf_header(make_elf(62))
        self.assertFalse(info["abi_ok"])
        self.assertEqual(info["machine"], 62)

    def test_reject_amd64_pe_masquerading_as_arm64ec(self):
        info = read_pe_header(make_pe(PE_AMD64), {PE_ARM64EC})
        self.assertFalse(info["abi_ok"])
        self.assertEqual(info["architecture"], "AMD64")

    def test_reject_magic_only_broken_image(self):
        self.assertFalse(read_pe_header(b"MZ" + b"\x00" * 62)["abi_ok"])
        self.assertFalse(read_elf_header(b"\x7fELF")["abi_ok"])

    def test_valid_host_architecture_is_not_proof_of_rendering(self):
        with tempfile.TemporaryDirectory() as temp:
            apk = Path(temp) / "test.apk"
            apk_at(apk)
            report = audit(apk)
            self.assertEqual(report["native_abi_closure"], "STRUCTURALLY_COMPATIBLE")
            self.assertEqual(report["guest_translation_abi"], "STRUCTURALLY_COMPATIBLE")
            self.assertEqual(report["game_rendering_claim"], "UNVERIFIED")
            self.assertFalse(report["would_publish_apk"])

    def test_mismatched_guest_abi_rejects_coherent_runtime(self):
        with tempfile.TemporaryDirectory() as temp:
            apk = Path(temp) / "test.apk"
            apk_at(apk, guest_machine=PE_AMD64)
            report = audit(apk)
            self.assertEqual(report["native_abi_closure"], "STRUCTURALLY_COMPATIBLE")
            self.assertEqual(report["guest_translation_abi"], "BLOCKED")

    def test_mismatched_native_machine_rejects(self):
        with tempfile.TemporaryDirectory() as temp:
            apk = Path(temp) / "test.apk"
            apk_at(apk, native_machine=62)
            report = audit(apk)
            self.assertEqual(report["native_abi_closure"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
