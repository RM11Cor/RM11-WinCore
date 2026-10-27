#!/usr/bin/env python3
"""Pure host tests for actual signed ELF, final hybrid PE and CHPE metadata."""
import io
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from engine_abi_audit import (
    PE_AMD64, PE_ARM64EC, PE_ARM64, audit, read_elf_header, read_pe_header
)
from pe_chpe import inspect_arm64ec


def make_elf(machine=183):
    data = bytearray(64)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<HH", data, 16, 3, machine)
    return bytes(data)


def make_pe(machine=PE_ARM64):
    data = bytearray(512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", data, 0x84, machine)
    struct.pack_into("<H", data, 0x98, 0x20B)
    return bytes(data)


def make_linked_arm64ec_image(with_chpe=True):
    """Final hybrid image has AMD64 machine; CHPE load config defines ABI."""
    data = bytearray(0x1200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", data, 0x84, PE_AMD64)
    struct.pack_into("<H", data, 0x86, 1)  # section count
    struct.pack_into("<H", data, 0x94, 0xF0)  # optional header bytes
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<Q", data, opt + 24, 0x180000000)
    struct.pack_into("<I", data, opt + 108, 16)
    struct.pack_into("<II", data, opt + 112 + 80, 0x1100, 0x140)
    section = opt + 0xF0
    data[section:section + 6] = b".rdata"
    struct.pack_into("<IIII", data, section + 8,
                     0x1000, 0x1000, 0x1000, 0x200)
    # load configuration RVA 0x1100 -> file offset 0x300
    struct.pack_into("<I", data, 0x300, 0x140)
    if with_chpe:
        struct.pack_into("<Q", data, 0x300 + 0xC8, 0x180001200)
        # CHPE metadata RVA 0x1200 -> file offset 0x400
        struct.pack_into("<I", data, 0x400, 2)
    return bytes(data)


def apk_at(path, native_machine=183, hybrid_chpe=True):
    with io.BytesIO() as nested:
        with zipfile.ZipFile(nested, "w") as engine:
            engine.writestr("opt/wine/lib/wine/aarch64-windows/libarm64ecfex.dll",
                            make_linked_arm64ec_image(hybrid_chpe))
            engine.writestr("opt/wine/lib/wine/aarch64-windows/libwow64fex.dll",
                            make_pe(PE_ARM64))
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

    def test_amd64_coff_header_alone_is_not_chpe_proof(self):
        info = read_pe_header(make_pe(PE_AMD64), {PE_AMD64})
        self.assertTrue(info["abi_ok"])  # generic PE format, not hybrid ABI
        self.assertFalse(inspect_arm64ec(make_pe(PE_AMD64))["abi_ok"])

    def test_reject_magic_only_broken_image(self):
        self.assertFalse(read_pe_header(b"MZ" + b"\x00" * 62)["abi_ok"])
        self.assertFalse(read_elf_header(b"\x7fELF")["abi_ok"])

    def test_linked_amd64_with_chpe_can_be_valid_arm64ec(self):
        good = inspect_arm64ec(make_linked_arm64ec_image(True))
        bad = inspect_arm64ec(make_linked_arm64ec_image(False))
        self.assertTrue(good["abi_ok"])
        self.assertEqual(good["chpe_version"], 2)
        self.assertFalse(bad["abi_ok"])

    def test_valid_machine_header_does_not_prove_game_rendering(self):
        with tempfile.TemporaryDirectory() as temp:
            apk = Path(temp) / "test.apk"
            apk_at(apk)
            report = audit(apk)
            self.assertEqual(report["native_abi_closure"], "STRUCTURALLY_COMPATIBLE")
            self.assertEqual(report["guest_translation_abi"], "STRUCTURALLY_COMPATIBLE")
            self.assertEqual(report["guest_fex_pe"]["arm64ec_module"]["machine"], PE_AMD64)
            self.assertEqual(report["guest_fex_pe"]["arm64ec_module"]["chpe_metadata"], "PRESENT")
            self.assertEqual(report["game_rendering_claim"], "UNVERIFIED")
            self.assertFalse(report["would_publish_apk"])

    def test_hybrid_without_chpe_cannot_certify_translation(self):
        with tempfile.TemporaryDirectory() as temp:
            apk = Path(temp) / "test.apk"
            apk_at(apk, hybrid_chpe=False)
            report = audit(apk)
            self.assertEqual(report["guest_translation_abi"], "BLOCKED")

    def test_native_machine_mismatch_blocks(self):
        with tempfile.TemporaryDirectory() as temp:
            apk = Path(temp) / "test.apk"
            apk_at(apk, native_machine=62)
            self.assertEqual(audit(apk)["native_abi_closure"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
