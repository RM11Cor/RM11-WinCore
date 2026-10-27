#!/usr/bin/env python3
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from verify_adrenotools_hooks import HOOKS, verify


class AdrenoToolsElfTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.libs = self.root / "libs"
        self.needs = self.root / "needs"
        self.libs.mkdir()
        self.needs.mkdir()
        for name in HOOKS:
            data = bytearray(4096)
            data[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<HH", data, 16, 3, 183)
            (self.libs / name).write_bytes(data)
            (self.needs / (name + ".needed")).write_text(
                "(NEEDED) Shared library: [libc.so]\n"
                "(NEEDED) Shared library: [libdl.so]\n")

    def tearDown(self):
        self.tmp.cleanup()

    def test_android_static_only_and_device_unverified(self):
        r = verify(self.libs, self.needs)
        self.assertEqual(len(r["binaries"]), 5)
        self.assertFalse(r["wine_child_namespace_integration_verified"])
        self.assertFalse(r["safe_to_publish_apk"])

    def test_glibc_or_private_hal_rejected(self):
        p = self.needs / (HOOKS[0] + ".needed")
        p.write_text(p.read_text() + "(NEEDED) Shared library: [libhardware.so]\n")
        with self.assertRaisesRegex(ValueError, "PRIVATE_OR_GLIBC"):
            verify(self.libs, self.needs)

    def test_wrong_elf_machine_rejected(self):
        p = self.libs / HOOKS[2]
        data = bytearray(p.read_bytes())
        struct.pack_into("<H", data, 18, 62)
        p.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "NOT_AARCH64_DYN"):
            verify(self.libs, self.needs)


if __name__ == "__main__":
    unittest.main()
