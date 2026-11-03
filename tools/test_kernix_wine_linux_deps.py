"""Synthetic regression tests; no real Wine, FEX or Android execution."""
import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from kernix_wine_linux_deps import audit, parse_dynamic, parse_program_headers

DYNAMIC = """
Dynamic section at offset 0x100 contains 3 entries:
 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]
 0x0000000000000001 (NEEDED) Shared library: [libwine.so.1]
 0x000000000000001d (RUNPATH) Library runpath: [$ORIGIN/../lib]
"""
PROGRAM = """
Program Headers:
  INTERP 0x000238 0x000238 0x000238
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
"""


def fixture(root):
    rel = "opt/kernix-wine-linux-x64/bin/wine"
    path = root / rel
    path.parent.mkdir(parents=True)
    payload = bytearray(64)
    payload[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", payload, 18, 62)
    path.write_bytes(payload)
    entry = {"path": rel, "kind": "elf-x86_64-linux", "size": len(payload),
             "sha256": hashlib.sha256(payload).hexdigest()}
    manifest = {
        "schema": "kernix.wine11-linux-x86_64-stage.v1",
        "source": "wine-mirror/wine", "host": "ubuntu-24.04-x86_64-glibc",
        "upstream_commit": "a" * 40, "android_bionic_compatible": False,
        "elf_x86_64_files": 1, "files": [entry],
    }
    return path, manifest


class WineDependencyAuditTests(unittest.TestCase):
    def test_readelf_needed_runpath(self):
        needed, paths = parse_dynamic(DYNAMIC)
        self.assertEqual(needed, ["libc.so.6", "libwine.so.1"])
        self.assertEqual(paths["RUNPATH"], "$ORIGIN/../lib")

    def test_malformed_needed_rejected(self):
        with self.assertRaisesRegex(ValueError, "INVALID_DT_NEEDED"):
            parse_dynamic("0x1 (NEEDED) Shared library: [/tmp/injected.so]")

    def test_interpreter_and_missing_interpreter(self):
        self.assertEqual(parse_program_headers(PROGRAM), "/lib64/ld-linux-x86-64.so.2")
        self.assertIsNone(parse_program_headers("Program Headers:\n  LOAD\n"))

    def test_broken_interp_rejected(self):
        with self.assertRaisesRegex(ValueError, "INVALID_PT_INTERP"):
            parse_program_headers("Program Headers:\n INTERP\n")

    def test_unsafe_interpreter_paths_rejected(self):
        for path in ("/lib64/../tmp/ld.so", "/lib64//ld.so",
                     "/lib64/./ld.so", "/lib64/ld\\evil.so", "/"):
            with self.subTest(path=path):
                with self.assertRaisesRegex(ValueError, "INVALID_PT_INTERP"):
                    parse_program_headers(
                        f"INTERP\\n[Requesting program interpreter: {path}]"
                    )

    def test_audit_hash_and_dependency_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _, manifest = fixture(root)
            with patch("kernix_wine_linux_deps._readelf",
                       side_effect=lambda path, flag: DYNAMIC if flag == "-d" else PROGRAM):
                result = audit(root, manifest)
            self.assertEqual(result["elf_files_audited"], 1)
            self.assertIn("libc.so.6", result["not_named_in_staged_files"])
            self.assertEqual(result["interpreters"], ["/lib64/ld-linux-x86-64.so.2"])
            self.assertFalse(result["rootfs_dependency_resolution_tested"])
            self.assertFalse(result["android_bionic_compatible"])

    def test_changed_bytes_rejected_before_readelf(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            path, manifest = fixture(root)
            payload = bytearray(path.read_bytes())
            payload[-1] ^= 1
            path.write_bytes(payload)
            with patch("kernix_wine_linux_deps._readelf") as reader:
                with self.assertRaisesRegex(ValueError, "ELF_SHA256_MISMATCH"):
                    audit(root, manifest)
                reader.assert_not_called()

    def test_wrong_machine_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            path, manifest = fixture(root)
            payload = bytearray(path.read_bytes())
            struct.pack_into("<H", payload, 18, 183)
            path.write_bytes(payload)
            manifest["files"][0]["sha256"] = hashlib.sha256(payload).hexdigest()
            with self.assertRaisesRegex(ValueError, "WRONG_ELF_ABI"):
                audit(root, manifest)

    def test_symlinked_elf_path_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            path, manifest = fixture(root)
            target = root / "other"
            path.rename(target)
            path.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "SYMLINK_ELF_PATH"):
                audit(root, manifest)


if __name__ == "__main__":
    unittest.main()
