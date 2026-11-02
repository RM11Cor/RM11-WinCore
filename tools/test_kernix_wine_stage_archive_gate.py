"""Synthetic archive tests: never treat these as actual Wine or Android runtime."""
import copy
import hashlib
import io
import struct
import tarfile
import tempfile
import unittest
from pathlib import Path
from kernix_wine_stage_archive_gate import verify, PREFIX, LICENSE


def elf():
    data = bytearray(128)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<H", data, 18, 62)
    return bytes(data)


def pe(machine=0x8664, offset=64):
    data = bytearray(max(256, offset + 6))
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, offset)
    data[offset:offset + 4] = b"PE\x00\x00"
    struct.pack_into("<H", data, offset + 4, machine)
    return bytes(data)


def fixture(directory, *, bad_archive=None, bad_link=None):
    data = {
        PREFIX + "bin/wine": elf(),
        PREFIX + "lib/wine/x86_64-windows/dxgi.dll": pe(),
        PREFIX + "lib/wine/x86_64-windows/long-header.dll": pe(offset=8192),
        PREFIX + "share/wine/mz-not-pe.dat": b"MZ" + bytes(96),
        PREFIX + "share/wine/winmd/windows.applicationmodel.winmd": pe(0x14c),
        LICENSE: b"upstream license fixture\n",
    }
    manifest = {
        "schema": "kernix.wine11-linux-x86_64-stage.v1",
        "source": "wine-mirror/wine", "upstream_commit": "a" * 40,
        "host": "ubuntu-24.04-x86_64-glibc",
        "android_bionic_compatible": False, "is_android_package": False,
        "fex_arm64_tested": False, "windows_game_tested": False,
        "elf_x86_64_files": 1, "pe_x86_64_files": 2,
        "winmd_metadata_files": 1, "files": [],
    }
    for path, contents in data.items():
        kind = ("winmd-metadata-x86" if path.endswith(".winmd")
                else "elf-x86_64-linux" if contents.startswith(b"\x7fELF")
                else "pe-x86_64-windows" if path.endswith(".dll") else "data")
        manifest["files"].append({"path": path, "kind": kind, "size": len(contents),
                                  "sha256": hashlib.sha256(contents).hexdigest()})
    link = PREFIX + "bin/wine-link"
    manifest["files"].append({"path": link, "kind": "symlink", "target": "wine"})
    archive = Path(directory) / "wine.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        for path, contents in data.items():
            payload = contents
            if bad_archive == path:
                payload = b"X" + contents[1:]
            info = tarfile.TarInfo(path)
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
        info = tarfile.TarInfo(link)
        info.type = tarfile.SYMTYPE
        info.linkname = bad_link if bad_link is not None else "wine"
        tf.addfile(info)
    return archive, manifest


class WineStageGateTests(unittest.TestCase):
    def test_valid_synthetic_archive(self):
        with tempfile.TemporaryDirectory() as d:
            archive, manifest = fixture(d)
            result = verify(archive, manifest)
            self.assertTrue(result["license_in_archive"])
            self.assertEqual(result["winmd_metadata_x86"], 1)
            self.assertEqual(result["pe_x86_64"], 2)
            self.assertTrue(result["all_regular_files_sha256_verified"])
            self.assertFalse(result["android_bionic_compatible"])
            self.assertFalse(result["runtime_tested"])

    def test_long_pe_offset_and_mz_non_pe_are_classified_correctly(self):
        with tempfile.TemporaryDirectory() as d:
            archive, manifest = fixture(d)
            result = verify(archive, manifest)
            self.assertEqual(result["pe_x86_64"], 2)
            self.assertTrue(any(e["kind"] == "data" and e["path"].endswith("mz-not-pe.dat")
                                for e in manifest["files"]))

    def test_long_header_pe_cannot_be_relabelled_data(self):
        with tempfile.TemporaryDirectory() as d:
            archive, manifest = fixture(d)
            entry = next(e for e in manifest["files"] if e["path"].endswith("long-header.dll"))
            entry["kind"] = "data"
            with self.assertRaisesRegex(ValueError, "ARCHIVE_ABI_OR_KIND_MISMATCH"):
                verify(archive, manifest)

    def test_changed_bytes_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            archive, manifest = fixture(d, bad_archive=PREFIX + "bin/wine")
            with self.assertRaisesRegex(ValueError, "ARCHIVE_SHA256_MISMATCH"):
                verify(archive, manifest)

    def test_missing_license_record_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            archive, manifest = fixture(d)
            manifest["files"] = [f for f in manifest["files"] if f["path"] != LICENSE]
            with self.assertRaisesRegex(ValueError, "UPSTREAM_LICENSE_MISSING_FROM_RUNTIME"):
                verify(archive, manifest)

    def test_modified_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            archive, manifest = fixture(d, bad_link="../../outside")
            with self.assertRaisesRegex(ValueError, "SYMLINK_TARGET_MISMATCH"):
                verify(archive, manifest)

    def test_wrong_abi_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            archive, manifest = fixture(d)
            entry = next(f for f in manifest["files"] if f["path"].endswith("/bin/wine"))
            entry["kind"] = "pe-x86_64-windows"
            with self.assertRaisesRegex(ValueError, "ARCHIVE_ABI_OR_KIND_MISMATCH"):
                verify(archive, manifest)

    def test_false_android_claim_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            archive, manifest = fixture(d)
            manifest["android_bionic_compatible"] = True
            with self.assertRaisesRegex(ValueError, "INVALID_STAGE_PROVENANCE_OR_CLAIMS"):
                verify(archive, manifest)

    def test_winmd_metadata_cannot_be_mislabeled_as_executable_pe(self):
        with tempfile.TemporaryDirectory() as d:
            archive, manifest = fixture(d)
            entry = next(f for f in manifest["files"] if f["path"].endswith(".winmd"))
            entry["kind"] = "pe-x86_64-windows"
            with self.assertRaisesRegex(ValueError, "ARCHIVE_ABI_OR_KIND_MISMATCH"):
                verify(archive, manifest)

    def test_wrong_source_revision_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            archive, manifest = fixture(d)
            manifest["upstream_commit"] = "main"
            with self.assertRaisesRegex(ValueError, "INVALID_STAGE_PROVENANCE_OR_CLAIMS"):
                verify(archive, manifest)


if __name__ == "__main__":
    unittest.main()
