"""No real game or native binary execution: synthetic ELF / source-lock tests."""
import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from kernix_native_artifact_gate import attest_arm64_elf, validate_source_lock

SOURCE = {
    "schema": "kernix.upstream-source-lock.v1",
    "recorded_utc": "2026-11-02",
    "note": "Only source pins, not binaries",
    "components": [
        {"kind": "fex", "repository": "FEX-Emu/FEX",
         "git_commit": "02e24ca5c01ed0c864466ed573db347336f70170",
         "license_spdx": "MIT", "android_binary_built": False},
        {"kind": "dxvk", "repository": "doitsujin/dxvk",
         "git_commit": "f863776806824486d709fee16ea619c03e22def4",
         "license_spdx": "Zlib", "android_binary_built": False},
        {"kind": "vkd3d", "repository": "HansKristian-Work/vkd3d-proton",
         "git_commit": "15dd1ee7864ef83c4ef835c72720effe60a10899",
         "license_spdx": "LGPL-2.1", "android_binary_built": False},
    ]
}

def synthetic_elf(machine=183, phoffset=64, segment_size=16):
    data = bytearray(256)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", data, 16, 3, machine, 1)
    struct.pack_into("<Q", data, 32, phoffset)
    struct.pack_into("<HHH", data, 52, 64, 56, 1)
    if phoffset == 64:
        struct.pack_into("<I", data, 64, 1)
        struct.pack_into("<Q", data, 72, 128)
        struct.pack_into("<Q", data, 96, segment_size)
        struct.pack_into("<Q", data, 104, segment_size)
    return bytes(data)

class NativeArtifactGateTests(unittest.TestCase):
    def test_locked_original_sources(self):
        self.assertEqual(set(validate_source_lock(SOURCE)), {"fex", "dxvk", "vkd3d"})

    def test_unpinned_source_and_forged_build_claim_rejected(self):
        for field, value in [
            ("git_commit", "main"),
            ("repository", "unknown/fex"),
            ("license_spdx", "UNKNOWN"),
            ("android_binary_built", True),
        ]:
            import copy
            bad = copy.deepcopy(SOURCE)
            bad["components"][0][field] = value
            with self.assertRaises(ValueError):
                validate_source_lock(bad)

    def test_duplicate_source_rejected(self):
        import copy
        bad = copy.deepcopy(SOURCE)
        bad["components"][1] = bad["components"][0]
        with self.assertRaises(ValueError):
            validate_source_lock(bad)

    def test_arm64_elf_header_and_digest(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/"synthetic.so"
            raw = synthetic_elf()
            path.write_bytes(raw)
            result = attest_arm64_elf(path, hashlib.sha256(raw).hexdigest())
            self.assertEqual(result["host_abi"], "arm64")
            self.assertTrue(result["binary_sha256_verified"])
            self.assertFalse(result["android_bionic_link_verified"])
            self.assertFalse(result["device_qualified"])
            self.assertFalse(result["installed_in_kernix"])

    def test_wrong_abi_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/"x86_64.so"
            raw = synthetic_elf(machine=62)
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "NOT_ARM64_NATIVE_ELF"):
                attest_arm64_elf(path, hashlib.sha256(raw).hexdigest())

    def test_digest_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/"native.so"
            path.write_bytes(synthetic_elf())
            with self.assertRaisesRegex(ValueError, "SHA256_MISMATCH"):
                attest_arm64_elf(path, "0"*64)

    def test_invalid_program_header_bounds_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/"bad.so"
            raw = synthetic_elf(phoffset=1024)
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "ELF_PROGRAM_HEADERS_OUT_OF_BOUNDS"):
                attest_arm64_elf(path, hashlib.sha256(raw).hexdigest())

    def test_oversized_load_segment_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/"bad.so"
            raw = synthetic_elf(segment_size=4096)
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "INVALID_ELF_LOAD_SEGMENT"):
                attest_arm64_elf(path, hashlib.sha256(raw).hexdigest())

    def test_elf_without_load_segment_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/"no-load.so"
            raw = bytearray(synthetic_elf())
            struct.pack_into("<I", raw, 64, 0)  # PT_NULL, not PT_LOAD
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "ELF_WITHOUT_LOAD_SEGMENT"):
                attest_arm64_elf(path, hashlib.sha256(raw).hexdigest())

    def test_invalid_program_header_entry_size_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/"bad-phentsize.so"
            raw = bytearray(synthetic_elf())
            struct.pack_into("<H", raw, 54, 32)  # ELF64 requires 56 bytes
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "INVALID_ELF_PROGRAM_HEADERS"):
                attest_arm64_elf(path, hashlib.sha256(raw).hexdigest())

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            real = Path(d)/"real.so"
            raw = synthetic_elf()
            real.write_bytes(raw)
            alias = Path(d)/"alias.so"
            alias.symlink_to(real)
            with self.assertRaisesRegex(ValueError, "MISSING_OR_SYMLINKED_ELF"):
                attest_arm64_elf(alias, hashlib.sha256(raw).hexdigest())

if __name__ == "__main__":
    unittest.main()
