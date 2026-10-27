#!/usr/bin/env python3
"""Negative regression tests: native supervisor is the ONLY allowed APK diff."""
import tempfile
import unittest
import zipfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from verify_engine_candidate_apk import (
    ENGINE_PATH, NATIVE_CRITICAL, analyze
)


def write_apk(path, native_blob=None, mutated=None, extras=None,
              compression=zipfile.ZIP_STORED):
    with zipfile.ZipFile(path, "w") as apk:
        for name in NATIVE_CRITICAL:
            blob = ("pinned-" + name).encode()
            if name == mutated:
                blob = b"altered-component"
            apk.writestr(name, blob)
        apk.writestr("AndroidManifest.xml", b"binary-manifest")
        if native_blob is not None:
            apk.writestr(ENGINE_PATH, native_blob, compress_type=compression)
        for name in extras or []:
            apk.writestr(name, b"unexpected")


class CandidatePackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.original = root / "baseline.apk"
        self.candidate = root / "candidate.apk"
        self.native = root / "librm11_engine_supervisor.so"
        self.native.write_bytes(b"\x7fELF" + b"A" * 6000)
        write_apk(self.original)

    def tearDown(self):
        self.temp.cleanup()

    def test_one_unmodified_extra_stored_elf_is_staging_only(self):
        write_apk(self.candidate, self.native.read_bytes())
        audit = analyze(self.original, self.candidate, self.native)
        self.assertTrue(audit["original_resources_preserved"])
        self.assertEqual(audit["new_file_count"], 1)
        self.assertFalse(audit["candidate_may_be_released"])
        self.assertEqual(audit["activation_flag"], "OFF")
        self.assertEqual(audit["android_native_supervisor_execution"], "UNVERIFIED")

    def test_replacement_wine_native_is_rejected(self):
        write_apk(self.candidate, self.native.read_bytes(),
                  mutated="lib/arm64-v8a/libwineprobe.so")
        with self.assertRaisesRegex(ValueError, "CONTENT_CHANGED"):
            analyze(self.original, self.candidate, self.native)

    def test_additional_untrusted_native_is_rejected(self):
        write_apk(self.candidate, self.native.read_bytes(),
                  extras=["lib/arm64-v8a/libunknown.so"])
        with self.assertRaisesRegex(ValueError, "UNEXPECTED_ADDED"):
            analyze(self.original, self.candidate, self.native)

    def test_compressed_executable_rejected(self):
        write_apk(self.candidate, self.native.read_bytes(),
                  compression=zipfile.ZIP_DEFLATED)
        with self.assertRaisesRegex(ValueError, "NOT_STORED"):
            analyze(self.original, self.candidate, self.native)

    def test_modified_executable_rejected(self):
        write_apk(self.candidate, self.native.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "NATIVE_BYTES_CHANGED"):
            analyze(self.original, self.candidate, self.native)

    def test_missing_added_elf_rejected(self):
        write_apk(self.candidate)
        with self.assertRaisesRegex(ValueError, "UNEXPECTED_ADDED"):
            analyze(self.original, self.candidate, self.native)

    def test_wrong_abi_evidence_must_be_rejected(self):
        import json
        write_apk(self.candidate, self.native.read_bytes())
        details=Path(self.temp.name) / "abi.json"
        details.write_text(json.dumps({
            "status":"BLOCKED","sha256":"0"*64,
            "safe_to_activate_engine": False,
        }))
        with self.assertRaisesRegex(ValueError, "ABI_OR_SHA"):
            analyze(self.original, self.candidate, self.native, details)


if __name__ == "__main__":
    unittest.main()
