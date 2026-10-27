#!/usr/bin/env python3
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from assemble_rm11_graphics_stack import one, write_bundle


class ProviderBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_reject_missing_or_duplicate_component(self):
        with self.assertRaisesRegex(ValueError, "AMBIGUOUS_OR_MISSING"):
            one(self.root, "d3d11.dll")
        (self.root / "a").mkdir()
        (self.root / "b").mkdir()
        (self.root / "a/d3d11.dll").write_bytes(b"fake" * 500)
        (self.root / "b/d3d11.dll").write_bytes(b"fake" * 500)
        with self.assertRaisesRegex(ValueError, "AMBIGUOUS_OR_MISSING"):
            one(self.root, "d3d11.dll")

    def test_output_is_closed_unless_runtime_proof_exists(self):
        # Unit-test only the deterministic container; real binary provenance
        # requires GitHub artifacts and is audited by stage() on CI.
        import hashlib
        data = b"test binary"
        manifest = {
            "schema": "rm11.engine.graphics-build-candidate.v1",
            "files": {"native/mock.bin": {
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data)}},
            "safe_to_release": False,
            "adreno_gpu_enumeration_verified": False,
        }
        archive = self.root / "candidate.zip"
        report = self.root / "candidate.json"
        write_bundle({"native/mock.bin": data}, manifest, archive, report)
        self.assertFalse(json.loads(report.read_text())["safe_to_release"])
        self.assertTrue(archive.is_file())


if __name__ == "__main__":
    unittest.main()
