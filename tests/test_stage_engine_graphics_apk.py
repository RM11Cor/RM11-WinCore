#!/usr/bin/env python3
"""Host-only tests: positive and tamper cases cannot prove GPU runtime."""
import hashlib
import json
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from assemble_rm11_graphics_stack import DXVK_SHA, MESA_TARBALL, ADRENO_SHA
from stage_engine_graphics_apk import (
    APK_MANIFEST, INPUT_NAMES, NATIVE_NAMES, SOURCE_RUNS, stage, audit_apk,
    verify_candidate)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def binary(name):
    data = bytearray(1024)
    if name.endswith(".dll"):
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3c, 0x80)
        data[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<H", data, 0x84, 0x8664)
        struct.pack_into("<H", data, 0x98, 0x20b)
    else:
        data[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<HH", data, 16, 3, 183)
    return bytes(data)


class GraphicsApkStageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.app = self.root / "app"
        self.app.mkdir()
        (self.app / "build.gradle").write_text("plugins { id 'com.android.application' }")
        self.archive = self.root / "candidate.zip"
        self.report = self.root / "candidate.json"
        self.apk = self.root / "apk.zip"
        self.blobs = {n: binary(n) for n in INPUT_NAMES}
        self.evidence = {
            "schema": "rm11.engine.graphics-build-candidate.v1",
            "source_runs": SOURCE_RUNS, "dxvk_commit": DXVK_SHA,
            "mesa_tar_sha256": MESA_TARBALL, "adrenotools_commit": ADRENO_SHA,
            "structural_source_artifacts_verified": True,
            "files": {n: {"sha256": digest(b), "size": len(b)}
                      for n, b in self.blobs.items()},
            "safe_to_release": False, "signed_apk_installed": False,
            "winedll_override_applied": False,
            "wine_child_custom_loader_verified": False,
            "android_turnip_dlopen_verified": False,
            "adreno_gpu_enumeration_verified": False,
            "x11_game_pixels_on_android_verified": False,
        }
        self.write_candidate()

    def tearDown(self):
        self.temp.cleanup()

    def write_candidate(self):
        self.report.write_text(json.dumps(self.evidence))
        with zipfile.ZipFile(self.archive, "w") as z:
            for name, data in self.blobs.items():
                z.writestr(name, data)
            z.writestr("graphics-candidate-manifest.json",
                       json.dumps(self.evidence))

    def write_apk(self, tamper=None):
        with zipfile.ZipFile(self.apk, "w") as z:
            for file in (self.app / "src/main").rglob("*"):
                if not file.is_file():
                    continue
                rel = file.relative_to(self.app / "src/main")
                if rel.parts[0] == "jniLibs":
                    archive_name = "lib/" + "/".join(rel.parts[1:])
                else:
                    archive_name = "/".join(rel.parts)
                payload = file.read_bytes()
                if archive_name == tamper:
                    payload += b"modified"
                z.writestr(archive_name, payload)

    def test_nine_exact_binaries_stage_with_disabled_activation(self):
        manifest = stage(self.archive, self.report, self.app)
        self.assertEqual(len(manifest["native_components"]), len(NATIVE_NAMES))
        self.assertFalse(manifest["safe_to_release"])
        self.assertFalse(manifest["wine_child_vulkan_loader_invoked"])
        self.write_apk()
        result = audit_apk(self.apk)
        self.assertEqual(result["component_count"], 9)
        self.assertFalse(result["safe_to_release"])
        self.assertEqual(result["hardware_frame_proof"], "UNVERIFIED")

    def test_reject_tampered_candidate_dll(self):
        self.blobs["dxvk/x64/d3d11.dll"] += b"tampered"
        self.write_candidate()
        with self.assertRaisesRegex(ValueError, "COMPONENT"):
            verify_candidate(self.archive, self.report)

    def test_reject_extra_archive_entry(self):
        with zipfile.ZipFile(self.archive, "a") as z:
            z.writestr("lib/arm64-v8a/untrusted.so", b"x" * 1024)
        with self.assertRaisesRegex(ValueError, "MISSING_EXTRA_OR_DUPLICATE"):
            stage(self.archive, self.report, self.app)

    def test_reject_fabricated_gpu_proof(self):
        self.evidence["adreno_gpu_enumeration_verified"] = True
        self.write_candidate()
        with self.assertRaisesRegex(ValueError, "RUNTIME_PROOF_CLAIM"):
            stage(self.archive, self.report, self.app)

    def test_reject_wrong_source_pin(self):
        self.evidence["mesa_tar_sha256"] = "f" * 64
        self.write_candidate()
        with self.assertRaisesRegex(ValueError, "SOURCE_PROVENANCE"):
            stage(self.archive, self.report, self.app)

    def test_reject_mutated_apk_native_component(self):
        stage(self.archive, self.report, self.app)
        self.write_apk("lib/arm64-v8a/libmain_hook.so")
        with self.assertRaisesRegex(ValueError, "COMPONENT_CHANGED"):
            audit_apk(self.apk)

    def test_never_overwrite_existing_native_component(self):
        stage(self.archive, self.report, self.app)
        with self.assertRaisesRegex(ValueError, "ALREADY_CONTAINS"):
            stage(self.archive, self.report, self.app)


if __name__ == "__main__":
    unittest.main()
