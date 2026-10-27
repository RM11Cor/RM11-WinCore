#!/usr/bin/env python3
"""Host-only tests for the real APK runtime-closure audit. No Android device."""
import hashlib
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from engine_closure_audit import audit


def _digest(value):
    return hashlib.sha256(value).hexdigest()


def _synthetic_apk(dst, ready=False, tamper=False, embedded_builtin=False):
    wine_zip = io.BytesIO()
    with zipfile.ZipFile(wine_zip, "w", compression=zipfile.ZIP_STORED) as wine:
        wine.writestr("opt/wine/lib/wine/aarch64-windows/libarm64ecfex.dll", b"fex")
        wine.writestr("opt/wine/lib/wine/aarch64-windows/libwow64fex.dll", b"wow")
        if embedded_builtin:
            wine.writestr("opt/wine/lib/wine/aarch64-windows/d3d11.dll",
                          b"WINE_BUILTIN_NOT_DXVK")
            wine.writestr("opt/wine/lib/wine/aarch64-windows/dxgi.dll",
                          b"WINE_BUILTIN_NOT_DXVK")
    dxgi = b"DXVK_BINARY_CONTENT_1"
    d3d11 = b"DXVK_BINARY_CONTENT_2"
    gpu = b"GPU_TURNIP_HW_ICD_1"
    manifest = {
        "schema": "rm11.engine.bundle.v1",
        "dxvk": {
            "provider": "dxvk", "source_commit": "a" * 40,
            "pe_files": {
                "dxgi.dll": {
                    "sha256": _digest(dxgi),
                    "apk_path": "assets/engine/dxvk/dxgi.dll"
                },
                "d3d11.dll": {
                    "sha256": _digest(d3d11),
                    "apk_path": "assets/engine/dxvk/d3d11.dll"
                }
            },
        },
        "gpu": {
            "driver": "turnip", "wsi": "hardware",
            "source_commit": "b" * 40,
            "apk_library": "lib/arm64-v8a/libturnip-verified.so",
            "sha256": _digest(gpu)
        }
    }
    with zipfile.ZipFile(dst, "w", compression=zipfile.ZIP_STORED) as apk:
        apk.writestr("lib/arm64-v8a/libwineprobe.so", b"wine")
        apk.writestr("lib/arm64-v8a/libwineserverrm11.so", b"server")
        apk.writestr("lib/arm64-v8a/libXlorie.so", b"xorg")
        apk.writestr("lib/arm64-v8a/libwine_winex11.so", b"x11")
        apk.writestr("assets/runtime/rm11-wine-stack.zip", wine_zip.getvalue())
        if ready:
            apk.writestr("assets/engine/engine-bundle-manifest.json",
                         json.dumps(manifest))
            apk.writestr("assets/engine/dxvk/dxgi.dll",
                         b"tampered" if tamper else dxgi)
            apk.writestr("assets/engine/dxvk/d3d11.dll", d3d11)
            apk.writestr("lib/arm64-v8a/libturnip-verified.so", gpu)


class EngineClosureTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.path = Path(self.folder.name) / "baseline.apk"

    def tearDown(self):
        self.folder.cleanup()

    def test_old_wine_builtins_cannot_masquerade_as_dxvk(self):
        _synthetic_apk(self.path, embedded_builtin=True)
        result = audit(self.path)
        self.assertEqual(result["checks"]["arm64ec_fex_module"], "PRESENT")
        self.assertEqual(result["checks"]["dxvk_d3d11_provider_hash_verified"],
                         "MISSING")
        self.assertEqual(result["structural_release_gate"], "BLOCKED")
        self.assertEqual(result["would_publish_apk"], False)
        self.assertEqual(result["game_rendering_claim"], "UNVERIFIED")

    def test_coherent_hash_verified_bundle_only_structurally_ready(self):
        _synthetic_apk(self.path, ready=True)
        result = audit(self.path)
        self.assertEqual(result["checks"]["dxvk_d3d11_provider_hash_verified"],
                         "PRESENT")
        self.assertEqual(result["checks"]["hardware_turnip_icd_hash_verified"],
                         "PRESENT")
        self.assertEqual(result["structural_release_gate"], "READY")
        # A complete APK on disk is NEVER proof of screen presentation.
        self.assertEqual(result["release_gate"],
                         "WAIT_FOR_REAL_ENGINE_INTEGRATION")

    def test_dxvk_binary_hash_mismatch_blocks_release(self):
        _synthetic_apk(self.path, ready=True, tamper=True)
        result = audit(self.path)
        self.assertEqual(result["checks"]["dxvk_d3d11_provider_hash_verified"],
                         "MISSING")
        self.assertEqual(result["structural_release_gate"], "BLOCKED")

    def test_corrupt_nested_engine_archive_is_reported_not_accepted(self):
        with zipfile.ZipFile(self.path, "w") as apk:
            apk.writestr("assets/runtime/corrupt.zip", b"broken")
        result = audit(self.path)
        self.assertTrue(any(x.startswith("NESTED_UNREADABLE:")
                            for x in result["unreadable_archives"]))
        self.assertEqual(result["structural_release_gate"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
