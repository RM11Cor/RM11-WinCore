"""Universal read-only KERNIX assessment tests with synthetic PE fixtures only."""
import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from kernix_universal_game_assessor import assess
from test_kernix_pe_imports import sample

REGISTRY = {"schema": "kernix.component-registry.v1", "components": []}


class UniversalAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.exe = Path(self.temp.name) / "game.exe"

    def write(self, dll=b"d3d11.dll", machine=0x8664, magic=0x20b):
        data = bytearray(sample(dll))
        struct.pack_into("<H", data, 132, machine)
        struct.pack_into("<H", data, 152, magic)
        struct.pack_into("<H", data, 152 + 68, 2)
        self.exe.write_bytes(data)
        return bytes(data)

    def profile(self):
        return {"schema": "kernix.game-profile.v1",
                "game_sha256": hashlib.sha256(self.exe.read_bytes()).hexdigest(),
                "mode": "balanced", "components": {}, "enabled": False}

    def test_every_game_including_working_uses_same_assessor(self):
        original = self.write()
        report = assess(self.exe)
        self.assertEqual(report["assess_all_game_states"],
                         ["working", "failing", "not_yet_tested"])
        self.assertEqual(report["identity"]["executable_sha256"],
                         hashlib.sha256(original).hexdigest())
        self.assertEqual(report["backend_candidate"], "windows-x86_64-pe")
        self.assertEqual(report["component_families_to_investigate_not_install"],
                         ["dxvk-d3d11-candidate"])
        self.assertEqual(report["static_import_audit"]["status"], "parsed")
        for key in ("candidate_version_selected", "compatibility_verified",
                    "quality_or_fps_improvement_measured", "game_executed",
                    "android_device_tested", "game_files_modified"):
            self.assertFalse(report[key])
        self.assertEqual(self.exe.read_bytes(), original)

    def test_d3d12_not_misrouted_to_dxvk(self):
        self.write(b"d3d12.dll")
        r = assess(self.exe)
        self.assertEqual(r["component_families_to_investigate_not_install"],
                         ["vkd3d-proton-d3d12-candidate"])

    def test_dxgi_alone_cannot_identify_directx_version(self):
        self.write(b"dxgi.dll")
        r = assess(self.exe)
        self.assertEqual(r["component_families_to_investigate_not_install"], [])
        self.assertIn("DXGI (version unspecified)",
                      r["static_import_audit"]["graphics_indicators"])

    def test_missing_static_import_table_does_not_imply_no_runtime_api(self):
        self.write()
        with patch("kernix_universal_game_assessor.analyze",
                   side_effect=ValueError("IMPORT_DIRECTORY_UNAVAILABLE")):
            r = assess(self.exe)
        self.assertEqual(r["static_import_audit"]["status"], "unavailable")
        self.assertEqual(r["static_import_audit"]["reason_if_unavailable"],
                         "IMPORT_DIRECTORY_UNAVAILABLE")
        self.assertEqual(r["component_families_to_investigate_not_install"], [])
        self.assertFalse(r["compatibility_verified"])

    def test_32bit_game_is_still_assessed_but_not_qualified(self):
        self.write(machine=0x14c, magic=0x10b)
        r = assess(self.exe)
        self.assertEqual(r["identity"]["architecture"], "x86")
        self.assertEqual(r["backend_candidate"], "unqualified-other-pe")
        self.assertFalse(r["candidate_version_selected"])

    def test_profile_checked_against_current_executable(self):
        self.write()
        profile = self.profile()
        r = assess(self.exe, profile, REGISTRY)
        self.assertEqual(r["game_profile_binding"]["profile_binding"],
                         "exact-file-hash-verified-static-only")
        self.assertFalse(r["game_profile_binding"]["launch_qualified"])
        self.exe.write_bytes(self.exe.read_bytes() + b"updated-build")
        with self.assertRaisesRegex(ValueError, "EXACT_GAME_EXECUTABLE_SHA256_MISMATCH"):
            assess(self.exe, profile, REGISTRY)

    def test_profile_requires_registry(self):
        self.write()
        with self.assertRaisesRegex(ValueError, "PROFILE_AND_REGISTRY_REQUIRED_TOGETHER"):
            assess(self.exe, self.profile(), None)

    def test_game_symlink_is_rejected(self):
        self.write()
        link = self.exe.with_name("link.exe")
        link.symlink_to(self.exe)
        with self.assertRaisesRegex(ValueError, "SYMLINK_GAME_EXECUTABLE_DENIED"):
            assess(link)

    def test_changed_file_during_scan_is_rejected(self):
        self.write()
        with patch("kernix_universal_game_assessor.analyze") as analyzer:
            def tamper(_):
                self.exe.write_bytes(self.exe.read_bytes() + b"changed")
                return {"static_imports": [], "graphics_api_indicators": []}
            analyzer.side_effect = tamper
            with self.assertRaisesRegex(ValueError, "GAME_CHANGED_DURING_ANALYSIS"):
                assess(self.exe)

    def test_ps4_self_not_treated_as_windows_exe(self):
        self.exe.write_bytes(bytes.fromhex("4f153d1d") + bytes(508))
        with self.assertRaisesRegex(ValueError, "NOT_PE_DOS_HEADER"):
            assess(self.exe)


if __name__ == "__main__":
    unittest.main()
