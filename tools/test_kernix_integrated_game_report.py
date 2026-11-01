"""Integrated KERNIX report smoke tests; synthetic only, zero game execution."""
import tempfile
import unittest
from pathlib import Path
from kernix_integrated_game_report import evaluate
from test_kernix_pe_imports import sample

REGISTRY={"schema":"kernix.component-registry.v1","components":[]}

class IntegrationTest(unittest.TestCase):
    def test_d3d11_requires_missing_dxvk(self):
        with tempfile.TemporaryDirectory() as folder:
            exe=Path(folder)/"synthetic.exe"
            exe.write_bytes(sample(b"d3d11.dll"))
            result=evaluate(exe,REGISTRY)
            self.assertEqual(result["graphics"]["api_indicators"],["Direct3D 11"])
            self.assertEqual(result["compatibility"]["missing_verified_component_kinds"],["dxvk"])
            self.assertEqual(result["profile"]["game_sha256"],result["identity"]["sha256"])
            self.assertFalse(result["game_executed"])
            self.assertFalse(result["autoselection_enabled"])
            self.assertFalse(result["profile"]["enabled"])

    def test_dxgi_does_not_assume_directx_version(self):
        with tempfile.TemporaryDirectory() as folder:
            exe=Path(folder)/"synthetic.exe"
            exe.write_bytes(sample(b"dxgi.dll"))
            result=evaluate(exe,REGISTRY)
            self.assertTrue(result["compatibility"]["insufficient_evidence"])
            self.assertEqual(result["compatibility"]["required_graphics_wrapper_kinds"],[])

    def test_profile_for_other_game_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            exe=Path(folder)/"synthetic.exe"
            exe.write_bytes(sample())
            profile={"schema":"kernix.game-profile.v1","game_sha256":"a"*64,
                     "mode":"balanced","components":{},"enabled":False}
            with self.assertRaises(ValueError):
                evaluate(exe,REGISTRY,profile)

    def test_no_enabling_existing_profile(self):
        with tempfile.TemporaryDirectory() as folder:
            exe=Path(folder)/"synthetic.exe"
            exe.write_bytes(sample())
            current=evaluate(exe,REGISTRY)["profile"]
            current["enabled"]=True
            with self.assertRaises(ValueError):
                evaluate(exe,REGISTRY,current)

    def test_invalid_executable_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            exe=Path(folder)/"invalid.exe"
            exe.write_text("not a PE")
            with self.assertRaises(ValueError):evaluate(exe,REGISTRY)

if __name__=="__main__":
    unittest.main()
