"""KERNIX independent compatibility planning: static only; no engine execution."""
import tempfile
import unittest
from pathlib import Path
from kernix_native_planner import plan, adjacent_markers
from test_kernix_pe_imports import sample

EMPTY = {"schema": "kernix.component-registry.v1", "components": []}

class NativePlannerTests(unittest.TestCase):
    def test_dx12_without_components_does_not_claim_boot(self):
        with tempfile.TemporaryDirectory() as t:
            exe=Path(t)/"sample.exe"
            exe.write_bytes(sample(b"d3d12.dll"))
            result=plan(exe,EMPTY)
            self.assertIn("vkd3d",result["required_component_capabilities"])
            self.assertIn("vkd3d",result["missing_verified_capabilities"])
            self.assertIn("wine_or_proton",result["missing_verified_capabilities"])
            self.assertFalse(result["runtime_tested"])
            self.assertFalse(result["game_started"])
            self.assertFalse(result["may_apply_automatically"])
            self.assertFalse(result["first_frame_verified"])

    def test_dxgi_only_ambiguous(self):
        with tempfile.TemporaryDirectory() as t:
            exe=Path(t)/"sample.exe"
            exe.write_bytes(sample(b"dxgi.dll"))
            result=plan(exe,EMPTY)
            self.assertNotIn("dxvk",result["required_component_capabilities"])
            self.assertNotIn("vkd3d",result["required_component_capabilities"])
            self.assertTrue(any("DXGI alone" in x for x in result["warnings"]))

    def test_unity_marker_is_hint_not_fact(self):
        with tempfile.TemporaryDirectory() as t:
            exe=Path(t)/"sample.exe"
            exe.write_bytes(sample(b"d3d11.dll"))
            (Path(t)/"UnityPlayer.dll").write_bytes(b"")
            result=plan(exe,EMPTY)
            self.assertEqual(result["engine_hints"][0]["engine"],"Unity")
            self.assertEqual(result["engine_hints"][0]["confidence"],"hint_only")
            self.assertIn("dxvk",result["required_component_capabilities"])

    def test_symlink_is_not_followed_and_bounded(self):
        with tempfile.TemporaryDirectory() as t, tempfile.TemporaryDirectory() as other:
            (Path(other)/"UnityPlayer.dll").write_bytes(b"")
            (Path(t)/"UnityPlayer.dll").symlink_to(Path(other)/"UnityPlayer.dll")
            self.assertEqual(adjacent_markers(Path(t)/"game.exe")["engine_hints"],[])
            for n in range(260):
                (Path(t)/f"file-{n}").touch()
            self.assertTrue(adjacent_markers(Path(t)/"game.exe")["directory_scan_truncated"])

    def test_bad_registry_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            exe=Path(t)/"sample.exe"; exe.write_bytes(sample())
            with self.assertRaises(ValueError):
                plan(exe,{"schema":"kernix.component-registry.v1","components":[{"id":"fake"}]})

if __name__ == "__main__":
    unittest.main()
