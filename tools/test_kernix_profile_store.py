"""Synthetic unit tests for profile save, snapshot integrity and rollback."""
import json
import tempfile
import unittest
from pathlib import Path
from kernix_profile_store import save, restore, paths, current_digest, load_snapshot

HASH = "a" * 64
REGISTRY = {"schema":"kernix.component-registry.v1","components":[]}
PROFILE = {"schema":"kernix.game-profile.v1","game_sha256":HASH,"mode":"balanced","components":{},"enabled":False}

class ProfileStoreTests(unittest.TestCase):
    def test_save_restore_prior_version(self):
        with tempfile.TemporaryDirectory() as d:
            first=save(d,PROFILE,REGISTRY)
            performance={**PROFILE,"mode":"performance"}
            second=save(d,performance,REGISTRY,expected_current=first["saved_snapshot"])
            self.assertNotEqual(first["saved_snapshot"],second["saved_snapshot"])
            pointer,snapshots=paths(d,HASH)
            self.assertEqual(current_digest(pointer),second["saved_snapshot"])
            self.assertTrue((snapshots/(first["saved_snapshot"]+".json")).exists())
            result=restore(d,HASH,first["saved_snapshot"],REGISTRY,expected_current=second["saved_snapshot"])
            self.assertEqual(result["restored_snapshot"],first["saved_snapshot"])
            self.assertEqual(load_snapshot(snapshots,current_digest(pointer),REGISTRY)["mode"],"balanced")
    def test_wrong_game_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            first=save(d,PROFILE,REGISTRY)
            with self.assertRaises(ValueError):
                restore(d,"b"*64,first["saved_snapshot"],REGISTRY)
    def test_stale_revision_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            first=save(d,PROFILE,REGISTRY)
            with self.assertRaises(ValueError):
                save(d,{**PROFILE,"mode":"performance"},REGISTRY,expected_current="b"*64)
            self.assertEqual(current_digest(paths(d,HASH)[0]),first["saved_snapshot"])
    def test_corruption_detected(self):
        with tempfile.TemporaryDirectory() as d:
            first=save(d,PROFILE,REGISTRY)
            pointer,snapshots=paths(d,HASH)
            (snapshots/(first["saved_snapshot"]+".json")).write_text("{}")
            with self.assertRaises(ValueError):
                restore(d,HASH,first["saved_snapshot"],REGISTRY)
    def test_enabled_profile_cannot_be_saved(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                save(d,{**PROFILE,"enabled":True},REGISTRY)
    def test_reject_snapshot_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            first=save(d,PROFILE,REGISTRY)
            _,snapshots=paths(d,HASH)
            snap=snapshots/(first["saved_snapshot"]+".json")
            snap.unlink()
            snap.symlink_to(Path(d)/"outside")
            with self.assertRaises(ValueError):
                restore(d,HASH,first["saved_snapshot"],REGISTRY)
    def test_duplicate_snapshot_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            first=save(d,PROFILE,REGISTRY)
            second=save(d,PROFILE,REGISTRY,expected_current=first["saved_snapshot"])
            self.assertEqual(first["saved_snapshot"],second["saved_snapshot"])

if __name__ == "__main__":
    unittest.main()
