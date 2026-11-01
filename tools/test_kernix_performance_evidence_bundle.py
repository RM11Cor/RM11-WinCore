"""Synthetic provenance fixtures; these are NOT phone performance measurements."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from kernix_performance_evidence_bundle import build_bundle

GAME="a"*64
PROFILE={"schema":"kernix.game-profile.v1","game_sha256":GAME,
         "mode":"balanced","components":{},"enabled":False}
REGISTRY={"schema":"kernix.component-registry.v1","components":[]}

class EvidenceBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.profile=self.root/"profile.json"
        self.registry=self.root/"registry.json"
        self.metadata=self.root/"metadata.json"
        self.frames=self.root/"frames.csv"
        self.profile.write_text(json.dumps(PROFILE))
        self.registry.write_text(json.dumps(REGISTRY))
        self.frames.write_text("timestamp_ns\n" + "\n".join(str(i*20_000_000) for i in range(1601)))
        self.meta={
            "engine":"kernix-reference", "source_commit":"b"*40,
            "device":"SYNTHETIC TEST FIXTURE (NOT A DEVICE MEASUREMENT)",
            "game_sha256":GAME, "scenario":"synthetic unit test",
            "config_sha256":hashlib.sha256(self.profile.read_bytes()).hexdigest(),
            "mode":"balanced", "crashes":0,"render_failures":0,
            "temperature_start_c":30,"temperature_end_c":31,
            "frame_source":"game-presented-frame-timestamps",
            "collector_id":"SYNTHETIC_ONLY"
        }
        self.metadata.write_text(json.dumps(self.meta))

    def bundle(self):
        return build_bundle(self.frames,self.metadata,self.profile,self.registry)

    def test_hashed_inputs_are_pinned(self):
        report=self.bundle()
        self.assertEqual(report["frame_log_sha256"],hashlib.sha256(self.frames.read_bytes()).hexdigest())
        self.assertEqual(report["profile_file_sha256"],self.meta["config_sha256"])
        self.assertEqual(report["game_sha256"],GAME)

    def test_no_device_or_runtime_attestation_claim(self):
        report=self.bundle()
        self.assertFalse(report["actual_runtime_components_attested"])
        self.assertFalse(report["device_measurement_independently_verified"])
        self.assertFalse(report["approved_for_legacy_port"])
        self.assertFalse(report["auto_port_allowed"])

    def test_reject_game_mismatch(self):
        self.meta["game_sha256"]="c"*64
        self.metadata.write_text(json.dumps(self.meta))
        with self.assertRaisesRegex(ValueError,"GAME_PROFILE_BENCHMARK_MISMATCH"):
            self.bundle()

    def test_reject_changed_profile_content(self):
        self.profile.write_text(json.dumps({**PROFILE,"mode":"performance"}))
        with self.assertRaises(ValueError):
            self.bundle()

    def test_reject_tampered_config_hash(self):
        self.meta["config_sha256"]="d"*64
        self.metadata.write_text(json.dumps(self.meta))
        with self.assertRaisesRegex(ValueError,"CONFIG_HASH_MUST_MATCH"):
            self.bundle()

    def test_reject_unsupported_frame_source(self):
        self.meta["frame_source"]="compose-ui-fps"
        self.metadata.write_text(json.dumps(self.meta))
        with self.assertRaisesRegex(ValueError,"NOT_GAME_PRESENTED_FRAMES"):
            self.bundle()

    def test_reject_symlink_metadata(self):
        source=self.root/"other.json"
        source.write_text(json.dumps(self.meta))
        self.metadata.unlink()
        self.metadata.symlink_to(source)
        with self.assertRaises(ValueError):
            self.bundle()

if __name__=="__main__":
    unittest.main()
