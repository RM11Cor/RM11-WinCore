"""Synthetic comparisons only: do not mistake fixture values for phone benchmarks."""
import copy
import unittest
from kernix_benchmark_evidence import compare, metrics, validate_run

def build(engine, fps=45):
    return {
        "schema":"kernix.benchmark-run.v1", "engine":engine,
        "source_commit":"a"*40 if engine=="kernix-reference" else "b"*40,
        "device":"REDMAGIC 11 Pro / Android 16 / Adreno 840",
        "game_sha256":"c"*64,"scenario":"same 60-second camera route",
        "config_sha256":"d"*64,"mode":"balanced",
        "fps_samples":[fps]*60,"duration_seconds":60,
        "crashes":0,"render_failures":0,
        "temperature_start_c":35,"temperature_end_c":39,
        "measured_on_device":True,
    }

class BenchmarkEvidenceTests(unittest.TestCase):
    def test_matched_reports_only_propose_manual_review(self):
        a,b=build("kernix-reference",60),build("rm11-legacy",40)
        result=compare(a,b)
        self.assertEqual(result["median_fps_delta"],20)
        self.assertTrue(result["candidate_for_manual_review"])
        self.assertFalse(result["approved_for_transfer"])
        self.assertFalse(result["automatic_port_allowed"])
        self.assertFalse(result["verified_on_phone_by_ci"])
    def test_different_scenario_rejected(self):
        a,b=build("kernix-reference"),build("rm11-legacy")
        b["scenario"]="different route"
        with self.assertRaises(ValueError):compare(a,b)
    def test_different_game_rejected(self):
        a,b=build("kernix-reference"),build("rm11-legacy")
        b["game_sha256"]="e"*64
        with self.assertRaises(ValueError):compare(a,b)
    def test_different_device_rejected(self):
        a,b=build("kernix-reference"),build("rm11-legacy")
        b["device"]="different"
        with self.assertRaises(ValueError):compare(a,b)
    def test_missing_real_sample_acknowledgement(self):
        a=build("kernix-reference")
        a["measured_on_device"]=False
        with self.assertRaises(ValueError):validate_run(a)
    def test_insufficient_samples(self):
        a=build("kernix-reference");a["fps_samples"]=[50]*3
        with self.assertRaises(ValueError):metrics(a)
    def test_nan_samples_rejected(self):
        a=build("kernix-reference");a["fps_samples"][0]=float("nan")
        with self.assertRaises(ValueError):metrics(a)
    def test_crashes_retained(self):
        a,b=build("kernix-reference"),build("rm11-legacy")
        a["crashes"]=1
        self.assertEqual(compare(a,b)["reference"]["crashes"],1)
    def test_unmatched_config_rejected(self):
        a,b=build("kernix-reference"),build("rm11-legacy")
        b["config_sha256"]="e"*64
        with self.assertRaises(ValueError):compare(a,b)

if __name__=="__main__":
    unittest.main()
