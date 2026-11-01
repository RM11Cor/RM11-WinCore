"""No synthetic fixtures are allowed to be called real device measurements."""
import tempfile
import unittest
from pathlib import Path
from kernix_frame_log_import import read_timestamps, fps_windows, convert

def meta():
    return {"engine":"kernix-reference","source_commit":"a"*40,
            "device":"REDMAGIC 11 Pro Android 16","game_sha256":"b"*64,
            "scenario":"test course","config_sha256":"c"*64,
            "mode":"balanced","crashes":0,"render_failures":0,
            "temperature_start_c":34,"temperature_end_c":36,
            "frame_source":"game-presented-frame-timestamps",
            "collector_id":"synthetic-test-hook"}

class FrameImportTests(unittest.TestCase):
    def test_30_second_60fps_conversion(self):
        stamps=[i*16_666_667 for i in range(1861)]
        report=convert(stamps,meta())
        self.assertEqual(len(report["benchmark_run"]["fps_samples"]),31)
        self.assertGreaterEqual(min(report["benchmark_run"]["fps_samples"]),59)
        self.assertFalse(report["ci_verified_device_measurement"])
    def test_refuse_ui_vsync(self):
        stamps=[i*20_000_000 for i in range(1551)]
        m=meta();m["frame_source"]="android-compose-ui-vsync"
        with self.assertRaises(ValueError):convert(stamps,m)
    def test_refuse_short_log(self):
        with self.assertRaises(ValueError):fps_windows([i*16_666_667 for i in range(600)])
    def test_non_monotonic_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/"frames.csv"
            f.write_text("timestamp_ns\n100\n200\n200\n")
            with self.assertRaises(ValueError):read_timestamps(f)
    def test_bad_metadata_rejected(self):
        m=meta();m["unrecognized"]="something"
        stamps=[i*20_000_000 for i in range(1551)]
        with self.assertRaises(ValueError):convert(stamps,m)
    def test_frames_csv_reader(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/"frames.csv"
            f.write_text("timestamp_ns\n10\n20\n")
            with self.assertRaises(ValueError):read_timestamps(f)
    def test_stall_recorded_zero_fps(self):
        stamps=[i*16_666_667 for i in range(120)]+[32_000_000_000+i*16_666_667 for i in range(120)]
        fps=fps_windows(stamps)
        self.assertIn(0,fps)
    def test_negative_fps_not_possible(self):
        with self.assertRaises(ValueError):fps_windows([100_000_000_000,1])

if __name__=="__main__":unittest.main()
