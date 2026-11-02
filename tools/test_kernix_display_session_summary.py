"""Synthetic display Activity lifecycle: never proof of game rendering."""
import json
import tempfile
import unittest
from pathlib import Path
from kernix_display_session_summary import summarize

def event(name,sid,seq,duration=0):
    return {"schema":"kernix.android-display-lifecycle.v1",
            "event":name,"session_id":sid,"event_sequence":seq,
            "elapsed_ms":duration,"game_fps":None,"frame_count":None,
            "game_exe_sha256":None,"actual_game_started":None,
            "game_process_confirmed":None}

class DisplaySummaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/"session.jsonl"
    def scan(self,events):
        self.path.write_text("\n".join(json.dumps(x) for x in events)+"\n")
        return summarize(self.path)
    def test_complete_session_is_not_game_proof(self):
        r=self.scan([event("display_resumed","s1",1),event("display_paused","s1",2,1200)])
        self.assertEqual(r["completed_sessions"][0]["duration_ms"],1200)
        self.assertFalse(r["game_launch_verified"])
        self.assertFalse(r["game_fps_measured"])
    def test_open_session_is_not_crash(self):
        r=self.scan([event("display_resumed","s1",1)])
        self.assertEqual(r["unfinished_session_count"],1)
        self.assertEqual(len(r["completed_sessions"]),0)
    def test_unpaired_end_rejected(self):
        with self.assertRaises(ValueError):
            self.scan([event("display_paused","unknown",1,100)])
    def test_sequence_regression_rejected(self):
        with self.assertRaises(ValueError):
            self.scan([event("display_resumed","s1",2),event("display_paused","s1",1,100)])
    def test_invented_fps_rejected(self):
        e=event("display_resumed","s1",1);e["game_fps"]=60
        with self.assertRaises(ValueError):self.scan([e])
    def test_duplicate_start_rejected(self):
        with self.assertRaises(ValueError):
            self.scan([event("display_resumed","s1",1),event("display_resumed","s1",2)])
    def test_multiple_sessions_separately_reported(self):
        events=[event("display_resumed","s1",1),event("display_paused","s1",2,100),
                event("display_resumed","s2",3),event("display_paused","s2",4,150)]
        r=self.scan(events)
        self.assertEqual([x["duration_ms"] for x in r["completed_sessions"]],[100,150])
    def test_invented_game_process_proof_rejected(self):
        e=event("display_resumed","s1",1);e["game_process_confirmed"]=True
        with self.assertRaises(ValueError):self.scan([e])

if __name__=="__main__":
    unittest.main()
