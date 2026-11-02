#!/usr/bin/env python3
"""Validate KERNIX Android display lifecycle records without inferring game FPS.

Opening XServerDisplayActivity does not prove any EXE started or any game frame
was presented. Paired session IDs only establish UI lifecycle duration.
"""
import argparse
import json
from pathlib import Path

MAX_BYTES=256*1024
MAX_LINES=2048

def summarize(path):
    p=Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size>MAX_BYTES:
        raise ValueError("INVALID_DISPLAY_LOG")
    current={}
    completed=[]
    number=0
    last_seq=-1
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        number+=1
        if number>MAX_LINES:raise ValueError("TOO_MANY_EVENTS")
        item=json.loads(line)
        if not isinstance(item,dict) or item.get("schema")!="kernix.android-display-lifecycle.v1":
            raise ValueError("INVALID_DISPLAY_SCHEMA")
        event=item.get("event")
        sid=item.get("session_id")
        seq=item.get("event_sequence")
        if not isinstance(sid,str) or not 1<=len(sid)<=80:
            raise ValueError("MISSING_SESSION_ID")
        if type(seq) is not int or seq<=last_seq:
            raise ValueError("OUT_OF_ORDER_EVENT_SEQUENCE")
        last_seq=seq
        # Fail closed on any attempt to smuggle performance/launch claims into
        # what is explicitly only an Android lifecycle telemetry stream.
        for field in ("game_fps","frame_count","game_exe_sha256",
                      "actual_game_started","game_process_confirmed"):
            if item.get(field) is not None:
                raise ValueError("UNSUPPORTED_GAME_PROOF:"+field)
        if event=="display_resumed":
            if sid in current:raise ValueError("DUPLICATE_SESSION_START")
            if item.get("elapsed_ms")!=0:raise ValueError("START_DURATION_NOT_ZERO")
            current[sid]=seq
        elif event=="display_paused":
            if sid not in current:raise ValueError("UNPAIRED_SESSION_END")
            duration=item.get("elapsed_ms")
            if type(duration) is not int or duration<0:
                raise ValueError("INVALID_SESSION_DURATION")
            completed.append({"session_id":sid,"duration_ms":duration,
                              "start_sequence":current.pop(sid),"end_sequence":seq})
        else:
            raise ValueError("UNKNOWN_DISPLAY_EVENT")
    return {"schema":"kernix.android-display-session-summary.v1",
            "event_count":number,"completed_sessions":completed,
            "unfinished_session_count":len(current),
            "game_launch_verified":False,"game_fps_measured":False,
            "components_verified":False,
            "note":"Android display lifecycle only; never evidence that a Windows game started."}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("display_log")
    a=p.parse_args()
    print(json.dumps(summarize(a.display_log),indent=2))

if __name__=="__main__":
    main()
