#!/usr/bin/env python3
"""Convert *externally captured* game frame timestamps to benchmark evidence.

No fake frames, no synthetic FPS fallback, no claim to have instrumented a game.
The time source MUST be game-presented-frame telemetry, not Compose UI vsync.
Logs are auditable CSV: timestamp_ns (one integer per line, optional header).
No PC game is launched and this command cannot inspect device temperature.
"""
import argparse
import csv
import hashlib
import json
import math
import re
from pathlib import Path
from kernix_benchmark_evidence import validate_run

MAX_CSV_BYTES=8 * 1024 * 1024
MAX_FRAMES=720000
SHA64=re.compile(r"^[a-f0-9]{64}$")
SHA40=re.compile(r"^[a-f0-9]{40}$")
ALLOWED_SOURCES={"game-presented-frame-timestamps", "verified-game-present-hook"}
ALLOWED_MODES={"balanced","performance","compatibility"}

def read_timestamps(path):
    path=Path(path)
    if not path.is_file() or path.stat().st_size>MAX_CSV_BYTES:
        raise ValueError("MISSING_OR_OVERSIZED_FRAME_LOG")
    values=[]
    with path.open(encoding="utf-8-sig",newline="") as stream:
        lines=csv.reader(stream)
        for line_no,row in enumerate(lines):
            if not row or (len(row)==1 and not row[0].strip()): continue
            if len(row)!=1:raise ValueError("EXPECTED_SINGLE_TIMESTAMP_COLUMN")
            value=row[0].strip()
            if not values and value=="timestamp_ns":continue
            if not value.isdecimal():raise ValueError("INVALID_TIMESTAMP_AT_LINE_"+str(line_no+1))
            stamp=int(value)
            if stamp>2**63-1:raise ValueError("TIMESTAMP_OVERFLOW")
            if values and stamp<=values[-1]:raise ValueError("NONMONOTONIC_FRAME_TIMESTAMPS")
            values.append(stamp)
            if len(values)>MAX_FRAMES:raise ValueError("FRAME_COUNT_LIMIT")
    if len(values)<60:raise ValueError("INSUFFICIENT_GAME_FRAMES")
    return values

def fps_windows(timestamps):
    """FPS for complete, contiguous seconds only; no duplicate edge frame counting."""
    base=timestamps[0]
    elapsed_ns=timestamps[-1]-base
    full_seconds=elapsed_ns//1_000_000_000
    if not 30<=full_seconds<=7200:raise ValueError("NEED_30_TO_7200_FULL_SECONDS")
    windows=[0]*full_seconds
    for stamp in timestamps[1:]:
        offset=(stamp-base)//1_000_000_000
        if offset<full_seconds:windows[offset]+=1
    # An interval with no presented frames is measurable stalling, not missing data.
    return windows

def convert(timestamps, metadata):
    fps=fps_windows(timestamps)
    if not isinstance(metadata,dict):raise ValueError("INVALID_METADATA")
    required={"engine","source_commit","device","game_sha256","scenario",
              "config_sha256","mode","crashes","render_failures",
              "temperature_start_c","temperature_end_c","frame_source","collector_id"}
    if set(metadata)!=required:raise ValueError("INVALID_METADATA_FIELDS")
    if metadata["frame_source"] not in ALLOWED_SOURCES:
        raise ValueError("NOT_GAME_PRESENTED_FRAMES")
    if not isinstance(metadata["collector_id"],str) or not 1<=len(metadata["collector_id"])<=128:
        raise ValueError("INVALID_COLLECTOR_ID")
    record={
        "schema":"kernix.benchmark-run.v1",
        **{k:v for k,v in metadata.items() if k not in ("frame_source","collector_id")},
        "fps_samples":fps,
        "duration_seconds":len(fps),
        "measured_on_device":True
    }
    validate_run(record)
    return {
        "schema":"kernix.frame-log-import.v1",
        "benchmark_run":record,
        "frame_source_declared":metadata["frame_source"],
        "collector_id":metadata["collector_id"],
        "frame_count":len(timestamps),
        "claimed_game_presented_fps_not_independently_verified":True,
        "ci_verified_device_measurement":False,
        "verified_temperature_source":False,
        "note":"Collector authenticity and temperature readings require external device evidence; this tool validates only format and arithmetic."
    }

def main():
    a=argparse.ArgumentParser()
    a.add_argument("--timestamps",required=True)
    a.add_argument("--metadata",required=True)
    a.add_argument("--output")
    args=a.parse_args()
    source=Path(args.metadata)
    if not source.is_file() or source.stat().st_size>65536:
        raise ValueError("MISSING_OR_OVERSIZED_METADATA")
    meta=json.loads(source.read_text(encoding="utf-8"))
    result=convert(read_timestamps(args.timestamps),meta)
    blob=json.dumps(result,indent=2,sort_keys=True,ensure_ascii=False)+"\n"
    if args.output:
        dest=Path(args.output)
        if dest.is_symlink():raise ValueError("SYMLINK_OUTPUT_REJECTED")
        dest.write_text(blob,encoding="utf-8")
    else:print(blob,end="")

if __name__=="__main__":main()
