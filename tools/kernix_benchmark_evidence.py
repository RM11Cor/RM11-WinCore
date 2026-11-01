#!/usr/bin/env python3
"""KERNIX benchmark evidence gate: compare source vs legacy reproducibly.

No executable/game launch, no unverified performance claims and no automatic
code/component transfer. Requires matched workloads and explicitly recorded
runs on both branches before allowing a human review.
"""
import argparse
import json
import math
import re
from pathlib import Path

SHA = re.compile(r"^[0-9a-f]{40,64}$")
ENGINE = {"kernix-reference", "rm11-legacy"}
MAX_SAMPLES = 7200
MODES = {"balanced", "performance", "compatibility"}

def validate_run(data):
    if not isinstance(data, dict) or data.get("schema") != "kernix.benchmark-run.v1":
        raise ValueError("INVALID_BENCHMARK_SCHEMA")
    required = {"schema","engine","source_commit","device","game_sha256",
                "scenario","config_sha256","mode","fps_samples","duration_seconds",
                "crashes","render_failures","temperature_start_c","temperature_end_c",
                "measured_on_device"}
    if set(data) != required:
        raise ValueError("INVALID_BENCHMARK_FIELDS")
    if data["engine"] not in ENGINE: raise ValueError("INVALID_ENGINE")
    if not isinstance(data["source_commit"],str) or not SHA.fullmatch(data["source_commit"]):
        raise ValueError("INVALID_COMMIT")
    if not isinstance(data["game_sha256"],str) or len(data["game_sha256"]) != 64 or not SHA.fullmatch(data["game_sha256"]):
        raise ValueError("INVALID_GAME_ID")
    if not isinstance(data["config_sha256"],str) or len(data["config_sha256"]) != 64 or not SHA.fullmatch(data["config_sha256"]):
        raise ValueError("INVALID_CONFIGURATION_ID")
    for field in ("device","scenario"):
        if not isinstance(data[field],str) or not 1 <= len(data[field]) <= 128:
            raise ValueError("INVALID_"+field.upper())
    if data["mode"] not in MODES: raise ValueError("INVALID_MODE")
    if data["measured_on_device"] is not True:
        raise ValueError("MEASUREMENT_NOT_VERIFIED")
    samples = data["fps_samples"]
    if not isinstance(samples,list) or not 30 <= len(samples) <= MAX_SAMPLES:
        raise ValueError("INSUFFICIENT_OR_OVERSIZED_SAMPLES")
    if any(type(x) not in (float,int) or not math.isfinite(x) or x < 0 or x > 1000 for x in samples):
        raise ValueError("INVALID_FPS_VALUES")
    duration=data["duration_seconds"]
    if type(duration) not in (int,float) or not math.isfinite(duration) or duration < 30 or duration > 7200:
        raise ValueError("INVALID_DURATION")
    for field in ("crashes","render_failures"):
        if type(data[field]) is not int or not 0 <= data[field] <= 1000:
            raise ValueError("INVALID_"+field.upper())
    for field in ("temperature_start_c","temperature_end_c"):
        v=data[field]
        if type(v) not in (int,float) or not math.isfinite(v) or not 0 <= v <= 100:
            raise ValueError("INVALID_TEMPERATURE")
    return data

def quantile(values, p):
    v=sorted(values)
    position=(len(v)-1)*p
    i=int(position)
    return round(v[i]+(v[min(i+1,len(v)-1)]-v[i])*(position-i),2)

def metrics(run):
    validate_run(run)
    values=run["fps_samples"]
    return {
        "fps_median": quantile(values,.5),
        "fps_p01": quantile(values,.01),
        "fps_p99": quantile(values,.99),
        "crashes":run["crashes"],
        "render_failures":run["render_failures"],
        "temperature_increase_c":round(run["temperature_end_c"]-run["temperature_start_c"],2),
        "duration_seconds":run["duration_seconds"]
    }

def compare(reference, legacy):
    validate_run(reference)
    validate_run(legacy)
    if reference["engine"]!="kernix-reference" or legacy["engine"]!="rm11-legacy":
        raise ValueError("INCORRECT_ENGINE_ORDER")
    matched = ("device","game_sha256","scenario","config_sha256","mode")
    differing = [x for x in matched if reference[x]!=legacy[x]]
    if differing:
        raise ValueError("UNMATCHED_BENCHMARK_CONDITIONS:"+",".join(differing))
    rm, lm=metrics(reference),metrics(legacy)
    # A single comparable pair is evidence only; never sufficient for automated transplant.
    return {"schema":"kernix.benchmark-comparison.v1",
            "reference":rm,"legacy":lm,
            "median_fps_delta":round(rm["fps_median"]-lm["fps_median"],2),
            "p01_fps_delta":round(rm["fps_p01"]-lm["fps_p01"],2),
            "source_commits":{"reference":reference["source_commit"],"legacy":legacy["source_commit"]},
            "equivalent_conditions":True,
            "verified_on_phone_by_ci":False,
            "candidate_for_manual_review":True,
            "approved_for_transfer":False,
            "automatic_port_allowed":False,
            "note":"Review source license, exact dependency graph, reproducibility and safety before any legacy port."}

def read(path):
    p=Path(path)
    if not p.is_file() or p.stat().st_size > 1_000_000:raise ValueError("MISSING_OR_OVERSIZED_REPORT")
    return json.loads(p.read_text(encoding="utf-8"))

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--reference",required=True)
    parser.add_argument("--legacy",required=True)
    a=parser.parse_args()
    print(json.dumps(compare(read(a.reference),read(a.legacy)),indent=2,sort_keys=True))

if __name__=="__main__":main()
