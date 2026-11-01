#!/usr/bin/env python3
"""KERNIX auditable game-performance evidence bundle (offline, no game execution).

Joins a static game profile, a *declared* collector report, and a component
registry without claiming Android device attestation. Every input file is
fingerprinted. A bundle is NEVER approval to transfer engine binaries.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
from kernix_frame_log_import import convert, read_timestamps
from kernix_game_profiles import validate_profile
from kernix_component_registry import validate as validate_registry

SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_JSON_BYTES = 65536
MAX_FRAME_LOG_BYTES = 8 * 1024 * 1024

def read_bounded_json(path):
    p=Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_JSON_BYTES:
        raise ValueError("INVALID_OR_OVERSIZED_JSON_INPUT")
    return json.loads(p.read_text(encoding="utf-8"))

def sha_file(path, limit):
    p=Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > limit:
        raise ValueError("INVALID_OR_OVERSIZED_EVIDENCE_SOURCE")
    h=hashlib.sha256()
    with p.open("rb") as stream:
        for chunk in iter(lambda: stream.read(256*1024),b""):
            h.update(chunk)
    return h.hexdigest()

def build_bundle(timestamps_path, metadata_path, profile_path, registry_path):
    metadata=read_bounded_json(metadata_path)
    profile=read_bounded_json(profile_path)
    registry=read_bounded_json(registry_path)
    by_id=validate_registry(registry)
    selection=validate_profile(profile,registry)
    imported=convert(read_timestamps(timestamps_path),metadata)
    run=imported["benchmark_run"]
    if run["game_sha256"]!=profile["game_sha256"]:
        raise ValueError("GAME_PROFILE_BENCHMARK_MISMATCH")
    if run["mode"]!=profile["mode"]:
        raise ValueError("PROFILE_MODE_BENCHMARK_MISMATCH")
    if run["config_sha256"]!=sha_file(profile_path, MAX_JSON_BYTES):
        raise ValueError("CONFIG_HASH_MUST_MATCH_EXACT_PROFILE_FILE")
    # The selection is only what the profile declares, not what the game
    # actually loaded. Runtime-loaded DLLs must eventually be attested.
    components=[]
    for ident in selection["component_ids"]:
        item=by_id[ident]
        components.append({"id":ident,"kind":item["kind"],"version":item["version"],
                           "declared_package_sha256":item["sha256"],"abi":item["abi"]})
    return {
        "schema":"kernix.game-performance-evidence.v1",
        "engine":run["engine"],
        "source_commit":run["source_commit"],
        "game_sha256":run["game_sha256"],
        "profile_file_sha256":sha_file(profile_path,MAX_JSON_BYTES),
        "registry_file_sha256":sha_file(registry_path,MAX_JSON_BYTES),
        "frame_log_sha256":sha_file(timestamps_path,MAX_FRAME_LOG_BYTES),
        "metadata_file_sha256":sha_file(metadata_path,MAX_JSON_BYTES),
        "observations":imported,
        "profile":selection,
        "selected_components_declared":components,
        "actual_runtime_components_attested":False,
        "device_measurement_independently_verified":False,
        "telemetry_collector_attested":False,
        "approved_for_legacy_port":False,
        "auto_port_allowed":False,
        "note":"Input hashes prove file identity, not the authenticity of game-present hooks, temperature data, or runtime components."
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--timestamps",required=True)
    p.add_argument("--metadata",required=True)
    p.add_argument("--profile",required=True)
    p.add_argument("--registry",default="components/registry.json")
    p.add_argument("--output")
    a=p.parse_args()
    record=build_bundle(a.timestamps,a.metadata,a.profile,a.registry)
    raw=json.dumps(record,ensure_ascii=False,sort_keys=True,indent=2)+"\n"
    if a.output:
        path=Path(a.output)
        if path.is_symlink():raise ValueError("SYMLINK_OUTPUT_REFUSED")
        path.write_text(raw,encoding="utf-8")
    else:
        print(raw,end="")

if __name__=="__main__":
    main()
