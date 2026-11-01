#!/usr/bin/env python3
"""KERNIX offline integrated game report: analysis -> proposal -> safe profile.

This is a desktop/CI tool only. It never executes games, installs components,
qualifies launches, or changes the shared Android runtime.
"""
import argparse
import json
from pathlib import Path
from kernix_game_preflight import inspect
from kernix_pe_imports import analyze
from kernix_component_registry import propose, validate as validate_registry
from kernix_game_profiles import validate_profile, read_json
from kernix_profile_store import save as save_profile

def evaluate(exe, registry, current_profile=None):
    components = validate_registry(registry)
    pe = inspect(exe)
    imports = analyze(exe)
    suggestion = propose(registry, imports)
    if current_profile is not None:
        if current_profile.get("game_sha256") != pe["sha256"]:
            raise ValueError("PROFILE_DOES_NOT_MATCH_GAME_FILE")
        profile = current_profile
    else:
        profile = {"schema":"kernix.game-profile.v1",
                   "game_sha256":pe["sha256"],"mode":"balanced",
                   "components":{},"enabled":False}
    status = validate_profile(profile, registry)
    return {
        "schema":"kernix.integrated-game-report.v1",
        "identity":{"filename":pe["file"],"sha256":pe["sha256"],
                    "architecture":pe["architecture"],"pe_format":pe["pe_format"],
                    "subsystem":pe["subsystem"]},
        "graphics":{"static_imports":imports["static_imports"],
                    "api_indicators":imports["graphics_api_indicators"],
                    "runtime_loaded_libraries_not_detected":True},
        "compatibility":suggestion,
        "profile":profile,
        "profile_validation":status,
        "verified_registry_entries":len(components),
        "source_only":True,
        "game_executed":False,
        "fps_measured":False,
        "autoselection_enabled":False,
        "device_qualified":False
    }

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe")
    parser.add_argument("--registry",default="components/registry.json")
    parser.add_argument("--profile")
    parser.add_argument("--output")
    parser.add_argument("--save-disabled-profile-root",help="Explicit opt-in: save a non-runnable profile to this directory")
    args=parser.parse_args()
    registry=read_json(args.registry)
    prior=read_json(args.profile) if args.profile else None
    report=evaluate(args.exe,registry,prior)
    if args.save_disabled_profile_root:
        report["profile_snapshot"]=save_profile(args.save_disabled_profile_root,report["profile"],registry)
    payload=json.dumps(report,indent=2,ensure_ascii=False,sort_keys=True)+"\n"
    if args.output:
        out=Path(args.output)
        if out.is_symlink():raise ValueError("SYMLINK_REPORT_OUTPUT_REFUSED")
        out.write_text(payload,encoding="utf-8")
    else:
        print(payload,end="")

if __name__=="__main__":
    main()
