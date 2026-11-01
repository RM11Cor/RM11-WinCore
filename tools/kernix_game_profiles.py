#!/usr/bin/env python3
"""KERNIX immutable per-game profile validation. No game launch or shared engine writes."""
import argparse
import hashlib
import json
import re
from pathlib import Path
from kernix_component_registry import validate as validate_registry

SHA = re.compile(r"^[a-f0-9]{64}$")
MODES = {"performance", "compatibility", "balanced"}
SLOTS = {"wine", "proton", "fex", "dxvk", "vkd3d", "turnip"}
MAX_PROFILE_BYTES = 65536

def profile_key(exe_sha256):
    if not isinstance(exe_sha256, str) or SHA.fullmatch(exe_sha256) is None:
        raise ValueError("INVALID_GAME_HASH")
    return exe_sha256

def validate_profile(profile, registry):
    items = validate_registry(registry)
    if profile.get("schema") != "kernix.game-profile.v1":
        raise ValueError("INVALID_PROFILE_SCHEMA")
    if set(profile) != {"schema", "game_sha256", "mode", "components", "enabled"}:
        raise ValueError("INVALID_PROFILE_FIELDS")
    profile_key(profile["game_sha256"])
    if profile["mode"] not in MODES:
        raise ValueError("INVALID_MODE")
    if profile["enabled"] is not False:
        raise ValueError("UNQUALIFIED_PROFILE_MUST_REMAIN_DISABLED")
    selections = profile["components"]
    if not isinstance(selections, dict) or not set(selections).issubset(SLOTS):
        raise ValueError("INVALID_COMPONENT_SLOTS")
    if "wine" in selections and "proton" in selections:
        raise ValueError("CONFLICTING_WINDOWS_RUNTIMES")
    selected = set()
    for slot, ident in selections.items():
        if not isinstance(ident, str) or ident not in items:
            raise ValueError("UNKNOWN_OR_UNVERIFIED_COMPONENT")
        if items[ident]["kind"] != slot:
            raise ValueError("COMPONENT_KIND_MISMATCH")
        if ident in selected:
            raise ValueError("DUPLICATE_COMPONENT")
        selected.add(ident)
    for ident in selected:
        if not set(items[ident]["requires"]).issubset(selected):
            raise ValueError("PROFILE_MISSING_DEPENDENCY")
    if any(items[ident]["abi"] == "x86_64" for ident in selected):
        raise ValueError("UNSUPPORTED_HOST_COMPONENT_ABI")
    return {
        "schema": "kernix.game-profile-validation.v1",
        "game_sha256": profile["game_sha256"],
        "component_ids": sorted(selected),
        "mode": profile["mode"],
        "profile_enabled": False,
        "launch_qualified": False,
        "runtime_modified": False,
    }

def read_json(path):
    path = Path(path)
    if not path.is_file() or path.stat().st_size > MAX_PROFILE_BYTES:
        raise ValueError("INVALID_OR_OVERSIZED_PROFILE")
    return json.loads(path.read_text(encoding="utf-8"))

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--profile",required=True)
    p.add_argument("--registry",default="components/registry.json")
    a=p.parse_args()
    print(json.dumps(validate_profile(read_json(a.profile), read_json(a.registry)), indent=2))

if __name__ == "__main__":
    main()
