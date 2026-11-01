#!/usr/bin/env python3
"""KERNIX read-only compatibility registry v1.

Registry is inventory, not a component installer. Unknown is not compatible.
Never enables an engine, runs a game, or changes a Wine prefix.
"""
import argparse
import json
from pathlib import Path

KINDS = {"wine", "proton", "fex", "dxvk", "vkd3d", "turnip"}
GRAPHICS_REQUIREMENTS = {
    "Direct3D 9": "dxvk",
    "Direct3D 10": "dxvk",
    "Direct3D 10.1": "dxvk",
    "Direct3D 11": "dxvk",
    "Direct3D 12": "vkd3d",
}
MAX_COMPONENTS = 200

def validate(registry):
    if registry.get("schema") != "kernix.component-registry.v1":
        raise ValueError("INVALID_REGISTRY_SCHEMA")
    entries = registry.get("components")
    if not isinstance(entries, list) or len(entries) > MAX_COMPONENTS:
        raise ValueError("INVALID_COMPONENT_LIST")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("INVALID_COMPONENT")
        if set(entry) != {"id", "kind", "version", "abi", "sha256", "verified", "requires"}:
            raise ValueError("INVALID_COMPONENT_FIELDS")
        ident = entry["id"]
        if not isinstance(ident, str) or not ident or ident in seen:
            raise ValueError("DUPLICATE_OR_INVALID_ID")
        seen.add(ident)
        if entry["kind"] not in KINDS or not isinstance(entry["version"], str) or not entry["version"]:
            raise ValueError("INVALID_KIND_OR_VERSION")
        if entry["abi"] not in ("arm64", "arm64ec", "x86_64"):
            raise ValueError("INVALID_ABI")
        digest = entry["sha256"]
        if not isinstance(digest, str) or len(digest) != 64 or any(x not in "0123456789abcdef" for x in digest):
            raise ValueError("UNVERIFIED_HASH")
        if entry["verified"] is not True:
            raise ValueError("COMPONENT_NOT_VERIFIED")
        if not isinstance(entry["requires"], list) or any(not isinstance(x,str) for x in entry["requires"]):
            raise ValueError("INVALID_REQUIRES")
    by_id = {entry["id"]:entry for entry in entries}
    for entry in entries:
        if entry["id"] in entry["requires"]:
            raise ValueError("SELF_DEPENDENCY")
        if any(dep not in by_id for dep in entry["requires"]):
            raise ValueError("MISSING_DEPENDENCY")
    visiting, done = set(), set()
    def walk(ident):
        if ident in visiting: raise ValueError("DEPENDENCY_CYCLE")
        if ident in done: return
        visiting.add(ident)
        for dep in by_id[ident]["requires"]: walk(dep)
        visiting.remove(ident)
        done.add(ident)
    for ident in by_id: walk(ident)
    return by_id

def propose(registry, game_scan):
    by_id = validate(registry)
    if game_scan.get("schema") != "kernix.pe-import-audit.v1":
        raise ValueError("INVALID_GAME_SCAN")
    indicators = game_scan.get("graphics_api_indicators", [])
    if not isinstance(indicators,list):
        raise ValueError("INVALID_GRAPHICS_INDICATORS")
    required = sorted({GRAPHICS_REQUIREMENTS[g] for g in indicators if g in GRAPHICS_REQUIREMENTS})
    available = sorted({item["kind"] for item in by_id.values()})
    missing = sorted(set(required) - set(available))
    ambiguous = ("DXGI (version unspecified)" in indicators or not indicators)
    return {
        "schema": "kernix.compatibility-proposal.v1",
        "required_graphics_wrapper_kinds": required,
        "missing_verified_component_kinds": missing,
        "observed_graphics_indicators": indicators,
        "needs_runtime_validation": True,
        "may_select_automatically": False,
        "insufficient_evidence": ambiguous,
        "available_verified_component_count": len(by_id),
        "note": "Static imports are only hints. Runtime resolution, matched ABI, renderer and driver support must be validated."
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--registry",default="components/registry.json")
    p.add_argument("--game-scan",required=True)
    a=p.parse_args()
    registry=json.loads(Path(a.registry).read_text(encoding="utf-8"))
    game=json.loads(Path(a.game_scan).read_text(encoding="utf-8"))
    print(json.dumps(propose(registry,game),indent=2))

if __name__ == "__main__":
    main()
