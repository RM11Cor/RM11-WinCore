#!/usr/bin/env python3
"""KERNIX v1 static game analysis and conservative, source-independent run plan.

Design: upstream component sources are separate from installation, pairing and game
launch. This module proposes required *capabilities*, never installs, executes,
or claims that the device/game actually works.
"""
import argparse
import json
from pathlib import Path

from kernix_game_preflight import inspect
from kernix_pe_imports import analyze
from kernix_component_registry import validate

MAX_ADJACENT = 256
ENGINE_MARKERS = {
    "Unity": ("UnityPlayer.dll", "GameAssembly.dll", "MonoBleedingEdge"),
    "Unreal Engine": ("Engine", "UE4Game-Win64-Shipping.exe", "UnrealEditor.exe"),
}
# These are static file-name hints, not guaranteed engine identification.
RUNTIME_INDICATORS = {
    "d3d9.dll": "dxvk",
    "d3d10.dll": "dxvk",
    "d3d10_1.dll": "dxvk",
    "d3d11.dll": "dxvk",
    "d3d12.dll": "vkd3d",
}
WINDOWS_API = {"wine", "proton"}


def adjacent_markers(game_path):
    parent = Path(game_path).resolve().parent
    names = set()
    count = 0
    try:
        for item in parent.iterdir():
            count += 1
            if count > MAX_ADJACENT:
                return {"engine_hints": [], "directory_scan_truncated": True}
            # Do not follow symlinks into other folders.
            if not item.is_symlink():
                names.add(item.name.casefold())
    except OSError:
        return {"engine_hints": [], "directory_scan_truncated": True}
    result = []
    for engine, markers in ENGINE_MARKERS.items():
        matching = sorted(m for m in markers if m.casefold() in names)
        if matching:
            result.append({"engine": engine, "evidence": matching, "confidence": "hint_only"})
    return {"engine_hints": result, "directory_scan_truncated": False}


def plan(exe, registry):
    pe = inspect(exe)
    imports = analyze(exe)
    installed = validate(registry)
    dlls = set(imports["static_imports"])
    wrappers = sorted({kind for dll, kind in RUNTIME_INDICATORS.items() if dll in dlls})
    arch = pe["architecture"]
    warnings = list(pe["hints"])
    if "dxgi.dll" in dlls and not wrappers:
        warnings.append("DXGI alone cannot establish Direct3D 11 vs 12")
    if not wrappers:
        warnings.append("The graphics API may be loaded dynamically or by another executable")
    if arch not in ("x86", "x86_64"):
        warnings.append("Unsupported or atypical Windows CPU architecture")
    # API-independent dependency: translation and Windows runtime are needed on Android ARM.
    desired = ["fex", "wine_or_proton", "turnip"] + wrappers if arch in ("x86","x86_64") else []
    by_kind = {}
    for comp in installed.values():
        by_kind.setdefault(comp["kind"], []).append({
            "id": comp["id"], "version": comp["version"], "abi": comp["abi"]
        })
    for kind in by_kind:
        by_kind[kind].sort(key=lambda x: (x["version"], x["id"]))
    available = {}
    missing = []
    for kind in desired:
        candidates = ([*by_kind.get("wine", []), *by_kind.get("proton", [])]
                      if kind == "wine_or_proton" else by_kind.get(kind, []))
        # A catalog is not proof of a complete, dependency-closed bootable runtime.
        available[kind] = candidates
        if not candidates:
            missing.append(kind)
    hints = adjacent_markers(exe)
    return {
        "schema": "kernix.native-game-plan.v1",
        "game_sha256": pe["sha256"],
        "architecture": arch,
        "subsystem": pe["subsystem"],
        "static_imports": sorted(dlls),
        "graphics_api_hints": imports["graphics_api_indicators"],
        "engine_hints": hints["engine_hints"],
        "directory_scan_truncated": hints["directory_scan_truncated"],
        "required_component_capabilities": desired,
        "verified_registry_candidates": available,
        "missing_verified_capabilities": missing,
        "warnings": warnings,
        "runtime_tested": False,
        "device_qualified": False,
        "game_started": False,
        "first_frame_verified": False,
        "may_apply_automatically": False,
        "note": "Static evidence only; driver ABI, Wine/FEX dependencies and renderer need runtime checks."
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe")
    parser.add_argument("--registry", default="components/registry.json")
    parser.add_argument("--output")
    a = parser.parse_args()
    registry = json.loads(Path(a.registry).read_text(encoding="utf-8"))
    result = json.dumps(plan(a.exe, registry), indent=2, ensure_ascii=False) + "\n"
    if a.output:
        Path(a.output).write_text(result, encoding="utf-8")
    else:
        print(result, end="")


if __name__ == "__main__":
    main()
