#!/usr/bin/env python3
"""KERNIX universal game assessment stage: read-only, for every added PC game.

This is identity and static dependency discovery, NOT a component resolver,
benchmark, Wine/FEX runtime, patcher, or game-compatibility guarantee.
"""
import argparse
import json
from pathlib import Path

from kernix_game_preflight import inspect
from kernix_pe_imports import analyze
from kernix_game_profile_binding import bind
from kernix_game_profiles import read_json

# Only explicit static imports are hints. DXGI alone never establishes D3D API.
DIRECT_GRAPHICS_TO_FAMILY = {
    "d3d9.dll": "dxvk-d3d9-candidate",
    "d3d10.dll": "dxvk-d3d10-candidate",
    "d3d10_1.dll": "dxvk-d3d10-candidate",
    "d3d11.dll": "dxvk-d3d11-candidate",
    "d3d12.dll": "vkd3d-proton-d3d12-candidate",
    "vulkan-1.dll": "native-vulkan-investigation",
    "opengl32.dll": "opengl-investigation",
    "ddraw.dll": "legacy-directdraw-investigation",
}

def _file_identity(path):
    if path.is_symlink():
        raise ValueError("SYMLINK_GAME_EXECUTABLE_DENIED")
    if not path.is_file():
        raise ValueError("GAME_EXECUTABLE_NOT_FOUND")
    stat = path.stat()
    if not stat.st_size:
        raise ValueError("EMPTY_GAME_EXECUTABLE")
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)

def assess(executable, profile=None, registry=None):
    """Offline inspection of any chosen PE, regardless of prior playability."""
    path = Path(executable)
    before = _file_identity(path)
    meta = inspect(path)  # streams SHA256; does not run the executable
    audit_status = "parsed"
    audit_error = None
    imports = []
    graphics = []
    try:
        audit = analyze(path)  # bounded PE static import table only
        imports = audit["static_imports"]
        graphics = audit["graphics_api_indicators"]
    except ValueError as exc:
        # A missing/malformed/oversized import table is UNKNOWN, not "no API".
        audit_status = "unavailable"
        audit_error = str(exc)
    after = _file_identity(path)
    if before != after:
        raise ValueError("GAME_CHANGED_DURING_ANALYSIS")
    if (profile is None) != (registry is None):
        raise ValueError("PROFILE_AND_REGISTRY_REQUIRED_TOGETHER")
    linked_profile = None
    if profile is not None:
        # Existing separate SHA-verified, disabled profile gate remains in force.
        linked_profile = bind(profile, registry, path)
        if before != _file_identity(path):
            raise ValueError("GAME_CHANGED_DURING_PROFILE_BINDING")
    families = sorted({DIRECT_GRAPHICS_TO_FAMILY[name]
                       for name in imports if name in DIRECT_GRAPHICS_TO_FAMILY})
    arch = meta["architecture"]
    candidate = ("windows-x86_64-pe" if arch == "x86_64" and
                 meta["pe_format"] == "PE32+" else "unqualified-other-pe")
    return {
        "schema": "kernix.universal-game-assessment.v1",
        "assess_all_game_states": ["working", "failing", "not_yet_tested"],
        "identity": {
            "executable_sha256": meta["sha256"],
            "file_size_bytes": meta["size_bytes"],
            "architecture": arch,
            "pe_format": meta["pe_format"],
            "subsystem": meta["subsystem"],
            "machine_hex": meta["machine_hex"],
        },
        "backend_candidate": candidate,
        "static_import_audit": {
            "status": audit_status,
            "reason_if_unavailable": audit_error,
            "direct_imports": imports,
            "graphics_indicators": graphics,
            "dynamically_loaded_libraries_not_detected": True,
        },
        "component_families_to_investigate_not_install": families,
        "game_profile_binding": linked_profile,
        "optimization_objective": "correct_rendering_and_stable_frametimes_then_optional_quality",
        "measurement_needed": [
            "same_device_exact_build_and_preset",
            "first_real_frame_and_input",
            "median_fps_and_one_percent_low",
            "frametime_stutters",
            "rendering_artifacts_and_crashes",
            "sustained_thermal_and_memory_pressure",
        ],
        "candidate_version_selected": False,
        "compatibility_verified": False,
        "quality_or_fps_improvement_measured": False,
        "game_executed": False,
        "android_device_tested": False,
        "game_files_modified": False,
        "note": ("Static imports are hints, not required DirectX level or proof of "
                 "component compatibility. An absent import is not evidence of an "
                 "absent runtime requirement; no driver, DLL or patch is installed."),
    }

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--executable", required=True)
    ap.add_argument("--profile")
    ap.add_argument("--registry")
    args = ap.parse_args()
    profile = read_json(args.profile) if args.profile is not None else None
    registry = read_json(args.registry) if args.registry is not None else None
    print(json.dumps(assess(args.executable, profile, registry),
                     indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
