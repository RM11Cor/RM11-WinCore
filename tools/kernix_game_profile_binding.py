#!/usr/bin/env python3
"""Read-only exact-game-image binding for KERNIX data-only profiles.

Never launches code, applies byte patches, selects a runtime or modifies games.
A PS4 SELF/PKG is deliberately outside the Windows PE G0/G2 runtime.
"""
import argparse
import json
from pathlib import Path

from kernix_game_preflight import inspect
from kernix_game_profiles import read_json, validate_profile


def bind(profile, registry, executable):
    result = validate_profile(profile, registry)
    file_path = Path(executable)
    if file_path.is_symlink():
        raise ValueError("SYMLINK_GAME_EXECUTABLE_DENIED")
    metadata = inspect(file_path)
    if metadata["architecture"] != "x86_64" or metadata["pe_format"] != "PE32+":
        raise ValueError("WINDOWS_X86_64_PE32_PLUS_REQUIRED")
    if metadata["sha256"] != result["game_sha256"]:
        raise ValueError("EXACT_GAME_EXECUTABLE_SHA256_MISMATCH")
    return {
        "schema": "kernix.game-profile-file-binding.v1",
        "game_sha256": result["game_sha256"],
        "game_image_format": "windows-pe32+-x86_64",
        "file_size_bytes": metadata["size_bytes"],
        "verified_component_ids": result["component_ids"],
        "profile_binding": "exact-file-hash-verified-static-only",
        "profile_enabled": False,
        "launch_qualified": False,
        "guest_code_executed": False,
        "game_files_modified": False,
        "binary_patches_applied": False,
        "android_device_tested": False,
        "note": "Hash match binds identity only. FEX/Wine/graphics/driver compatibility still requires actual device/runtime evidence. PS4 SELF/PKG needs a separate backend."
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--registry", default="components/registry.json")
    args = parser.parse_args()
    print(json.dumps(bind(read_json(args.profile),read_json(args.registry),
                          args.executable),indent=2,ensure_ascii=False))


if __name__ == "__main__":
    main()
