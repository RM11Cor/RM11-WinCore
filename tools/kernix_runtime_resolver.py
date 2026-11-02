#!/usr/bin/env python3
"""Deterministic KERNIX runtime composition from *verified* component bundles.

This is a lock-plan compiler, not a loader or downloader. The installer and
Android host must separately verify actual bytes, ELF/PE ABI and launch results.
Never assumes latest upstream version is compatible.
"""
import argparse
import hashlib
import json
from pathlib import Path

from kernix_component_registry import validate as validate_registry

SLOTS = ("wine", "proton", "fex", "dxvk", "vkd3d", "turnip")
WINDOWS = {"wine", "proton"}
MAX_LOCK_BYTES = 65536


def _validate_selection(selection, by_id):
    if not isinstance(selection, dict) or not selection:
        raise ValueError("EMPTY_OR_INVALID_SELECTION")
    if not set(selection).issubset(SLOTS):
        raise ValueError("UNKNOWN_SLOT")
    if set(selection).intersection(WINDOWS) == WINDOWS:
        raise ValueError("CONFLICTING_WINDOWS_RUNTIMES")
    selected = {}
    for kind, ident in selection.items():
        if not isinstance(ident, str) or ident not in by_id:
            raise ValueError("UNKNOWN_COMPONENT_ID")
        item = by_id[ident]
        if item["kind"] != kind:
            raise ValueError("MISMATCHED_COMPONENT_KIND")
        if item["abi"] == "x86_64":
            raise ValueError("HOST_ABI_INCOMPATIBLE")
        selected[ident] = item
    if len(selected) != len(selection):
        raise ValueError("REUSED_COMPONENT_ID")
    return selected


def compose(registry, selection, game_hash, *, required=()):
    """Compile immutable run settings, verifying direct + transitive closure."""
    if not isinstance(game_hash, str) or len(game_hash) != 64 or any(
        c not in "0123456789abcdef" for c in game_hash
    ):
        raise ValueError("INVALID_GAME_HASH")
    by_id = validate_registry(registry)
    selected = _validate_selection(selection, by_id)
    if not ("fex" in selection and "turnip" in selection and
            len(set(selection).intersection(WINDOWS)) == 1):
        raise ValueError("MISSING_BOOTSTRAP_COMPONENTS")
    kinds = set(selection)
    if not isinstance(required, (list, tuple)) or not set(required).issubset(
        {"dxvk", "vkd3d"}
    ):
        raise ValueError("INVALID_REQUIREMENTS")
    if not set(required).issubset(kinds):
        raise ValueError("MISSING_GAME_GRAPHICS_REQUIREMENTS")

    # Explicit dependencies, including dependencies not directly selected by
    # the game's graphics API, cannot be silently pulled in from an unverified
    # directory; all must be in the lock.
    for ident, component in selected.items():
        for dep in component["requires"]:
            if dep not in selected:
                raise ValueError("DEPENDENCY_NOT_SELECTED:" + ident + ":" + dep)

    # Stable sorted topological build order. Dependency first, no dependence
    # on JSON map insertion order or upstream release latest ordering.
    order, visited = [], set()
    def visit(ident):
        if ident in visited:
            return
        for dep in sorted(selected[ident]["requires"]):
            visit(dep)
        visited.add(ident)
        order.append(ident)
    for ident in sorted(selected):
        visit(ident)

    immutable = [{
        "id": ident,
        "kind": selected[ident]["kind"],
        "version": selected[ident]["version"],
        "abi": selected[ident]["abi"],
        "sha256": selected[ident]["sha256"],
        "requires": sorted(selected[ident]["requires"]),
    } for ident in order]
    result = {
        "schema": "kernix.runtime-lock.v1",
        "game_sha256": game_hash,
        "components": immutable,
        "slots": {k: selection[k] for k in sorted(selection)},
        "validated_dependencies": True,
        "runtime_tested": False,
        "gpu_qualified": False,
        "first_frame_verified": False,
        "installable": False,
        "note": "Immutable selection recipe only; installer must hash-check actual payloads and verify ABI before enablement."
    }
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > MAX_LOCK_BYTES:
        raise ValueError("RUNTIME_LOCK_TOO_LARGE")
    result["plan_sha256"] = hashlib.sha256(encoded).hexdigest()
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--registry", default="components/registry.json")
    p.add_argument("--selection", required=True, help="JSON object mapping component type to verified component id")
    p.add_argument("--game-sha256", required=True)
    p.add_argument("--required", nargs="*", default=[])
    a = p.parse_args()
    reg = json.loads(Path(a.registry).read_text(encoding="utf-8"))
    selected = json.loads(Path(a.selection).read_text(encoding="utf-8"))
    print(json.dumps(compose(reg, selected, a.game_sha256, required=a.required), indent=2))


if __name__ == "__main__":
    main()
