#!/usr/bin/env python3
"""KERNIX two-component bundle audit; preserves upstream separation.

Only run on extracted, verified CI artifact contents. Not an installer or a
Windows launcher. Prevents blending mismatched DXGI/D3D12 components silently.
"""
import argparse
import hashlib
import json
from pathlib import Path
from kernix_component_payload_gate import verify_tree

SUPPORTED = {
    "dxvk": {"repository": "doitsujin/dxvk", "required": {"d3d11.dll", "dxgi.dll"}},
    "vkd3d": {"repository": "HansKristian-Work/vkd3d-proton", "required": {"d3d12.dll"}},
}


def validate_pair(dxvk_root, dxvk_manifest, vkd3d_root, vkd3d_manifest):
    result = {}
    for kind, root, manifest_path in (
        ("dxvk", dxvk_root, dxvk_manifest),
        ("vkd3d", vkd3d_root, vkd3d_manifest),
    ):
        path = Path(manifest_path)
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if manifest.get("component", {}).get("kind") != kind:
            raise ValueError("COMPONENT_KIND_MISMATCH:" + kind)
        if manifest.get("source", {}).get("repository") != SUPPORTED[kind]["repository"]:
            raise ValueError("UNEXPECTED_UPSTREAM:" + kind)
        audit = verify_tree(root, manifest)
        names = {
            Path(entry["path"]).name.lower()
            for entry in manifest["files"]
            if entry["format"] == "pe"
        }
        if not SUPPORTED[kind]["required"].issubset(names):
            raise ValueError("REQUIRED_WINDOWS_DLL_MISSING:" + kind)
        result[kind] = {
            "component_id": audit["component_id"],
            "source_commit": manifest["source"]["git_commit"],
            "files": len(manifest["files"]),
            "manifest_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "required_dlls_present": sorted(SUPPORTED[kind]["required"]),
        }
    return {
        "schema": "kernix.dxvk-vkd3d-composition-audit.v1",
        "separate_components": result,
        "same_abi_pe64": True,
        "d3d12_needs_dxvk_dxgi": True,
        "verified_binaries_are_installed": False,
        "wine_dxgi_override_tested": False,
        "android_vulkan_tested": False,
        "game_tested": False,
        "note": "Integrity and component coexistence only. Requires a compatible Windows runtime, CPU translation, Vulkan driver, and tested DLL override setup."
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dxvk-root", required=True)
    p.add_argument("--dxvk-manifest", required=True)
    p.add_argument("--vkd3d-root", required=True)
    p.add_argument("--vkd3d-manifest", required=True)
    p.add_argument("--output", required=True)
    a=p.parse_args()
    result=validate_pair(a.dxvk_root,a.dxvk_manifest,a.vkd3d_root,a.vkd3d_manifest)
    Path(a.output).write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print("KERNIX_INDEPENDENT_DXVK_VKD3D_COMPOSITION_AUDIT_PASS")


if __name__=="__main__":
    main()
