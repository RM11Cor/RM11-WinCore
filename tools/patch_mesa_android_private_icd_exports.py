#!/usr/bin/env python3
"""Repair Mesa 26.2.0's *Android-only* ICD symbol export list, fail-closed.

The official Android Vulkan HAL version map exposes HMI, not the public
Linux Vulkan ICD loader entries. RM11's **app-private** libadrenotools /
Wine child must use vk_icdGetInstanceProcAddr; exporting it by exact
name is necessary before runtime hardware checks are possible.
This patch does NOT imply GPU enumeration, KGSL, WSI or game frames.
"""
import argparse
import json
from pathlib import Path

ICD = (
    "vk_icdGetInstanceProcAddr",
    "vk_icdNegotiateLoaderICDInterfaceVersion",
    "vk_icdGetPhysicalDeviceProcAddr",
)

def patch(root):
    root = Path(root)
    version_map = root / "src/vulkan/vulkan-android.sym"
    android_symbols = root / "src/vulkan/vulkan-icd-android-symbols.txt"
    normal_map = root / "src/vulkan/vulkan.sym"
    files = (version_map, android_symbols, normal_map)
    if any(p.is_symlink() or not p.is_file() for p in files):
        raise ValueError("RM11_TURNIP_PINNED_EXPORT_SOURCE_ABSENT")
    m = version_map.read_text(encoding="utf-8")
    a = android_symbols.read_text(encoding="utf-8")
    normal = normal_map.read_text(encoding="utf-8")
    if not all(name + ";" in normal for name in ICD):
        raise ValueError("RM11_TURNIP_NATIVE_ICD_EXPORT_SOURCE_MISSING")
    if (m.count("\t\tHMI;") != 1 or m.count("\tlocal:") != 1
            or m.count("\t\t*;") != 1
            or m.count("\tglobal:") != 1 or not m.strip().endswith("};")
            or a.count("\nHMI\n") != 1):
        raise ValueError("RM11_TURNIP_ANDROID_EXPORT_MAP_SOURCE_DRIFT")
    if any(name in m or name in a for name in ICD):
        raise ValueError("RM11_TURNIP_ANDROID_EXPORT_MAP_PARTIAL_OR_PREPATCHED")
    # Explicitly export ONLY the same three exact upstream Linux ICD symbols.
    # Preserve the Android HMI and the local:* rule to avoid symbol collisions.
    added = "".join("\n\t\t" + name + ";" for name in ICD)
    map_after = m.replace("\t\tHMI;", "\t\tHMI;" + added, 1)
    symbols_after = a.rstrip("\n") + "\n" + "\n".join(ICD) + "\n"
    if map_after.count("\t\tHMI;") != 1 or "local:" not in map_after:
        raise ValueError("RM11_TURNIP_ANDROID_HAL_EXPORT_DROPPED")
    # Check all preconditions before writing either source file.
    version_map.write_text(map_after, encoding="utf-8")
    android_symbols.write_text(symbols_after, encoding="utf-8")
    return {
        "schema":"rm11.turnip.android-app-private-icd-exports.v1",
        "source_release":"mesa-26.2.0",
        "exported_symbols_expected":list(ICD),
        "hal_hmi_retained":True,
        "local_other_symbols_retained":True,
        "host_elf_export_verification":"REQUIRED_AFTER_LINK",
        "on_device_vulkan_instance_verified":False,
        "on_device_gpu_enumeration_verified":False,
        "release_game_ready":False,
    }

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()
    result = patch(args.source)
    dst = Path(args.out)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print("RM11_TURNIP_ANDROID_APP_PRIVATE_ICD_EXPORTS_SOURCE_PATCHED_NO_GPU_PROOF")

if __name__ == "__main__":
    main()
