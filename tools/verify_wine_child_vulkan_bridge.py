#!/usr/bin/env python3
"""Fail-closed architecture/import audit of the child-only bridge."""
import argparse
import json
import re
import struct
from pathlib import Path

def validate(path, dynamic, symbols):
    p = Path(path)
    if not p.is_file() or p.is_symlink() or p.stat().st_size < 4096:
        raise ValueError("RM11_VNEXT_BRIDGE_ELF_MISSING")
    b = p.read_bytes()
    if b[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<HH",b,16)!=(3,183):
        raise ValueError("RM11_VNEXT_BRIDGE_ABI_INVALID")
    needed = sorted(set(re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", dynamic)))
    if "libc.so" not in needed or any(x in needed for x in ("libhardware.so","libc.so.6")):
        raise ValueError("RM11_VNEXT_BRIDGE_PRIVATE_DEPENDENCY")
    # The bridge is NEVER a Wine loader binary or Vulkan driver itself.
    if "rm11_vnext_open_vulkan" not in symbols or "rm11_vnext_vulkan_policy" not in symbols:
        raise ValueError("RM11_VNEXT_BRIDGE_MISSING_EXPORTS")
    return {"schema":"rm11.engine.wine-child-vulkan-bridge.elf.v1",
            "architecture":"aarch64", "android_abi":"bionic",
            "dynamic_needed":needed,"native_elf_verified":True,
            "installed_in_apk":False,"verified_in_real_wine_child":False,
            "actual_custom_turnip_selected":False,
            "adreno_physical_device_enumerated":False,
            "x11_android_game_frame_proven":False, "safe_to_release":False}

def main():
    cli=argparse.ArgumentParser()
    for key in ("elf","dynamic","symbols","out"):
        cli.add_argument("--"+key,required=True)
    args=cli.parse_args()
    result=validate(args.elf,Path(args.dynamic).read_text(),Path(args.symbols).read_text())
    Path(args.out).write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("RM11_WINE_CHILD_VULKAN_BRIDGE_ANDROID_STATIC_GATE_PASS_NO_DEVICE")

if __name__=="__main__":
    main()
