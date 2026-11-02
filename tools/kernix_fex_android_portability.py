#!/usr/bin/env python3
"""Classify actual Linux AArch64 ELF dependencies against Android Bionic.

This gate NEVER declares Linux/glibc binaries Android-ready. It produces
actionable dependency lists based on the real source-built FEX artifact.
"""
import argparse
import json
from pathlib import Path

LINUX_C_RUNTIME = {
    "libc.so.6", "libm.so.6", "libdl.so.2", "libpthread.so.0",
    "librt.so.1", "libresolv.so.2", "libutil.so.1",
    "ld-linux-aarch64.so.1",
}


def classify(report):
    if report.get("schema") != "kernix.fex-linux-arm64-elf-dependency-audit.v1":
        raise ValueError("unexpected FEX audit schema")
    if report.get("android_bionic_compatible") is not False:
        raise ValueError("Linux-only FEX cannot be marked Bionic-compatible")
    objects = report.get("files")
    if not isinstance(objects, list) or not objects:
        raise ValueError("no ELF objects")
    all_needed = set()
    all_interp = set()
    for item in objects:
        if item.get("elf_machine") != "AArch64":
            raise ValueError("mixed/unknown machine")
        if not item.get("sha256") or len(item["sha256"]) != 64:
            raise ValueError("ELF hash missing")
        all_needed.update(item.get("needed", []))
        all_interp.update(item.get("interpreter", []))
    glibc_needed = sorted(all_needed & LINUX_C_RUNTIME)
    glibc_loader = sorted(x for x in all_interp if "ld-linux" in x)
    other_needed = sorted(all_needed - LINUX_C_RUNTIME)
    return {
        "schema": "kernix.fex-android-portability-blockers.v1",
        "source_commit": report["source_commit"],
        "linux_elf_objects": len(objects),
        "glibc_library_dependencies": glibc_needed,
        "glibc_elf_interpreters": glibc_loader,
        "other_linux_link_dependencies": other_needed,
        "needs_android_bionic_rebuild_or_isolated_compatible_linux_runtime": True,
        "runtime_android_compatible": False,
        "android_apk_ready": False,
        "wine_runtime_connected": False,
        "priority": [
            "Select supported Android execution architecture: Bionic-native port or explicitly isolated Linux userspace",
            "Resolve ARM64 C runtime and ELF interpreter mismatches",
            "Provision x86-64 guest root filesystem or equivalent compatible Linux/Wine environment",
            "Integrate native Vulkan driver and DXVK/VKD3D with compatible Wine DLL loading",
            "Run device-level Windows EXE smoke test before claiming game compatibility",
        ],
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    a = p.parse_args()
    report = classify(json.loads(Path(a.input).read_text()))
    Path(a.output).parent.mkdir(parents=True, exist_ok=True)
    Path(a.output).write_text(json.dumps(report, indent=2) + "\n")
    print("KERNIX_FEX_ANDROID_PORTABILITY_CLASSIFIED")
    print("GLIBC_LOADER", report["glibc_elf_interpreters"])
    print("GLIBC_LIBRARIES", report["glibc_library_dependencies"])
    print("OTHER_LINUX_DEPENDENCIES", report["other_linux_link_dependencies"])
    print("ANDROID_READY=false")


if __name__ == "__main__":
    main()
