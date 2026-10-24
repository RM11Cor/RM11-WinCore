#!/usr/bin/env python3
"""Fail-closed source/ARM64 ELF audit for the RM11 v4 native X11 migration.

This audit does NOT establish that Wine can paint text on a real display.
The pinned GPLv3 source is built only in an isolated, secret-free CI job.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

PIN = "7e5f5c5c9226e2cdab392b2efba91bc4bd86463e"
ANDROID_SYSTEM_LIBS = {
    "libandroid.so", "libmediandk.so", "libEGL.so", "libGLESv2.so",
    "liblog.so", "libm.so", "libc.so", "libdl.so", "libz.so",
    "libjnigraphics.so", "libvulkan.so", "libnativewindow.so",
}

def cmd(*args, cwd=None):
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=True)
    return result.stdout.strip()

def require(condition, description):
    if not condition:
        raise RuntimeError("RM11_V4_NATIVE_GATE_FAILED: " + description)

def audit(root: Path, elf: Path | None):
    require(root.is_dir(), "upstream source absent")
    revision = cmd("git", "rev-parse", "HEAD", cwd=root)
    require(revision == PIN, "unpinned upstream commit: " + revision)
    licence = (root / "LICENSE").read_text()
    require("GNU GENERAL PUBLIC LICENSE" in licence and "Version 3" in licence,
            "source GPL-3.0 license missing")
    module_lines = cmd("git", "submodule", "status", "--recursive", cwd=root).splitlines()
    require(len(module_lines) >= 15, "missing native Xorg dependency submodules")
    require(all(s and s[0] == " " for s in module_lines),
            "uninitialized/mismatched native dependency submodule")
    native = root / "lorie/src/main/cpp"
    cmake = (native / "recipes/xserver.cmake").read_text()
    require("add_library(Xlorie SHARED" in cmake, "upstream libXlorie target missing")
    require("add_library(xserver_render STATIC" in cmake, "Xrender source not in build")
    require("xserver_render" in cmake, "Xrender not in upstream project")
    for relative in ("lorie/activity.cpp", "lorie/cmdentrypoint.cpp",
                     "lorie/InitOutput.c", "xserver/render/render.c",
                     "xserver/dix/dispatch.c"):
        require((native / relative).is_file(), "native Xorg/JNI input missing: " + relative)
    result = {
        "schema": "rm11.v4.native-x11.build-audit.v1",
        "upstream": "https://github.com/termux/termux-x11",
        "upstream_revision": revision,
        "license": "GPL-3.0",
        "upstream_license_sha256": hashlib.sha256(licence.encode()).hexdigest(),
        "native_submodules_initialized": len(module_lines),
        "xorg_render_link_target_in_source": True,
        "jni_surface_and_cmd_bridge_in_source": True,
        "arm64_library_built": False,
        "actual_android_surface_rendered": False,
        "wine_glyphs_visible": False,
        "safe_to_publish_rm11_apk": False,
    }
    if elf is not None:
        require(elf.is_file(), "native library not produced")
        header = elf.read_bytes()[:20]
        require(header[:4] == b"\x7fELF", "native output not ELF")
        require(header[4] == 2 and header[5] == 1, "not a 64-bit little endian ELF")
        require(int.from_bytes(header[18:20], "little") == 183, "not ARM64 ELF")
        output = cmd("readelf", "-d", str(elf))
        dependencies = sorted(set(re.findall(r"Shared library: \[([^\]]+)\]", output)))
        require(dependencies, "native ELF DT_NEEDED missing")
        unexpected = sorted(set(dependencies) - ANDROID_SYSTEM_LIBS)
        require(not unexpected, "native shared dependency packaging unresolved: " + repr(unexpected))
        result["arm64_library_built"] = True
        result["arm64_library_size"] = elf.stat().st_size
        result["arm64_library_sha256"] = hashlib.sha256(elf.read_bytes()).hexdigest()
        result["elf_dt_needed"] = dependencies
        # A native ELF compiling successfully is not proof that its Android
        # activity bridge, sockets, or Wine glyphs function on the phone.
    return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--elf", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.source.resolve(), args.elf.resolve() if args.elf else None)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print("RM11_V4_NATIVE_X11_SOURCE_PIN", PIN)
    print("RM11_V4_NATIVE_X11_ARM64_COMPILED", result["arm64_library_built"])
    print("RM11_V4_NATIVE_X11_RUNTIME_RENDERING_VERIFIED", result["wine_glyphs_visible"])
    print("RM11_V4_USER_APK_RELEASE_ALLOWED", result["safe_to_publish_rm11_apk"])

if __name__ == "__main__":
    main()
