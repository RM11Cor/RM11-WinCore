#!/usr/bin/env python3
"""Validate Termux:X11 Android AAR/JNI as a vendorable *component*, not an RM11 APK.

GPLv3: source is pinned upstream; use only with corresponding source and notices.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
from zipfile import ZipFile

PIN = "7e5f5c5c9226e2cdab392b2efba91bc4bd86463e"
CLASSES = [
    "com/termux/x11/LorieView.class",
    "com/termux/x11/CmdEntryPoint.class",
    "com/termux/x11/MainActivity.class",
    "com/termux/x11/LorieApp.class",
]

def require(cond, description):
    if not cond:
        raise RuntimeError("RM11_V4_AAR_GATE_FAILED: " + description)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--aar", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    args = p.parse_args()
    require(args.aar.is_file(), "upstream Android AAR missing")
    with ZipFile(args.aar) as outer:
        so_name = "jni/arm64-v8a/libXlorie.so"
        require(so_name in outer.namelist(), "native ARM64 X.Org ELF missing from AAR")
        native=outer.read(so_name)
        require(len(native)>300000, "native X.Org library suspiciously small")
        require(native[:4]==b"\x7fELF" and native[4]==2 and native[5]==1 and
                int.from_bytes(native[18:20],"little")==183,
                "native AAR ELF architecture is not aarch64")
        require("classes.jar" in outer.namelist(), "Java JNI bridge missing")
        with ZipFile(io.BytesIO(outer.read("classes.jar"))) as classes:
            missing=sorted(set(CLASSES)-set(classes.namelist()))
            require(not missing,"missing JNI/UI classes: "+repr(missing))
        require("AndroidManifest.xml" in outer.namelist(),"library app manifest missing")
        supported=[item for item in outer.namelist() if
                   item.startswith("jni/") and item.endswith("/libXlorie.so")]
        report = {
            "schema": "rm11.v4.android-lorie-aar-audit.v1",
            "upstream_source": "https://github.com/termux/termux-x11",
            "upstream_pin": PIN,
            "license": "GPL-3.0",
            "aar_sha256": hashlib.sha256(args.aar.read_bytes()).hexdigest(),
            "arm64_xorg_elf_sha256": hashlib.sha256(native).hexdigest(),
            "arm64_xorg_elf_size": len(native),
            "jni_modules": supported,
            "required_java_classes": CLASSES,
            "compiled_android_ui_and_jni_together": True,
            "linked_to_rm11_application": False,
            "android_surface_frame_received": False,
            "wine_gui_text_visible": False,
            "signed_rm11_apk_release_allowed": False,
        }
        args.report.parent.mkdir(parents=True,exist_ok=True)
        args.report.write_text(json.dumps(report,indent=2)+"\n")
        print("RM11_V4_NATIVE_ANDROID_AAR_AND_JNI_BUNDLED: YES")
        print("RM11_V4_ARM64_XLORIE_ELF_VERIFIED: YES")
        print("RM11_V4_NATIVE_BACKEND_IN_RM11_APPLICATION: NOT_YET")
        print("RM11_V4_WINE_TEXT_RENDERED_ON_ANDROID: NOT_YET")

if __name__=="__main__":
    main()
