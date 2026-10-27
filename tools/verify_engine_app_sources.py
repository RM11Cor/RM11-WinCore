#!/usr/bin/env python3
"""Verify RM11 app and isolated enginebridge compile together for Android.

This reports build-time linkage only. It does not create a runnable APK,
install Wine, drive Vulkan/X11, or prove Windows game rendering.
"""
import argparse
import hashlib
import io
import json
import zipfile
from pathlib import Path

APP_MAIN = "com/rm11/autocore/MainActivity.class"
ENGINE_MAIN = "com/rm11/autocore/engine/EngineOwnedProcessSession.class"
ENGINE_NATIVE = "jni/arm64-v8a/librm11_engine_supervisor.so"


def audit(app_class_root, aar_path):
    compiled_app = Path(app_class_root)
    aar_path = Path(aar_path)
    if not (compiled_app / APP_MAIN).is_file():
        raise ValueError("ENGINE_APP_REAL_MAIN_ACTIVITY_NOT_COMPILED")
    # Duplicate engine implementations across app and AAR can cause dex
    # duplicate-class errors and unsafe mixed Wine versions.
    if (compiled_app / ENGINE_MAIN).exists():
        raise ValueError("ENGINE_BRIDGE_JAVA_COMPILED_TWICE")
    with zipfile.ZipFile(aar_path) as aar:
        if ENGINE_NATIVE not in aar.namelist():
            raise ValueError("ENGINE_BRIDGE_AAR_NATIVE_MISSING")
        with zipfile.ZipFile(io.BytesIO(aar.read("classes.jar"))) as jar:
            if ENGINE_MAIN not in jar.namelist():
                raise ValueError("ENGINE_BRIDGE_AAR_JAVA_MISSING")
        native=aar.read(ENGINE_NATIVE)
    return {
        "schema": "rm11.engine.app-java-linkage.v1",
        "app_main_class_compiled": True,
        "engine_jar_class_present": True,
        "duplicate_engine_java_in_app": False,
        "arm64_native_library_present_in_engine_aar": True,
        "engine_aar_sha256": hashlib.sha256(aar_path.read_bytes()).hexdigest(),
        "engine_native_sha256": hashlib.sha256(native).hexdigest(),
        "compiled_android_app_source": True,
        "android_app_apk_built": False,
        "engine_session_activation": "OFF",
        "wine_fex_execution": "UNVERIFIED",
        "dxvk_turnip_android_frame": "UNVERIFIED",
        "ready_to_release": False
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--app-classes",required=True)
    p.add_argument("--engine-aar",required=True)
    p.add_argument("--out",required=True)
    args=p.parse_args()
    result=audit(args.app_classes,args.engine_aar)
    text=json.dumps(result,sort_keys=True,indent=2)+"\n"
    print(text)
    Path(args.out).write_text(text,encoding="utf-8")


if __name__=="__main__":
    main()
