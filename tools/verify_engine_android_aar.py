#!/usr/bin/env python3
"""Gate for the AAR built from RM11 vNext Java source and Android NDK ELF.

Never claims that an AAR has been installed, that Bionic executed the native
process, or that X11/DXVK/Turnip can display a Windows game frame.
"""
import argparse
import hashlib
import io
import json
import zipfile
from pathlib import Path

from verify_android_native_supervisor import audit_bytes

AAR_LIBRARY = "jni/arm64-v8a/librm11_engine_supervisor.so"
WINE_VULKAN_LIBRARY = "jni/arm64-v8a/librm11_vnext_wine_vkbridge.so"
JAVA_CLASSES = (
    "com/rm11/autocore/engine/EngineOwnedProcessSession.class",
    "com/rm11/autocore/engine/EngineOwnedProcessSession$OwnedProcess.class",
    "com/rm11/autocore/engine/EngineDataStager.class",
    "com/rm11/autocore/engine/EngineInstalledTreeVerifier.class",
)


def audit(aar_path, expected_elf_path, expected_vulkan_bridge_path=None):
    aar_path = Path(aar_path)
    expected_elf_path = Path(expected_elf_path)
    with expected_elf_path.open("rb") as f:
        native = f.read()
    expected_digest = hashlib.sha256(native).hexdigest()
    bridge_digest = None
    if expected_vulkan_bridge_path is not None:
        bridge_bytes = Path(expected_vulkan_bridge_path).read_bytes()
        if len(bridge_bytes) < 4096 or len(bridge_bytes) > 4 * 1024 * 1024:
            raise ValueError("ENGINE_AAR_VULKAN_BRIDGE_ELF_SIZE_UNSAFE")
        bridge_digest = hashlib.sha256(bridge_bytes).hexdigest()
        if bridge_bytes[:6] != b"\x7fELF\x02\x01":
            raise ValueError("ENGINE_AAR_VULKAN_BRIDGE_NOT_ELF64")
        import struct
        if struct.unpack_from("<HH", bridge_bytes, 16) != (3, 183):
            raise ValueError("ENGINE_AAR_VULKAN_BRIDGE_NOT_AARCH64_DYN")
    if len(native) > 16 * 1024 * 1024:
        raise ValueError("ENGINE_NATIVE_SIZE_EXCEEDS_LIMIT")
    with zipfile.ZipFile(aar_path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("ENGINE_AAR_DUPLICATE_ENTRIES")
        if AAR_LIBRARY not in names:
            raise ValueError("ENGINE_AAR_MISSING_ARM64_NATIVE_SUPERVISOR")
        binary = archive.read(AAR_LIBRARY)
        if hashlib.sha256(binary).hexdigest() != expected_digest:
            raise ValueError("ENGINE_AAR_NATIVE_SUPERVISOR_SHA_CHANGED")
        matching = sorted(n for n in names if n.startswith("jni/") and n.endswith(".so"))
        expected_names = sorted([AAR_LIBRARY] + ([WINE_VULKAN_LIBRARY] if bridge_digest else []))
        if matching != expected_names:
            raise ValueError("ENGINE_AAR_UNKNOWN_NATIVE_LIBRARIES")
        if bridge_digest is not None:
            if hashlib.sha256(archive.read(WINE_VULKAN_LIBRARY)).hexdigest() != bridge_digest:
                raise ValueError("ENGINE_AAR_WINE_VULKAN_BRIDGE_SHA_CHANGED")
        if "classes.jar" not in names:
            raise ValueError("ENGINE_AAR_MISSING_ANDROID_JAVA_CLASSES")
        with zipfile.ZipFile(io.BytesIO(archive.read("classes.jar"))) as jar:
            classes = set(jar.namelist())
            missing = [name for name in JAVA_CLASSES if name not in classes]
            if missing:
                raise ValueError("ENGINE_ANDROID_CLASS_NOT_COMPILED:" + missing[0])
            # No legacy runtime classes can leak into the vNext bridge AAR.
            foreign = [name for name in classes
                       if name.endswith(".class")
                       and not name.startswith("com/rm11/autocore/engine/")]
            if foreign:
                raise ValueError("ENGINE_ANDROID_AAR_MIXED_LEGACY_CODE")
    abi = audit_bytes(binary)
    if abi.get("status") != "ELF_STRUCTURE_READY_FOR_ANDROID_DEVICE_PROOF":
        raise ValueError("ENGINE_ANDROID_AAR_NATIVE_ABI_NOT_VERIFIED")
    return {
        "schema": "rm11.engine.android-source-aar.v1",
        "aar_sha256": hashlib.sha256(aar_path.read_bytes()).hexdigest(),
        "native_sha256": expected_digest,
        "wine_vulkan_bridge_sha256": bridge_digest,
        "wine_vulkan_bridge_packaged_inactive": bridge_digest is not None,
        "wine_child_vulkan_linked_at_runtime": False,
        "compiled_java_classes_present": list(JAVA_CLASSES),
        "signed_native_source_elf_staged": True,
        "native_executable_entry": AAR_LIBRARY,
        "actual_android_gradle_module_compiled": True,
        "elf_abi_gate": abi["status"],
        "legacy_game_launcher_changed": False,
        "engine_activated": False,
        "app_apk_built": False,
        "android_device_execution": "UNVERIFIED",
        "dxvk_turnip_x11_frame_proof": "UNVERIFIED",
        "releasable_apk": False,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("aar")
    p.add_argument("native_elf")
    p.add_argument("--wine-vulkan-bridge")
    p.add_argument("--out")
    args = p.parse_args()
    result = audit(args.aar, args.native_elf, args.wine_vulkan_bridge)
    message = json.dumps(result, indent=2, sort_keys=True) + "\n"
    print(message)
    if args.out:
        Path(args.out).write_text(message, encoding="utf-8")


if __name__ == "__main__":
    main()
