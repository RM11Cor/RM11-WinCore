#!/usr/bin/env python3
"""Verify the Android debug APK assembled from RM11 vNext source.

This is a private CI artifact produced and deleted in the workflow. It proves
Gradle packaging and **not** Wine/FEX execution or rendering.
"""
import argparse
import hashlib
import json
import zipfile
from pathlib import Path
from engine_graphics_provider_audit import inspect as graphics_provider_inspect

SUPERVISOR="lib/arm64-v8a/librm11_engine_supervisor.so"
WINE_VULKAN_BRIDGE="lib/arm64-v8a/librm11_vnext_wine_vkbridge.so"
REQUIRED=("AndroidManifest.xml","classes.dex",SUPERVISOR)
MAX_ELF=16*1024*1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def audit(apk_path,expected_elf_path,legacy_manifest_path=None,expected_bridge_path=None):
    apk_path=Path(apk_path)
    expected_elf_path=Path(expected_elf_path)
    native=expected_elf_path.read_bytes()
    if len(native)>MAX_ELF:raise ValueError("NATIVE_TOO_LARGE")
    with zipfile.ZipFile(apk_path) as a:
        files=a.infolist()
        names=[x.filename for x in files]
        if len(names)!=len(set(names)):
            raise ValueError("APK_DUPLICATE_ENTRIES")
        missing=[x for x in REQUIRED if x not in names]
        if missing:raise ValueError("SOURCE_APK_MISSING:"+missing[0])
        found=a.read(SUPERVISOR)
        bridge_hash = None
        if expected_bridge_path is not None:
            if WINE_VULKAN_BRIDGE not in names:
                raise ValueError("SOURCE_APK_WINE_VULKAN_BRIDGE_MISSING")
            bridge=Path(expected_bridge_path).read_bytes()
            built=a.read(WINE_VULKAN_BRIDGE)
            if (len(bridge)<4096 or len(bridge)>4*1024*1024 or
                    len(built)!=len(bridge)):
                raise ValueError("SOURCE_APK_WINE_VULKAN_BRIDGE_SIZE_INVALID")
            if digest(built)!=digest(bridge):
                raise ValueError("SOURCE_APK_WINE_VULKAN_BRIDGE_SHA_CHANGED")
            import struct
            if (built[:6]!=b"\x7fELF\x02\x01" or
                    struct.unpack_from("<HH",built,16)!=(3,183)):
                raise ValueError("SOURCE_APK_WINE_VULKAN_BRIDGE_ELF_INVALID")
            bridge_hash=digest(bridge)
        if digest(found)!=digest(native):
            raise ValueError("SOURCE_APK_SUPERVISOR_BINARY_CHANGED")
        if len(found)<4096 or found[:4]!=b"\x7fELF":
            raise ValueError("SOURCE_APK_NATIVE_NOT_ELF")
        native_names=sorted(x for x in names if x.startswith("lib/arm64-v8a/"))
        # Do not call the old legacy build "ready" just because the host
        # activity compiles. Report the presence of the historical runtime.
        legacy={
            n:n in names for n in (
                "lib/arm64-v8a/libwineprobe.so",
                "lib/arm64-v8a/libwineserverrm11.so",
                "lib/arm64-v8a/libXlorie.so",
                "assets/runtime/rm11-wine-stack.zip",
            )
        }
        if not all(legacy.values()):
            raise ValueError("SOURCE_APK_LEGACY_WINE_RUNTIME_INCOMPLETE")
        if a.getinfo(SUPERVISOR).compress_type != zipfile.ZIP_STORED:
            # Keep this an informational distinction: compressed native
            # binaries can be extracted to nativeLibraryDir when
            # android:extractNativeLibs=true. It is not a loader verdict.
            pass
        verified_legacy={}
        if legacy_manifest_path is None:
            raise ValueError("SOURCE_APK_TRUSTED_RUNTIME_MANIFEST_REQUIRED")
        trusted=json.loads(Path(legacy_manifest_path).read_text(encoding="utf-8"))
        if trusted.get("baseline_apk_sha256")!="1f6c511e6949080e9ec41b6b08ae724cccc49d5c10491db16db9bb32371e34e8":
            raise ValueError("SOURCE_APK_PINNED_BASELINE_ID_CHANGED")
        components=trusted.get("pinned_runtime_components",{})
        for name in ("lib/arm64-v8a/libwineprobe.so",
                     "lib/arm64-v8a/libwineserverrm11.so",
                     "assets/runtime/rm11-wine-stack.zip"):
            expected=components.get(name,{}).get("sha256")
            if not expected or len(expected)!=64:
                raise ValueError("SOURCE_APK_RUNTIME_DIGEST_NOT_PINNED:"+name)
            hasher=hashlib.sha256()
            with a.open(name) as source:
                for block in iter(lambda: source.read(1024*1024),b""):
                    hasher.update(block)
            if hasher.hexdigest()!=expected:
                raise ValueError("SOURCE_APK_RUNTIME_BYTES_MODIFIED:"+name)
            verified_legacy[name]=expected
        internal_asset="assets/engine/engine-native-manifest.json"
        if internal_asset not in names:
            raise ValueError("SOURCE_APK_SIGNED_ENGINE_MANIFEST_MISSING")
        engine=json.loads(a.read(internal_asset).decode("utf-8"))
        if (engine.get("schema")!="rm11.engine.native-manifest.v1"
                or engine.get("android_package")!="com.rm11.autocore"
                or engine.get("activation")!="DISABLED_UNTIL_HARDWARE_WINE_FRAME_PROOF"
                or engine.get("safe_to_release_as_game_fix") is not False
                or engine.get("legacy_wine_only") is not True):
            raise ValueError("SOURCE_APK_ENGINE_MANIFEST_ACTIVATION_UNSAFE")
        components=engine.get("components",{})
        expected_native={
            "supervisor":SUPERVISOR,
            "wine_loader":"lib/arm64-v8a/libwineprobe.so",
            "wine_server":"lib/arm64-v8a/libwineserverrm11.so",
            "wine_stack":"assets/runtime/rm11-wine-stack.zip",
        }
        engine_component_hashes={}
        for key,apk_entry in expected_native.items():
            info=components.get(key,{})
            expected=info.get("sha256")
            if info.get("apk_path")!=apk_entry or not isinstance(expected,str):
                raise ValueError("SOURCE_APK_ENGINE_MANIFEST_COMPONENT_MISSING:"+key)
            hasher=hashlib.sha256()
            with a.open(apk_entry) as e:
                for block in iter(lambda:e.read(1024*1024),b""):
                    hasher.update(block)
            if hasher.hexdigest()!=expected:
                raise ValueError("SOURCE_APK_ENGINE_MANIFEST_COMPONENT_TAMPERED:"+key)
            engine_component_hashes[key]=expected
        if engine_component_hashes["supervisor"]!=digest(native):
            raise ValueError("SOURCE_APK_ENGINE_MANIFEST_SUPERVISOR_MISMATCH")
        manifest=a.getinfo("AndroidManifest.xml")
        return {
            "schema":"rm11.engine.private-source-debug-apk.v1",
            "apk_sha256":hashlib.file_digest(apk_path.open("rb"),"sha256").hexdigest(),
            "supervisor_sha256":digest(native),
            "wine_vulkan_bridge_sha256":bridge_hash,
            "wine_vulkan_bridge_zip_hash_verified":bridge_hash is not None,
            "wine_child_vulkan_runtime_active":False,
            "supervisor_elf_matches_compiled_ndk_binary":True,
            "supervisor_zip_method":a.getinfo(SUPERVISOR).compress_type,
            "compiled_android_manifest_size":manifest.file_size,
            "legacy_native_entries_present":legacy,
            "pinned_old_runtime_content_hashes_verified":verified_legacy,
            "legacy_runtime_compatibility_only":True,
            # Signed Wine/FEX inputs are necessary but NOT hardware-game-ready.
            # Actual D3D11 DXVK and Turnip providers must be checked by
            # independent binary-identity/ABI gates, not by file names.
            "graphics_provider_static_gate":graphics_provider_inspect(apk_path)["static_provider_gate"],
            "graphics_device_frame_proof":"UNVERIFIED",
            "embedded_signed_engine_manifest_verified":True,
            "engine_component_hashes_verified":engine_component_hashes,
            "engine_activation":"OFF",
            "arm64_native_library_entries":native_names,
            "java_dex_present":True,
            "source_app_apk_compiled":True,
            "production_signed":False,
            "installed_on_device":False,
            "wine_fex_execution":"UNVERIFIED",
            "vulkan_x11_actual_game_pixels":"UNVERIFIED",
            "safe_to_release":False,
        }


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("apk")
    parser.add_argument("native")
    parser.add_argument("--out",required=True)
    parser.add_argument("--legacy-manifest",required=True)
    parser.add_argument("--wine-vulkan-bridge")
    a=parser.parse_args()
    result=audit(a.apk,a.native,a.legacy_manifest,a.wine_vulkan_bridge)
    text=json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True)+"\n"
    Path(a.out).write_text(text)
    print(text)


if __name__=="__main__":main()
