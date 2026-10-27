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

SUPERVISOR="lib/arm64-v8a/librm11_engine_supervisor.so"
REQUIRED=("AndroidManifest.xml","classes.dex",SUPERVISOR)
MAX_ELF=16*1024*1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def audit(apk_path,expected_elf_path,legacy_manifest_path=None):
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
        manifest=a.getinfo("AndroidManifest.xml")
        return {
            "schema":"rm11.engine.private-source-debug-apk.v1",
            "apk_sha256":hashlib.file_digest(apk_path.open("rb"),"sha256").hexdigest(),
            "supervisor_sha256":digest(native),
            "supervisor_elf_matches_compiled_ndk_binary":True,
            "supervisor_zip_method":a.getinfo(SUPERVISOR).compress_type,
            "compiled_android_manifest_size":manifest.file_size,
            "legacy_native_entries_present":legacy,
            "pinned_old_runtime_content_hashes_verified":verified_legacy,
            "legacy_runtime_compatibility_only":True,
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
    a=parser.parse_args()
    result=audit(a.apk,a.native,a.legacy_manifest)
    text=json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True)+"\n"
    Path(a.out).write_text(text)
    print(text)


if __name__=="__main__":main()
