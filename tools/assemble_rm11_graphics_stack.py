#!/usr/bin/env python3
"""Assemble provenance-verified DXVK/Turnip/AdrenoTools CI candidate, no APK.

Artifacts are downloaded independently from known successful workflow runs.
Never make this an installable APK or claim Vulkan runtime/Android frame proof.
"""
import argparse
import hashlib
import json
import struct
import zipfile
from pathlib import Path

from engine_graphics_provider_audit import pe_amd64, elf_aarch64

DXVK_SHA = "c3dd74be6baec53786d4e064a572185b70347a17"
MESA_TARBALL = "efd4bb08cdb7c365a812cd4e6c9202ab55b2f22cdcd13c7d6c4f9647b799a4ef"
ADRENO_SHA = "8fae8ce254dfc1344527e05301e43f37dea2df80"
HOOKS = ("libadrenotools.so", "libhook_impl.so", "libmain_hook.so",
         "libfile_redirect_hook.so", "libgsl_alloc_hook.so")


def one(root, name):
    root = Path(root)
    matches = list(root.rglob(name))
    if len(matches) != 1 or not matches[0].is_file() or matches[0].is_symlink():
        raise ValueError("RM11_GRAPHICS_COMPONENT_AMBIGUOUS_OR_MISSING:" + name)
    p = matches[0]
    if not 0 < p.stat().st_size < 180 * 1024 * 1024:
        raise ValueError("RM11_GRAPHICS_COMPONENT_SIZE_UNSAFE:" + name)
    return p


def json_one(root, name):
    return json.loads(one(root, name).read_text(encoding="utf-8"))


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def add_file(files, target, source, expected, check):
    blob = Path(source).read_bytes()
    if len(blob) < 512 or digest(blob) != expected:
        raise ValueError("RM11_GRAPHICS_PROVIDER_HASH_MISMATCH:" + target)
    if not check(blob[:8192]):
        raise ValueError("RM11_GRAPHICS_PROVIDER_ABI_MISMATCH:" + target)
    if target in files:
        raise ValueError("RM11_GRAPHICS_PROVIDER_DUPLICATE_OUTPUT:" + target)
    files[target] = blob


def stage(dxvk_dir, turnip_dir, adreno_dir, libcxx_file):
    dx = json_one(dxvk_dir, "dxvk-win64-source-provenance.json")
    tu = json_one(turnip_dir, "turnip-android-source-abi.json")
    aim = json_one(turnip_dir, "aimapper5-source-provenance.json")
    ad = json_one(adreno_dir, "adrenotools-native-linkproof.json")
    if (dx.get("source_commit") != DXVK_SHA or
            dx.get("source_build_verified") is not True or
            dx.get("can_publish_game_apk") is not False):
        raise ValueError("RM11_GRAPHICS_DXVK_PROVENANCE_UNVERIFIED")
    if (tu.get("mesa_upstream_tar_sha256") != MESA_TARBALL or
            tu.get("static_elf_abi_verified") is not True or
            tu.get("icd_public_elf_symbols_verified") is not True or
            set(tu.get("icd_exported_functions",[])) != {
                "vk_icdGetInstanceProcAddr",
                "vk_icdNegotiateLoaderICDInterfaceVersion",
                "vk_icdGetPhysicalDeviceProcAddr"} or
            tu.get("app_linker_namespace_gate") !=
            "UNVERIFIED_APP_NAMESPACE_LOADABILITY" or
            tu.get("safe_to_publish_engine_apk") is not False):
        raise ValueError("RM11_GRAPHICS_TURNIP_PROVENANCE_UNVERIFIED")
    if (aim.get("upstream_commit") !=
            "c71f600a2977a141f21a922c9ed2e14fb09b13d3" or
            aim.get("source_spdx") != "MIT" or
            aim.get("mesa_26_2_single_layer_compat_applied") is not True or
            aim.get("safe_to_publish_apk") is not False):
        raise ValueError("RM11_GRAPHICS_AIMAPPER_PROVENANCE_UNVERIFIED")
    if (ad.get("upstream_commit") != ADRENO_SHA or
            ad.get("source_link_abi_verified") is not True or
            ad.get("safe_to_publish_apk") is not False):
        raise ValueError("RM11_GRAPHICS_LOADER_PROVENANCE_UNVERIFIED")
    files = {}
    for dll in ("d3d11.dll", "dxgi.dll"):
        metadata = dx["pe_files"][dll]
        if (metadata["source_commit"] != DXVK_SHA or
                metadata["architecture"] != "x86_64" or
                metadata["validated_pe_header"] is not True):
            raise ValueError("RM11_GRAPHICS_DXVK_PE_METADATA_INVALID:" + dll)
        add_file(files, "dxvk/x64/" + dll, one(dxvk_dir, dll),
                 metadata["sha256"], pe_amd64)
    add_file(files, "native/arm64-v8a/libvulkan_freedreno.so",
             one(turnip_dir, "libvulkan_freedreno.so"), tu["elf_sha256"],
             elf_aarch64)
    for library in HOOKS:
        entry = ad["binaries"][library]
        if entry["architecture"] != "aarch64":
            raise ValueError("RM11_GRAPHICS_ADRENO_ABI_WRONG:" + library)
        add_file(files, "native/arm64-v8a/" + library,
                 one(adreno_dir, library), entry["sha256"], elf_aarch64)
    libcxx = Path(libcxx_file)
    if (libcxx.is_symlink() or libcxx.name != "libc++_shared.so" or
            not libcxx.is_file()):
        raise ValueError("RM11_GRAPHICS_NDK_LIBCXX_MISSING")
    libcbytes = libcxx.read_bytes()
    if not elf_aarch64(libcbytes[:8192]):
        raise ValueError("RM11_GRAPHICS_NDK_LIBCXX_ABI_WRONG")
    files["native/arm64-v8a/libc++_shared.so"] = libcbytes
    manifest = {
        "schema": "rm11.engine.graphics-build-candidate.v1",
        "source_runs": {"dxvk": 40584764808, "turnip_aimapper": 40629557489,
                        "adrenotools": 40590287552},
        "mesa_tar_sha256": MESA_TARBALL,
        "dxvk_commit": DXVK_SHA, "adrenotools_commit": ADRENO_SHA,
        "ndk_version": "27.2.12479018",
        "files": {name: {"sha256": digest(data), "size": len(data)}
                  for name, data in sorted(files.items())},
        "structural_source_artifacts_verified": True,
        "turnip_icd_public_exports_verified": True,
        "signed_apk_installed": False,
        "winedll_override_applied": False,
        "wine_child_custom_loader_verified": False,
        "android_turnip_dlopen_verified": False,
        "adreno_gpu_enumeration_verified": False,
        "x11_game_pixels_on_android_verified": False,
        "safe_to_release": False,
        "note": "CI content-addressed evidence only; not executable on device",
    }
    return files, manifest


def write_bundle(files, manifest, out_zip, out_report):
    out_zip = Path(out_zip)
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    metadata = json.dumps(manifest, sort_keys=True, indent=2) + "\n"
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=6) as out:
        for name, data in sorted(files.items()):
            out.writestr(name, data)
        out.writestr("graphics-candidate-manifest.json", metadata.encode())
    Path(out_report).write_text(metadata, encoding="utf-8")
    with zipfile.ZipFile(out_zip) as z:
        assert z.testzip() is None
        for name, info in manifest["files"].items():
            assert digest(z.read(name)) == info["sha256"]
    print("RM11_GRAPHICS_CANDIDATE_STATIC_CLOSURE_PASS_DEVICE_UNVERIFIED")


def main():
    p = argparse.ArgumentParser()
    for name in ("dxvk", "turnip", "adrenotools", "libcxx", "out", "report"):
        p.add_argument("--" + name, required=True)
    a = p.parse_args()
    files, manifest = stage(a.dxvk, a.turnip, a.adrenotools, a.libcxx)
    write_bundle(files, manifest, a.out, a.report)


if __name__ == "__main__":
    main()
