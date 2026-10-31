#!/usr/bin/env python3
"""Stage SHA-pinned upstream VKD3D-Proton v3.0.1 x64 PE files into APK assets.
Actual device Vulkan/WSI success is NOT implied by this build-time check."""
import argparse
import hashlib
import json
import pathlib
import shutil
import struct

ARCHIVE_SHA256 = "3cf2315522af5e43605ef6d3c41dad91387040bf97199934f3f7ab76caaa2f0c"
VERSION = "v3.0.1"
SCHEMA = "rm11.v49073.vkd3d-proton-provider.v1"


def sha_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as src:
        for data in iter(lambda: src.read(1024 * 1024), b""):
            digest.update(data)
    return digest.hexdigest()


def validate_pe64(path):
    data = pathlib.Path(path).read_bytes()
    if len(data) < 4096 or data[:2] != b"MZ":
        raise ValueError(f"Not an executable Windows DLL: {path}")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if not 0x40 <= pe <= min(len(data) - 26, 4096):
        raise ValueError("Invalid PE header offset")
    if data[pe:pe+4] != b"PE\x00\x00":
        raise ValueError("Invalid Windows PE signature")
    if struct.unpack_from("<H", data, pe+4)[0] != 0x8664:
        raise ValueError("Not x86-64 PE")
    if struct.unpack_from("<H", data, pe+24)[0] != 0x20B:
        raise ValueError("Not PE32+ (64-bit)")


def find_x64(root, name):
    matches = [x for x in pathlib.Path(root).rglob(name)
               if x.is_file() and x.parent.name.lower() in ("x64", "x86_64", "64")]
    if len(matches) != 1:
        raise ValueError(f"Expected one x64/{name}; found {len(matches)}")
    return matches[0]


def stage(archive, unpacked, app):
    archive = pathlib.Path(archive)
    if sha_file(archive) != ARCHIVE_SHA256:
        raise ValueError("Pinned upstream VKD3D-Proton archive hash mismatch")
    asset = pathlib.Path(app) / "src/main/assets/engine/providers/vkd3d"
    out = asset / "x64"
    out.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema": SCHEMA,
        "upstream": "HansKristian-Work/vkd3d-proton",
        "upstream_tag": VERSION,
        "upstream_archive_sha256": ARCHIVE_SHA256,
        "mode": "EXPERIMENTAL_X11_SOFTWARE_WSI_DEVICE_PROOF_REQUIRED",
        "files": {}
    }
    for dll in ("d3d12.dll", "d3d12core.dll"):
        original = find_x64(unpacked, dll)
        validate_pe64(original)
        dest = out / dll
        shutil.copyfile(original, dest)
        if sha_file(original) != sha_file(dest):
            raise ValueError(f"Copied DLL hash mismatch: {dll}")
        manifest["files"][dll] = sha_file(dest)
    (asset / "vkd3d-provider.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("R4_V49073_UPSTREAM_VKD3D_3_0_1_PE64_HASHED_ASSETS_STAGED_UNPROVEN")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--archive", required=True)
    p.add_argument("--unpacked", required=True)
    p.add_argument("--app", default="app")
    args = p.parse_args()
    stage(args.archive, args.unpacked, args.app)


if __name__ == "__main__":
    main()
