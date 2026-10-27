#!/usr/bin/env python3
"""Stage pinned graphics providers into an INTERNAL source-built RM11 APK.

This is a packaging/identity gate, never a Wine hook or game activator.
Source artifacts must first pass assemble_rm11_graphics_stack.py.
"""
import argparse
import hashlib
import json
import re
import stat
import zipfile
from pathlib import Path

from assemble_rm11_graphics_stack import DXVK_SHA, MESA_TARBALL, ADRENO_SHA, HOOKS
from engine_graphics_provider_audit import pe_amd64, elf_aarch64, inspect

DXVK_NAMES = ("d3d11.dll", "dxgi.dll")
NATIVE_NAMES = ("libvulkan_freedreno.so",) + HOOKS + ("libc++_shared.so",)
SOURCE_RUNS = {"dxvk": 40584764808, "turnip_aimapper": 40589960744,
               "adrenotools": 40590287552}
INPUT_NAMES = {"dxvk/x64/" + n for n in DXVK_NAMES} | {
    "native/arm64-v8a/" + n for n in NATIVE_NAMES}
MANIFEST_NAME = "graphics-candidate-manifest.json"
APK_MANIFEST = "assets/engine/engine-bundle-manifest.json"
MAX_FILE = 180 * 1024 * 1024
MAX_TOTAL = 450 * 1024 * 1024
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
OFF = "DISABLED_UNTIL_HARDWARE_WINE_FRAME_PROOF"


def fail(code):
    raise ValueError("RM11_GRAPHICS_APK_" + code)


def digest(stream):
    h = hashlib.sha256()
    size = 0
    head = bytearray()
    while True:
        block = stream.read(1024 * 1024)
        if not block:
            break
        size += len(block)
        if size > MAX_FILE:
            fail("OVERSIZED_COMPONENT")
        if len(head) < 8192:
            head.extend(block[:8192 - len(head)])
        h.update(block)
    return h.hexdigest(), size, bytes(head)


def verify_candidate(candidate, report):
    expected = json.loads(Path(report).read_text(encoding="utf-8"))
    if (expected.get("schema") != "rm11.engine.graphics-build-candidate.v1"
            or expected.get("source_runs") != SOURCE_RUNS
            or expected.get("dxvk_commit") != DXVK_SHA
            or expected.get("mesa_tar_sha256") != MESA_TARBALL
            or expected.get("adrenotools_commit") != ADRENO_SHA
            or expected.get("structural_source_artifacts_verified") is not True):
        fail("SOURCE_PROVENANCE_NOT_PINNED")
    for field in ("safe_to_release", "signed_apk_installed",
                  "winedll_override_applied", "wine_child_custom_loader_verified",
                  "android_turnip_dlopen_verified", "adreno_gpu_enumeration_verified",
                  "x11_game_pixels_on_android_verified"):
        if expected.get(field) is not False:
            fail("RUNTIME_PROOF_CLAIM_UNTRUSTED_" + field.upper())
    files = expected.get("files")
    if not isinstance(files, dict) or set(files) != INPUT_NAMES:
        fail("COMPONENT_SET_INCOMPLETE")
    with zipfile.ZipFile(candidate) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if len(names) != len(INPUT_NAMES) + 1 or set(names) != INPUT_NAMES | {MANIFEST_NAME}:
            fail("ARCHIVE_HAS_MISSING_EXTRA_OR_DUPLICATE_ENTRY")
        meta = archive.getinfo(MANIFEST_NAME)
        if meta.file_size < 32 or meta.file_size > 32768:
            fail("CANDIDATE_MANIFEST_SIZE")
        if json.loads(archive.read(meta)) != expected:
            fail("MANIFEST_SIDECAR_MISMATCH")
        total = 0
        for info in entries:
            if (stat.S_IFMT(info.external_attr >> 16) == stat.S_IFLNK
                    or info.is_dir() or info.flag_bits & 0x1):
                fail("SYMLINK_DIRECTORY_OR_ENCRYPTED")
            if info.filename == MANIFEST_NAME:
                continue
            record = files[info.filename]
            if (not isinstance(record, dict)
                    or not isinstance(record.get("sha256"), str)
                    or not SHA64.fullmatch(record["sha256"])
                    or type(record.get("size")) is not int
                    or not (512 <= record["size"] <= MAX_FILE)
                    or record["size"] != info.file_size):
                fail("COMPONENT_METADATA_INVALID")
            total += info.file_size
            if total > MAX_TOTAL:
                fail("COMPONENT_TOTAL_TOO_LARGE")
            with archive.open(info) as stream:
                sha, size, head = digest(stream)
            if sha != record["sha256"] or size != record["size"]:
                fail("COMPONENT_SHA256_MISMATCH_" + info.filename)
            valid = pe_amd64(head) if info.filename.startswith("dxvk/") else elf_aarch64(head)
            if not valid:
                fail("COMPONENT_ARCHITECTURE_MISMATCH_" + info.filename)
    return expected


def create_apk_manifest(candidate_manifest):
    items = candidate_manifest["files"]
    def record(original, target, architecture):
        return {"apk_path": target, "architecture": architecture,
                "sha256": items[original]["sha256"]}
    pe_files = {
        name: record("dxvk/x64/" + name,
                     "assets/engine/providers/dxvk/x64/" + name, "x86_64")
        for name in DXVK_NAMES
    }
    natives = {
        name: record("native/arm64-v8a/" + name,
                     "lib/arm64-v8a/" + name, "aarch64")
        for name in NATIVE_NAMES
    }
    return {
        "schema": "rm11.engine.bundle.v1",
        "android_package": "com.rm11.autocore",
        "source_runs": SOURCE_RUNS,
        "dxvk": {"provider": "dxvk", "source_commit": DXVK_SHA,
                 "pe_files": pe_files},
        "gpu": {"driver": "turnip", "source_archive_sha256": MESA_TARBALL,
                "apk_library": "lib/arm64-v8a/libvulkan_freedreno.so",
                "sha256": natives["libvulkan_freedreno.so"]["sha256"],
                "architecture": "aarch64", "libc": "bionic",
                "wsi": "UNVERIFIED_ON_DEVICE"},
        "native_components": natives,
        "activation": OFF,
        "device_hardware_frame_proof": "UNVERIFIED",
        "wine_child_vulkan_loader_invoked": False,
        "safe_to_release": False,
    }


def stage(candidate, report, app):
    evidence = verify_candidate(candidate, report)
    app = Path(app)
    if not (app / "build.gradle").is_file():
        fail("APP_SOURCE_ROOT_MISSING")
    manifest = create_apk_manifest(evidence)
    outputs = {}
    for name in DXVK_NAMES:
        outputs["dxvk/x64/" + name] = (
            app / "src/main/assets/engine/providers/dxvk/x64" / name)
    for name in NATIVE_NAMES:
        outputs["native/arm64-v8a/" + name] = (
            app / "src/main/jniLibs/arm64-v8a" / name)
    manifest_path = app / "src/main/assets/engine/engine-bundle-manifest.json"
    if any(p.exists() or p.is_symlink() for p in list(outputs.values()) + [manifest_path]):
        fail("SOURCE_ALREADY_CONTAINS_GRAPHICS_PROVIDER")
    with zipfile.ZipFile(candidate) as archive:
        for name, dst in outputs.items():
            dst.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(name) as source, dst.open("xb") as target:
                while block := source.read(1024 * 1024):
                    target.write(block)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                             encoding="utf-8")
    return manifest


def audit_apk(path):
    with zipfile.ZipFile(path) as apk:
        names = [z.filename for z in apk.infolist()]
        if len(names) != len(set(names)) or APK_MANIFEST not in names:
            fail("APK_MANIFEST_ABSENT_OR_DUPLICATE")
        info = apk.getinfo(APK_MANIFEST)
        if info.file_size < 128 or info.file_size > 32768:
            fail("APK_MANIFEST_SIZE")
        data = json.loads(apk.read(info))
        if (data.get("schema") != "rm11.engine.bundle.v1"
                or data.get("android_package") != "com.rm11.autocore"
                or data.get("source_runs") != SOURCE_RUNS
                or data.get("activation") != OFF
                or data.get("safe_to_release") is not False
                or data.get("device_hardware_frame_proof") != "UNVERIFIED"
                or data.get("wine_child_vulkan_loader_invoked") is not False
                or data.get("dxvk", {}).get("source_commit") != DXVK_SHA
                or data.get("gpu", {}).get("source_archive_sha256") != MESA_TARBALL):
            fail("APK_MANIFEST_RELEASE_OR_SOURCE_UNSAFE")
        files = {
            "lib/arm64-v8a/" + name: data.get("native_components", {}).get(name)
            for name in NATIVE_NAMES
        }
        for name in DXVK_NAMES:
            key = "assets/engine/providers/dxvk/x64/" + name
            files[key] = data.get("dxvk", {}).get("pe_files", {}).get(name)
        if len(files) != 9:
            fail("APK_COMPONENT_COUNT_INVALID")
        for entry_path, entry in files.items():
            if (not isinstance(entry, dict) or entry.get("apk_path") != entry_path
                    or not isinstance(entry.get("sha256"), str)
                    or not SHA64.fullmatch(entry["sha256"]) or entry_path not in names):
                fail("APK_COMPONENT_MISSING_" + entry_path)
            with apk.open(entry_path) as source:
                sha, size, head = digest(source)
            if (sha != entry["sha256"] or size < 512
                    or not (pe_amd64(head) if entry_path.endswith(".dll")
                            else elf_aarch64(head))):
                fail("APK_COMPONENT_CHANGED_" + entry_path)
    provider = inspect(path)
    if provider["static_provider_gate"] != "PROVIDER_BINARIES_STRUCTURALLY_VERIFIED":
        fail("DXVK_TURNIP_PROVIDER_AUDIT_FAILED")
    return {"schema": "rm11.engine.graphics-apk-static-closure.v1",
            "component_count": 9, "all_apk_content_hashes_match": True,
            "source_pins_verified": True, "apk_native_load_unverified": True,
            "wine_child_hook_active": False, "hardware_frame_proof": "UNVERIFIED",
            "safe_to_release": False}


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("stage")
    s.add_argument("--candidate", required=True)
    s.add_argument("--report", required=True)
    s.add_argument("--app", default="app")
    a = sub.add_parser("audit")
    a.add_argument("apk")
    a.add_argument("--out", required=True)
    args = p.parse_args()
    if args.mode == "stage":
        result = stage(args.candidate, args.report, args.app)
        print("RM11_PINNED_GRAPHICS_STAGED_IN_SOURCE activation=" + result["activation"])
    else:
        result = audit_apk(args.apk)
        Path(args.out).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print("RM11_NINE_GRAPHICS_COMPONENTS_SIGNED_CONTENT_STATICALLY_VERIFIED_NO_DEVICE_PROOF")


if __name__ == "__main__":
    main()
