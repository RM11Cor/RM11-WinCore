#!/usr/bin/env python3
"""Read-only RM11 engine completeness audit of a previously signed APK.

This is an architectural release gate, not another on-device game experiment.
A PNG/WSI probe, file presence or a live wineserver is never taken as proof
that a Windows game renders. No binaries are modified or installed.
"""
import argparse
import hashlib
import io
import json
import os
import re
import tempfile
import zipfile
from pathlib import Path

MAX_ENTRY = 600 * 1024 * 1024
MAX_FILES = 80000
NESTED_ZIP = re.compile(r"^assets/runtime/[^/]+\.zip$")
WINE_SUFFIX = ("libarm64ecfex.dll", "libwow64fex.dll")
DXVK_REQUIRED = ("dxgi.dll", "d3d11.dll")


def _inventory(apk):
    """Collect names from top-level APK and bounded nested Wine ZIPs.

    Unlike checking the source tree, this sees only shipped bytes.
    Archive entries and nested archives are read-only; no extraction to device.
    """
    names = []
    unreadable = []
    for info in apk.infolist():
        if len(names) >= MAX_FILES:
            unreadable.append("APK_FILE_COUNT_CAPPED")
            break
        names.append(info.filename.replace("\\", "/"))
        if not NESTED_ZIP.fullmatch(info.filename):
            continue
        if info.file_size > MAX_ENTRY:
            unreadable.append("NESTED_ARCHIVE_TOO_LARGE:" + os.path.basename(info.filename))
            continue
        try:
            with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as spool:
                with apk.open(info) as src:
                    for block in iter(lambda: src.read(1024 * 1024), b""):
                        spool.write(block)
                        if spool.tell() > MAX_ENTRY:
                            raise ValueError("NESTED_UNCOMPRESSED_BYTES_EXCEEDED")
                spool.seek(0)
                with zipfile.ZipFile(spool) as nested:
                    for child in nested.namelist()[:MAX_FILES - len(names)]:
                        names.append("@" + os.path.basename(info.filename) + "/" +
                                     child.replace("\\", "/"))
        except (OSError, ValueError, zipfile.BadZipFile,
                RuntimeError) as exc:
            unreadable.append("NESTED_UNREADABLE:" +
                              os.path.basename(info.filename) + ":" +
                              type(exc).__name__)
    return names, unreadable


def _find_suffix(entries, suffix):
    # Normalized names only. Never take a Wine builtin DLL as proof it is DXVK.
    lower_suffix = suffix.lower()
    return [name for name in entries
            if name.replace("\\", "/").lower().endswith("/" + lower_suffix)]


def _status(check):
    if check is None:
        return "UNVERIFIED"
    return "PRESENT" if check else "MISSING"


def audit(apk_path):
    apk_path = Path(apk_path)
    if not apk_path.is_file():
        raise FileNotFoundError(apk_path)
    apk_digest = hashlib.file_digest(apk_path.open("rb"), "sha256").hexdigest()
    with zipfile.ZipFile(apk_path, "r") as z:
        names, unreadable = _inventory(z)
        app_native = {p for p in names if p.startswith("lib/arm64-v8a/")}
        wine_launcher = "lib/arm64-v8a/libwineprobe.so" in app_native
        wine_server = "lib/arm64-v8a/libwineserverrm11.so" in app_native
        x11_server = any(p.endswith("/libXlorie.so") for p in app_native)
        x11_client = any("libwine_winex11.so" in p for p in app_native)
        arm64ec = bool(_find_suffix(names, "libarm64ecfex.dll"))
        wow64 = bool(_find_suffix(names, "libwow64fex.dll"))
        # Wine-provided builtin d3d11.dll and dxgi.dll are NOT DXVK.
        # Require signed, content-addressed DXVK provider manifest.
        manifest_path = "assets/engine/engine-bundle-manifest.json"
        has_manifest = manifest_path in names
        provenance = False
        dxvk_verified = False
        native_icd_verified = False
        if has_manifest:
            try:
                manifest = json.loads(z.read(manifest_path).decode("utf-8"))
                provenance = manifest.get("schema") == "rm11.engine.bundle.v1"
                dxvk = manifest.get("dxvk", {})
                files = dxvk.get("pe_files", {})
                dxvk_verified = (
                    provenance and dxvk.get("provider") == "dxvk" and
                    len(dxvk.get("source_commit", "")) == 40 and
                    all(isinstance(files.get(k), dict) and
                        re.fullmatch(r"[a-f0-9]{64}", files[k].get("sha256", ""))
                        for k in DXVK_REQUIRED)
                )
                if dxvk_verified:
                    for dll in DXVK_REQUIRED:
                        path = files[dll].get("apk_path", "")
                        if path not in z.namelist():
                            dxvk_verified = False
                            break
                        with z.open(path) as src:
                            hashvalue = hashlib.sha256()
                            for block in iter(lambda: src.read(1024 * 1024), b""):
                                hashvalue.update(block)
                            if hashvalue.hexdigest() != files[dll]["sha256"]:
                                dxvk_verified = False
                                break
                gpu = manifest.get("gpu", {})
                native_icd_verified = (
                    provenance and gpu.get("driver") == "turnip" and
                    gpu.get("wsi") == "hardware" and
                    len(gpu.get("source_commit", "")) == 40 and
                    isinstance(gpu.get("apk_library"), str) and
                    gpu.get("apk_library", "") in z.namelist() and
                    isinstance(gpu.get("sha256"), str) and
                    bool(re.fullmatch(r"[a-f0-9]{64}", gpu.get("sha256", "")))
                )
                if native_icd_verified:
                    with z.open(gpu["apk_library"]) as src:
                        digest = hashlib.sha256()
                        for block in iter(lambda: src.read(1024 * 1024), b""):
                            digest.update(block)
                        native_icd_verified = digest.hexdigest() == gpu["sha256"]
            except (ValueError, KeyError, TypeError, UnicodeError,
                    zipfile.BadZipFile):
                provenance = False
                dxvk_verified = False
                native_icd_verified = False
    checks = {
        "apk_native_wine_loader": _status(wine_launcher),
        "apk_native_wineserver": _status(wine_server),
        "native_xorg_server": _status(x11_server),
        "native_x11_wine_client": _status(x11_client),
        "arm64ec_fex_module": _status(arm64ec),
        "wow64_fex_module": _status(wow64),
        "coherent_engine_bundle_provenance": _status(provenance),
        "dxvk_d3d11_provider_hash_verified": _status(dxvk_verified),
        "hardware_turnip_icd_hash_verified": _status(native_icd_verified),
        "on_device_guest_frame_presented": "UNVERIFIED",
        "on_device_game_pe_progress": "UNVERIFIED",
    }
    structural_ready = all(v == "PRESENT" for k, v in checks.items()
                           if not k.startswith("on_device_")) and not unreadable
    # Physical game execution needs Android screen and process evidence;
    # never substitute static bundle inspection for device verification.
    return {
        "schema": "rm11.engine.closure.audit.v1",
        "apk_sha256": apk_digest,
        "release_gate": "WAIT_FOR_REAL_ENGINE_INTEGRATION",
        "structural_release_gate": "READY" if structural_ready else "BLOCKED",
        "checks": checks,
        "unreadable_archives": unreadable[:20],
        "archive_entries_inspected": len(names),
        "game_rendering_claim": "UNVERIFIED",
        "would_publish_apk": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("apk", help="existing shipped APK to audit read-only")
    parser.add_argument("--out", help="write machine-readable audit JSON")
    parser.add_argument("--require-structural-ready", action="store_true")
    args = parser.parse_args()
    result = audit(args.apk)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    print(text)
    if args.require_structural_ready and (
        result["structural_release_gate"] != "READY"
    ):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
