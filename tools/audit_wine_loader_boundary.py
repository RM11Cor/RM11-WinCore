#!/usr/bin/env python3
"""Read-only Android ELF loader audit for the existing, signed RM11 APK.

Never executes a Wine or Android ELF. Examines DT_NEEDED and DT_SONAME,
symbol imports/exports, package filenames and original source environment
policy. Unlike a static FT_* export audit, this identifies possible linker
namespace/dependency gaps and differences between Wine's dlopen SONAME and
the signed JNI library basename. Any 'candidate' needs device proof.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from zipfile import ZipFile


BUNDLE = (
    "lib/arm64-v8a/libwine_win32u.so",
    "lib/arm64-v8a/librm11_freetype_core.so",
    "lib/arm64-v8a/librm11_wine_data_redirect.so",
    "lib/arm64-v8a/librm11_ft.so",
    "lib/arm64-v8a/libwineprobe.so",
)
SYSTEM_NAMES = {
    "libc.so", "libm.so", "libdl.so", "liblog.so",
    "libandroid.so", "libz.so", "libEGL.so", "libGLESv2.so",
    "libvulkan.so", "libOpenSLES.so", "libjnigraphics.so",
}
# A Wine runtime module in private ImageFs, not an Android NDK JNI library.
# This is a classifier only: existence and runtime linker visibility are NOT
# proven by the presence of this name in a DT_NEEDED entry.
WINE_PRIVATE_RUNTIME_NAMES = {"ntdll.so"}

def classify_dependencies(needed: list[str], packaged: set[str]) -> dict:
    return {
        "android_platform_names": sorted(n for n in needed if n in SYSTEM_NAMES),
        "apk_signed_jni_names": sorted(n for n in needed if n in packaged),
        "wine_private_imagefs_names_not_verified": sorted(
            n for n in needed if n in WINE_PRIVATE_RUNTIME_NAMES
        ),
        "unclassified_external_names": sorted(
            n for n in needed
            if n not in SYSTEM_NAMES and n not in packaged
            and n not in WINE_PRIVATE_RUNTIME_NAMES
        ),
    }


def hash_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def arm64_elf(blob: bytes, name: str):
    if len(blob) < 1024 or blob[:4] != b"\x7fELF" or blob[4] != 2 or blob[5] != 1:
        raise ValueError("Not ELF64 little endian: " + name)
    if int.from_bytes(blob[18:20], "little") != 183:
        raise ValueError("Not AArch64 ELF: " + name)


def needed_from_readelf(text: str) -> list[str]:
    return sorted(set(re.findall(r"\(NEEDED\).*?Shared library: \[([^\]]+)\]", text)))


def soname_from_readelf(text: str) -> str | None:
    names = re.findall(r"\(SONAME\).*?Library soname: \[([^\]]+)\]", text)
    return names[0] if names else None


def symbols_from_readelf(text: str) -> tuple[set[str], set[str]]:
    imports, exports = set(), set()
    for line in text.splitlines():
        if not re.match(r"^\s*\d+:", line):
            continue
        fields = line.split()
        if len(fields) < 8:
            continue
        name = fields[7].split("@", 1)[0]
        if not name or name.startswith("("):
            continue
        if fields[6] == "UND":
            imports.add(name)
        else:
            exports.add(name)
    return imports, exports


def loader_environment(source: str) -> dict:
    # Reflect source defaults only, not actual environment at runtime.
    enabled_off = bool(re.search(
        r'env\.put\("RM11_NATIVE_FREETYPE_DLOPEN_REDIRECT",\s*"0"\)', source
    ))
    loaded_preload = "librm11_wine_data_redirect.so" in source and "LD_PRELOAD" in source
    return {
        "source_freetype_redirect_defaults_off": enabled_off,
        "source_preloads_native_redirect_shim": loaded_preload,
    }


def readelf_file(readelf: str, path: Path, option: str) -> str:
    return subprocess.check_output(
        [readelf, "--wide", option, str(path)], text=True
    )


def audit(apk: Path, readelf: str, src_environment: str) -> dict:
    filenames = set()
    with ZipFile(apk, "r") as archive:
        filenames = {item.filename for item in archive.infolist()}
        missing_files = sorted(set(BUNDLE) - filenames)
        if missing_files:
            raise ValueError("Pinned APK missing selected signed native ELF: " + str(missing_files))
        native_names = {
            Path(name).name
            for name in filenames
            if name.startswith("lib/arm64-v8a/") and name.endswith(".so")
        }
        blobs = {name: archive.read(name) for name in BUNDLE}
    for name, blob in blobs.items():
        if len(blob) > 10_000_000:
            raise ValueError("Unexpectedly large native library " + name)
        arm64_elf(blob, name)

    # Temporary extraction happens only on the isolated Ubuntu CI runner.
    from tempfile import TemporaryDirectory
    with TemporaryDirectory(prefix="rm11-abi-v443-") as folder:
        root = Path(folder)
        dynamic, imports, exports = {}, {}, {}
        for index, (filename, blob) in enumerate(blobs.items()):
            path = root / ("signed_" + str(index) + ".so")
            path.write_bytes(blob)
            dynamic[filename] = readelf_file(readelf, path, "-d")
            imports[filename], exports[filename] = symbols_from_readelf(
                readelf_file(readelf, path, "--dyn-syms")
            )

    details = {}
    for path in BUNDLE:
        dependencies = needed_from_readelf(dynamic[path])
        details[Path(path).name] = {
            "signed_sha256": hash_bytes(blobs[path]),
            "file_size": len(blobs[path]),
            "elf_soname": soname_from_readelf(dynamic[path]),
            "needed": dependencies,
            "dependency_classification": classify_dependencies(dependencies, native_names),
        }

    original = "lib/arm64-v8a/libwine_win32u.so"
    core = "lib/arm64-v8a/librm11_freetype_core.so"
    alias = "lib/arm64-v8a/librm11_ft.so"
    shim = "lib/arm64-v8a/librm11_wine_data_redirect.so"
    probe = "lib/arm64-v8a/libwineprobe.so"

    requested_name = "libfreetype.so" if b"libfreetype.so\x00" in blobs[original] else (
        "libfreetype.so.6" if b"libfreetype.so.6\x00" in blobs[original] else None)
    mismatch = requested_name not in native_names if requested_name else None
    shim_exports = "dlopen" in exports[shim]
    wine_imports = "dlopen" in imports[original]
    core_symbols = {x for x in exports[core] if x.startswith("FT_")}
    font_export_ok = all(x in core_symbols for x in (
        "FT_Init_FreeType", "FT_New_Face", "FT_Load_Glyph", "FT_Render_Glyph"
    ))
    all_missing = sorted({
        v for entry in details.values()
        for v in entry["dependency_classification"]["unclassified_external_names"]
    })
    wine_private = sorted({
        v for entry in details.values()
        for v in entry["dependency_classification"]["wine_private_imagefs_names_not_verified"]
    })
    return {
        "schema": "rm11.v443.readonly-android-linker-audit.v1",
        "scope": "SIGNED_APK_STATIC_ANALYSIS_ONLY",
        "apk_sha256": hash_bytes(apk.read_bytes()),
        "wine_requested_font_soname": requested_name,
        "signed_apk_has_exact_wine_requested_font_basename": not mismatch,
        "signed_apk_uses_renamed_freetype_core_basename": "librm11_freetype_core.so" in native_names,
        "signed_fontclient_alias_matches_core": blobs[alias] == blobs[core],
        "original_wine_win32u_imports_dlopen": wine_imports,
        "native_redirect_shim_exports_dlopen": shim_exports,
        "native_wine_loader_imports_dlopen": "dlopen" in imports[probe],
        "bundled_font_has_required_basic_ft_exports": font_export_ok,
        "unclassified_external_native_dependencies": all_missing,
        "private_wine_runtime_names_not_verified": wine_private,
        "freetype_redirect_required_by_name_mismatch": bool(mismatch),
        "native_libraries": details,
        "default_launch_environment_source": loader_environment(src_environment),
        "source_code_note": "Default Wine FT redirect is OFF to protect wineserver; this is not proof that an enabled redirect loads successfully.",
        "interpretation": (
            "Unrenamed Wine requests a bare SONAME while the signed APK installs "
            "the library under a private JNI filename; bridge interposition is "
            "necessary. Imports/exports and DT_NEEDED alone cannot show whether "
            "Android's linker namespaces, symbol resolution or client/server "
            "Wine IPC succeed at runtime."
        ),
        "runtime_dlopen_performed": False,
        "wine_process_started": False,
        "on_device_fonts_fixed": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--readelf", default="readelf")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    value = audit(args.apk, args.readelf, args.source.read_text())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    print("RM11_V443_REQUESTED_FONT=", value["wine_requested_font_soname"])
    print("RM11_V443_EXACT_FONT_FILE_IN_APK=", value["signed_apk_has_exact_wine_requested_font_basename"])
    print("RM11_V443_SHIM_EXPORTS_DLOPEN=", value["native_redirect_shim_exports_dlopen"])
    print("RM11_V443_ORIGINAL_WIN32U_IMPORTS_DLOPEN=", value["original_wine_win32u_imports_dlopen"])
    print("RM11_V443_FONT_ALIAS_SHA_MATCH=", value["signed_fontclient_alias_matches_core"])
    print("RM11_V443_UNCLASSIFIED_NATIVE_DEPENDENCIES=", value["unclassified_external_native_dependencies"])
    print("RM11_V443_WINE_PRIVATE_RUNTIME_LINKS_UNVERIFIED=", value["private_wine_runtime_names_not_verified"])
    print("RM11_V443_WINE_FREETYPE_NAME_BRIDGE_REQUIRED=", value["freetype_redirect_required_by_name_mismatch"])
    print("RM11_V443_READ_ONLY_NO_APK_PATCH_AND_NO_WINESERVER_START")


if __name__ == "__main__":
    main()
