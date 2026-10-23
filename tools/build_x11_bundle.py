#!/usr/bin/env python3
"""Resolve a minimal ARM64 Termux/Bionic X11 ELF dependency closure for Wine.

Only independent X11 CLIENT shared libraries are copied into Android's signed
APK jniLibs directory. Wine/FEX and game files are never touched. All downloaded
.deb packages are authenticated by the SHA-256 from the official Termux APT
index and every resulting ELF is checked for AArch64/DT_NEEDED completeness.

This is a diagnostic integration, not an assertion that Wine X11 works on a
particular phone. Libraries retain upstream licenses, see provenance JSON.
"""
import gzip
import hashlib
import json
import lzma
import re
import shutil
import subprocess
import tempfile
import urllib.request
from collections import deque
from pathlib import Path

BASE = "https://packages.termux.dev/apt"
REPOS = [
    (f"{BASE}/termux-main", "stable"),
    (f"{BASE}/termux-x11", "x11"),
]
START_PACKAGES = (
    "libx11", "libxext", "libandroid-sysvshm",
    "libxcb", "libxau", "libxdmcp",
)
INITIAL_ELFS = ("libX11.so", "libXext.so", "libandroid-sysvshm.so")
ANDROID_SYSTEM = {
    "libc.so", "libm.so", "libdl.so", "liblog.so",
    "libandroid.so", "libz.so", "libstdc++.so",
    "libEGL.so", "libGLESv2.so", "libGLESv3.so",
    "libvulkan.so", "libjnigraphics.so",
}
MAX_PACKAGES = 60
MAX_TOTAL_DOWNLOAD = 120 * 1024 * 1024
MAX_LIBS = 50


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fetch(url, max_bytes):
    req = urllib.request.Request(url, headers={"User-Agent": "RM11-WinCore-native-X11-audit/1.0"})
    with urllib.request.urlopen(req, timeout=50) as r:
        data = r.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("Bounded download limit exceeded for " + url)
    return data


def parse_index(data):
    """Parse RFC822-ish APT package stanzas, including wrapped fields."""
    rows = []
    for stanza in data.decode("utf-8").strip().split("\n\n"):
        d = {}
        key = None
        for line in stanza.splitlines():
            if line.startswith(" ") and key:
                d[key] += " " + line.strip()
            elif ": " in line:
                key, value = line.split(": ", 1)
                d[key] = value
        if all(key in d for key in ("Package", "Version", "Filename", "SHA256")):
            rows.append(d)
    return rows


def index_repositories():
    packages = {}
    repo_versions = []
    for base, suite in REPOS:
        uri = f"{base}/dists/{suite}/main/binary-aarch64/Packages.xz"
        raw = fetch(uri, 30 * 1024 * 1024)
        rows = parse_index(lzma.decompress(raw))
        if len(rows) < 100:
            raise RuntimeError("Invalid or unexpectedly small Termux index: " + uri)
        repo_versions.append({"repository": uri, "index_sha256": sha(raw)})
        for p in rows:
            # X11 channel takes priority for same package (the main repo is first).
            p = dict(p)
            p["_base"] = base
            packages[p["Package"]] = p
    return packages, repo_versions


def dep_choices(field):
    for group in field.split(","):
        choices = []
        for alternative in group.split("|"):
            a = re.match(r"\s*([a-zA-Z0-9+._-]+)", alternative)
            if a:
                choices.append(a.group(1))
        if choices:
            yield choices


def run(*args):
    proc = subprocess.run(args, check=True, text=True, capture_output=True)
    return proc.stdout


def elf_needed(path):
    output = run("readelf", "-dW", str(path))
    needed = re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", output)
    return sorted(set(needed))


def is_arm64_elf(path):
    try:
        with open(path, "rb") as f:
            hdr = f.read(20)
        return len(hdr) == 20 and hdr[:4] == b"\x7fELF" and hdr[4] == 2 and hdr[5] == 1 and hdr[18:20] == b"\xb7\x00"
    except (OSError, ValueError):
        return False


def main():
    packages, repositories = index_repositories()
    missing_roots = sorted(set(START_PACKAGES) - packages.keys())
    if missing_roots:
        raise RuntimeError("Missing official Termux packages: " + ", ".join(missing_roots))

    # Resolve official Termux APT dependencies. We do NOT install packages,
    # run maintainer scripts, download games, or modify the runtime imagefs.
    queue = deque(START_PACKAGES)
    chosen = {}
    while queue:
        name = queue.popleft()
        if name in chosen:
            continue
        pkg = packages.get(name)
        if not pkg:
            raise RuntimeError("Missing required Termux dependency: " + name)
        chosen[name] = pkg
        if len(chosen) > MAX_PACKAGES:
            raise RuntimeError("Exceeded bounded dependency package count")
        for alternatives in dep_choices(pkg.get("Depends", "")):
            next_name = next((c for c in alternatives if c in packages), None)
            # Virtual/system dependencies not in official indexes must not be
            # assumed present silently if we actually need their ELF.
            if next_name:
                queue.append(next_name)

    output_root = Path("app/src/main/jniLibs/arm64-v8a")
    provenance = Path("app/src/main/assets/runtime/rm11-x11-provenance.json")
    output_root.mkdir(parents=True, exist_ok=True)
    provenance.parent.mkdir(parents=True, exist_ok=True)
    manifest = []
    catalog = {}
    total_download = 0

    with tempfile.TemporaryDirectory(prefix="rm11-x11-packages-") as directory:
        tmp = Path(directory)
        for name, p in sorted(chosen.items()):
            uri = p["_base"] + "/" + p["Filename"].lstrip("/")
            data = fetch(uri, 35 * 1024 * 1024)
            total_download += len(data)
            if total_download > MAX_TOTAL_DOWNLOAD:
                raise RuntimeError("Termux package download budget exceeded")
            if sha(data).lower() != p["SHA256"].lower():
                raise RuntimeError("APT metadata SHA256 mismatch: " + name)
            deb = tmp / (name + ".deb")
            deb.write_bytes(data)
            extracted = tmp / name
            extracted.mkdir()
            run("dpkg-deb", "-x", str(deb), str(extracted))
            entry = {
                "package": name,
                "version": p["Version"],
                "deb_sha256": sha(data),
                "deb_url": uri,
                "license": p.get("Homepage", "See Termux package upstream"),
            }
            manifest.append(entry)
            deb.unlink()
            for candidate in extracted.rglob("*"):
                if not (candidate.name.endswith(".so") or ".so." in candidate.name):
                    continue
                if not candidate.is_file() or not is_arm64_elf(candidate):
                    continue
                # A source package may include symlinks with matching names;
                # preserve their actual SONAME/content when repackaging.
                old = catalog.get(candidate.name)
                if old and old.read_bytes() != candidate.read_bytes():
                    raise RuntimeError("Conflicting SONAME: " + candidate.name)
                catalog[candidate.name] = candidate

        selected = {}
        need = deque(INITIAL_ELFS)
        while need:
            soname = need.popleft()
            if soname in selected or soname in ANDROID_SYSTEM:
                continue
            source = catalog.get(soname)
            if source is None:
                raise RuntimeError("Native X11 DT_NEEDED closure unsatisfied: " + soname +
                                   "; available: " + ", ".join(sorted(catalog)[:120]))
            selected[soname] = source
            if len(selected) > MAX_LIBS:
                raise RuntimeError("Native X11 library count budget exceeded")
            for dependency in elf_needed(source):
                if dependency not in selected and dependency not in ANDROID_SYSTEM:
                    need.append(dependency)

        selected_manifest = []
        for name, source in sorted(selected.items()):
            if not re.fullmatch(r"lib[A-Za-z0-9+_.-]+\.so", name):
                raise RuntimeError("Not a safely packagable JNI library name: " + name)
            dst = output_root / name
            if dst.exists():
                if sha(dst.read_bytes()) != sha(source.read_bytes()):
                    raise RuntimeError("Would overwrite previous Wine/FEX native library: " + name)
            else:
                shutil.copyfile(source, dst)
            if not is_arm64_elf(dst):
                raise RuntimeError("Generated APK native library is not ELF64 AArch64: " + name)
            selected_manifest.append({
                "library": name, "sha256": sha(dst.read_bytes()),
                "dt_needed": elf_needed(dst),
                "size_bytes": dst.stat().st_size,
            })

    out = {
        "label": "RM11 X11 Bionic client diagnostic bundle (not proof of rendering)",
        "source_repositories": repositories,
        "termux_packages": manifest,
        "native_arm64_libraries": selected_manifest,
        "existing_wine_fex_files_modified": False,
    }
    provenance.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    print("RM11_X11_NATIVE_CLIENT_CLOSURE_V281")
    print(json.dumps({"packages": len(manifest),
                      "copied_libraries": [x["library"] for x in selected_manifest],
                      "sources": repositories}, indent=2))
    print("No client runtime, server display or Vulkan behavior was asserted.")


if __name__ == "__main__":
    main()
