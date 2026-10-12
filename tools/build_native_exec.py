#!/usr/bin/env python3
"""Build first-party ARM64 Android PIE executable for packaging as lib*.so.

The source ZIP contains no pre-built third-party executable. In GitHub Actions,
`scripts-check.py` compiles this before Gradle packages the APK. The executable
is *not* a .so library: it merely uses the .so filename to be extracted to the
Android package's nativeLibraryDir (app-data files are not executable).
"""
from pathlib import Path
import os
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "app/src/main/cpp/PackagedExecProbe.c"
OUT = ROOT / "app/src/main/jniLibs/arm64-v8a/librm11execprobe.so"
NDK_VER = "27.2.12479018"


def find_compiler():
    roots = []
    if os.environ.get("RM11_NDK_HOME"):
        roots.append(Path(os.environ["RM11_NDK_HOME"]))
    for name in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        if os.environ.get(name):
            sdk = Path(os.environ[name])
            roots.extend((sdk / "ndk" / NDK_VER, sdk / "ndk-bundle"))
    roots.append(Path.home() / "Android/Sdk/ndk" / NDK_VER)
    for root in roots:
        compiler = root / "toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang"
        if compiler.is_file():
            return compiler
    return None


def verify_elf(path):
    data = path.read_bytes()
    if len(data) < 64 or data[:4] != b'\x7fELF' or data[4:6] != b'\x02\x01':
        raise RuntimeError("Output must be 64-bit little-endian ELF")
    if struct.unpack_from('<H', data, 18)[0] != 183:
        raise RuntimeError("Output must have AArch64 e_machine")
    if struct.unpack_from('<H', data, 16)[0] != 3:
        raise RuntimeError("Output must be ET_DYN PIE")
    # A runnable dynamic ELF needs PT_INTERP (type=3), unlike a JNI .so.
    phoff = struct.unpack_from('<Q', data, 32)[0]
    entsize = struct.unpack_from('<H', data, 54)[0]
    count = struct.unpack_from('<H', data, 56)[0]
    if not entsize or count > 256 or phoff + entsize * count > len(data):
        raise RuntimeError("Invalid ELF program headers")
    if not any(struct.unpack_from('<I', data, phoff + i * entsize)[0] == 3
               for i in range(count)):
        raise RuntimeError("Missing PT_INTERP: executable linked as library?")
    if b'/system/bin/linker64' not in data:
        raise RuntimeError("Android linker64 interpreter not present")


def main():
    required = '--required' in sys.argv
    cc = find_compiler()
    if not cc:
        if required:
            raise SystemExit('FAIL: Android NDK compiler unavailable; cannot package V1.1 executable')
        print('SKIP: Android NDK unavailable locally; GitHub CI will compile packaged native executable')
        return
    OUT.parent.mkdir(parents=True, exist_ok=True)
    cmd = [str(cc), '-O2', '-fPIE', '-pie', '-fstack-protector-strong',
           '-Wl,-z,relro,-z,now', '-Wl,--build-id=sha1',
           str(SOURCE), '-o', str(OUT)]
    subprocess.run(cmd, check=True)
    verify_elf(OUT)
    print(f'PASS: built Android ARM64 executable with PT_INTERP at {OUT} ({OUT.stat().st_size} bytes)')

if __name__ == '__main__':
    main()
