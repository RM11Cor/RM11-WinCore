#!/usr/bin/env python3
"""Build and test a genuine x86-64 Linux ELF with PT_INTERP & DT_NEEDED libc.so.6.

Host glibc is a CI build-time dependency only. No Linux rootfs, loader, or glibc
is copied into the APK. This guest is APK DATA and cannot execute natively on
Android ARM64. An on-device attempt through Box64 is an experiment, not a promise.
"""
from pathlib import Path
import platform
import re
import struct
import subprocess

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'app/src/main/assets/box64_test/hello_glibc_x86_64.c'
TARGET = ROOT / 'app/src/main/assets/box64_test/hello_glibc_x86_64.elf'
MARKER = b'RM11_X86_64_GLIBC_DYNAMIC_OK'


def verify(path: Path):
    data = path.read_bytes()
    if not 64 <= len(data) <= 256 * 1024 or data[:6] != b'\x7fELF\x02\x01':
        raise RuntimeError('Missing/invalid bounded x86-64 ELF64')
    typ, arch = struct.unpack_from('<HH', data, 16)
    if typ not in (2, 3) or arch != 62 or MARKER not in data:
        raise RuntimeError('Expected x86-64 ELF and dynamic guest marker')
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phsize, phcount = struct.unpack_from('<HH', data, 54)
    if phsize < 56 or not 1 <= phcount <= 64 or phoff + phsize * phcount > len(data):
        raise RuntimeError('Invalid ELF program headers')
    if not any(struct.unpack_from('<I', data, phoff + phsize*i)[0] == 3 for i in range(phcount)):
        raise RuntimeError('PT_INTERP (dynamic loader) missing')
    # readelf is expected on ubuntu-latest x86_64 CI, provides independent audit
    out = subprocess.check_output(['readelf', '-l', '-d', str(path)], text=True, timeout=10)
    if '/lib64/ld-linux-x86-64.so.2' not in out or not re.search(r'NEEDED.*libc\.so\.6', out):
        raise RuntimeError('Expected Linux glibc loader and libc.so.6 dependency not found')
    return len(data)


def build():
    if platform.machine().lower() not in ('x86_64', 'amd64'):
        raise RuntimeError('Only x86-64 Linux CI hosts can build this test guest')
    TARGET.unlink(missing_ok=True)
    try:
        subprocess.run(['gcc', '-O2', '-fPIE', '-pie', '-Wl,--build-id=none',
                        '-o', str(TARGET), str(SOURCE)], check=True, timeout=60)
        size = verify(TARGET)
        result = subprocess.run([str(TARGET)], capture_output=True, timeout=5)
        if result.returncode != 0 or not result.stdout.startswith(MARKER):
            raise RuntimeError('Host-side dynamic guest run failed: ' + repr(result))
    except Exception:
        TARGET.unlink(missing_ok=True)
        raise
    print(f'PASS: x86-64 dynamic Linux guest ({size} bytes), PT_INTERP + DT_NEEDED libc.so.6, native CI smoke test')
    print('LIMIT: Android Box64 execution, glibc, Wine and EXE support NOT established')


if __name__ == '__main__':
    build()
