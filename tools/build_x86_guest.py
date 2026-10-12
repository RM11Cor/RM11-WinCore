#!/usr/bin/env python3
"""Build/check a tiny freestanding x86-64 Linux ELF guest for Box64.

This file is *not* ARM64/Android executable. It is packaged as an APK asset and
read as data by Box64. No glibc, network or external game files are needed.
"""
import argparse
import os
from pathlib import Path
import platform
import struct
import subprocess

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / 'app/src/main/assets/box64_test/hello_x86_64.S'
TARGET = ROOT / 'app/src/main/assets/box64_test/hello_x86_64.elf'
MARKER = b'RM11_X86_64_GUEST_EXEC_OK\n'


def verify_guest(path):
    data = Path(path).read_bytes()
    if len(data) < 64 or len(data) > 256 * 1024 or data[:6] != b'\x7fELF\x02\x01':
        raise RuntimeError('Guest must be bounded ELF64 little endian')
    typ, machine = struct.unpack_from('<HH', data, 16)
    if typ != 2 or machine != 62:  # x86-64 ET_EXEC (no PIE, no dynamic loader)
        raise RuntimeError('Guest must be x86-64 ET_EXEC, not ARM64 / shared library')
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phsize, phnum = struct.unpack_from('<HH', data, 54)
    if phsize < 56 or not 1 <= phnum <= 64 or phoff + phsize * phnum > len(data):
        raise RuntimeError('Malformed guest program headers')
    if any(struct.unpack_from('<I', data, phoff + phsize * i)[0] == 3 for i in range(phnum)):
        raise RuntimeError('A dynamic loader/glibc guest is not suitable for this test')
    if MARKER not in data:
        raise RuntimeError('Missing expected successful guest execution marker')
    return len(data)


def build(cc='gcc', run_host_test=True):
    if platform.machine().lower() not in ('x86_64', 'amd64'):
        raise RuntimeError('Compile on x86-64 runner, or use explicit x86-64 cross-toolchain')
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.unlink(missing_ok=True)
    try:
        subprocess.run([cc, '-nostdlib', '-static', '-no-pie', '-Wl,--build-id=none',
                        '-o', str(TARGET), str(SRC)], check=True, timeout=60)
        size = verify_guest(TARGET)
        if run_host_test:
            p = subprocess.run([str(TARGET)], capture_output=True, timeout=5, check=False)
            if p.returncode != 0 or p.stdout != MARKER:
                raise RuntimeError(f'x86_64 native host smoke test failed: exit={p.returncode}, stdout={p.stdout!r}, stderr={p.stderr!r}')
    except Exception:
        TARGET.unlink(missing_ok=True)
        raise
    print(f'PASS: x86-64 ELF {size} bytes, no glibc/dynamic loader; host guest smoke test passed')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    if args.verify_only:
        print('PASS: packaged x86-64 guest ELF metadata checked, bytes:', verify_guest(TARGET))
    else:
        build()

if __name__ == '__main__':
    main()
