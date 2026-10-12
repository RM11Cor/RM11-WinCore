#!/usr/bin/env python3
"""Generate deterministic first-party x86-64 ELF dynamically linked to libc,
without the __libc_start_main dependency that V1.5/V1.6 couldn't resolve.

No glibc binaries copied to the APK. This narrows the startup ABI problem,
not a general fix for running arbitrary x86-64 binaries on Android.
"""
from pathlib import Path
import platform
import subprocess

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'app/src/main/assets/box64_test/no_crt_libc_x86_64.S'
TARGET = ROOT / 'app/src/main/assets/box64_test/no_crt_libc_x86_64.elf'
MARKER = b'RM11_X86_64_LIBC_WRITE_OK'


def verify(path):
    data = path.read_bytes()
    if not (64 <= len(data) <= 256 * 1024) or data[:6] != b'\x7fELF\x02\x01' or MARKER not in data:
        raise RuntimeError('Invalid x86-64 ELF or missing output marker')
    info = subprocess.check_output(['readelf', '-h', '-l', '-d', '-Ws', '-r', str(path)], text=True, timeout=10)
    for item in ('Machine:                           Advanced Micro Devices X86-64',
                 '/lib64/ld-linux-x86-64.so.2', 'Shared library: [libc.so.6]', 'write@GLIBC_'):
        if item not in info:
            raise RuntimeError('Expected ELF dependency missing: ' + item)
    if '__libc_start_main' in info:
        raise RuntimeError('CRT dependency was reintroduced')
    if 'JUMP_SLOT' not in info:
        raise RuntimeError('Expected actual dynamic symbol relocation')
    return len(data)


def build():
    if platform.machine().lower() not in ('x86_64', 'amd64'):
        raise RuntimeError('First-party guest must be built on Linux x86-64 CI')
    TARGET.unlink(missing_ok=True)
    try:
        subprocess.run(['gcc', '-nostartfiles', '-fPIC', '-pie', '-Wl,--build-id=none',
                        '-Wl,--dynamic-linker=/lib64/ld-linux-x86-64.so.2',
                        '-o', str(TARGET), str(SOURCE), '-Wl,--no-as-needed', '-lc'],
                       check=True, timeout=60)
        nbytes = verify(TARGET)
        result = subprocess.run([str(TARGET)], capture_output=True, timeout=5)
        if result.returncode != 0 or result.stdout.strip() != MARKER:
            raise RuntimeError(f'Native x86-64 host execution failed: {result!r}')
    except Exception:
        TARGET.unlink(missing_ok=True)
        raise
    print(f'PASS: no-CRT x86-64 ELF {nbytes} bytes; dynamic libc write via PLT, host execution OK')
    print('LIMIT: host is x86-64; Android Box64 + wrapped libc resolution not tested here')


if __name__ == '__main__':
    build()
