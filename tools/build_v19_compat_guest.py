#!/usr/bin/env python3
"""Compile audited first-party Linux x86-64 glibc probes; NOT Android runtime proof."""
from pathlib import Path
import platform
import subprocess
import struct
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT/'app/src/main/assets/box64_test/v19_glibc_compat_x86_64.c'
DST = ROOT/'app/src/main/assets/box64_test/v19_glibc_compat_x86_64.elf'
MODES = {'memory':'MEMORY', 'file':'FILE', 'thread':'THREAD', 'dlopen':'DLOPEN'}

def verify_elf(path):
    data = path.read_bytes()
    if not (1024 <= len(data) <= 256*1024 and data[:6] == b'\x7fELF\x02\x01'):
        raise RuntimeError('Invalid ELF64 guest')
    kind, machine = struct.unpack_from('<HH', data, 16)
    if (kind, machine) != (3, 62):
        raise RuntimeError('Expected Linux x86-64 PIE (ET_DYN)')
    out = subprocess.check_output(['readelf','-l','-d','-Ws',str(path)], text=True, timeout=10)
    if '/lib64/ld-linux-x86-64.so.2' not in out or 'libc.so.6' not in out or 'NEEDED' not in out:
        raise RuntimeError('glibc ELF dependency or interpreter missing')
    for marker in MODES.values():
        if f'RM11_V19_{marker}_OK'.encode() not in data:
            raise RuntimeError('Missing mode marker: '+marker)
    for symbol in ('pthread_create', 'pthread_join', 'malloc', 'free', 'dlopen', 'dlsym', 'open', 'read', 'write'):
        if symbol not in out:
            raise RuntimeError('Missing expected dynamic ABI symbol: '+symbol)
    return len(data)

def build():
    if platform.system() != 'Linux' or platform.machine().lower() not in ('x86_64','amd64'):
        raise RuntimeError('Require Linux x86-64 host for first-party guest')
    DST.unlink(missing_ok=True)
    try:
        subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror',
                        '-fPIE','-pie','-pthread','-Wl,--build-id=none',
                        str(SRC),'-o',str(DST),'-ldl'],check=True,timeout=45)
        size=verify_elf(DST)
        with tempfile.TemporaryDirectory(prefix='rm11-v19-test-') as temp:
            for mode, marker in MODES.items():
                args=[str(DST),mode]
                if mode=='file': args.append(str(Path(temp)/'test-file.tmp'))
                result=subprocess.run(args,capture_output=True,text=True,timeout=5)
                if result.returncode != 0 or f'RM11_V19_{marker}_OK' not in result.stdout.splitlines():
                    raise RuntimeError(f'Host {mode} check failed: {result.returncode} {result.stdout} {result.stderr}')
                if mode=='file' and Path(args[-1]).exists():
                    raise RuntimeError('Guest left file behind')
        print(f'PASS: V1.9 x86-64 dynamic ABI probes ({size} bytes), four separate host modes')
        print('LIMIT: Native Linux x86-64 success does NOT prove Android Box64 compatibility')
    except Exception:
        DST.unlink(missing_ok=True)
        raise

if __name__=='__main__':build()
