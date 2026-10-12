#!/usr/bin/env python3
"""Rebuild/audit first-party Windows x86-64 PE console executable.

No Windows SDK needed. clang/lld-link are used on Linux and are not used at runtime.
The Win32 API calls are deliberately limited to private marker creation.
"""
from pathlib import Path
import hashlib
import os
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT/'app/src/main/assets/wine_exe_v22'
PE = DEST/'rm11_probe.exe'
MARKER = b'RM11_V22_WINDOWS_PE_EXEC_OK\n'

def audit(data):
    if len(data) < 1024 or len(data) > 100_000 or data[:2] != b'MZ':
        raise ValueError('Windows PE missing/invalid')
    off = struct.unpack_from('<I', data, 0x3c)[0]
    if off > len(data) - 256 or data[off:off+4] != b'PE\0\0':
        raise ValueError('PE header absent')
    if struct.unpack_from('<H', data, off+4)[0] != 0x8664:
        raise ValueError('Not x86-64 machine')
    if struct.unpack_from('<H', data, off+24)[0] != 0x20b:
        raise ValueError('Not PE32+ format')
    if struct.unpack_from('<H',data,off+24+68)[0] != 3:
        raise ValueError('Not Windows console subsystem')
    if b'KERNEL32.dll' not in data or not all(x in data for x in [b'CreateFileA',b'WriteFile',b'ExitProcess',b'CloseHandle',b'RM11-V22-WIN32-OK.txt',MARKER]):
        raise ValueError('Missing Win32 imports and exact test marker')
    return hashlib.sha256(data).hexdigest()

def main():
    if shutil.which('clang') and shutil.which('lld-link'):
        with tempfile.TemporaryDirectory(prefix='rm11-winpe-') as td:
            temp=Path(td)
            subprocess.run(['clang','-target','x86_64-pc-windows-msvc','-c','-O2','-fno-stack-protector',
                            str(DEST/'rm11_probe_win64.c'),'-o',str(temp/'test.obj')],check=True)
            subprocess.run(['lld-link','/dll','/noentry','/def:'+str(DEST/'kernel32_imports.def'),
                            '/machine:x64','/out:'+str(temp/'import-only.dll'),'/implib:'+str(temp/'kernel32.lib')], check=True)
            subprocess.run(['lld-link','/entry:mainCRTStartup','/subsystem:console','/machine:x64',
                            '/nodefaultlib','/dynamicbase','/nxcompat','/out:'+str(temp/'rm11_probe.exe'),
                            str(temp/'test.obj'),str(temp/'kernel32.lib')],check=True)
            raw=(temp/'rm11_probe.exe').read_bytes()
            audit(raw)
            PE.write_bytes(raw)
    else:
        if not PE.is_file():
            raise SystemExit('FAIL: clang/lld-link unavailable and trusted bundled Win64 test EXE missing')
        print('NOTE: clang/lld-link unavailable; verifying pre-built Win64 PE only')
    digest=audit(PE.read_bytes())
    (DEST/'PE-SHA256.txt').write_text(digest+'\n',encoding='utf-8')
    print('PASS: real Win64 PE with kernel32 imports, sha256='+digest)

if __name__=='__main__':main()
