#!/usr/bin/env python3
"""Offline regression checks for native APK Box64 ELF admission guard."""
import importlib.util
from pathlib import Path
import struct
import tempfile

SCRIPT=Path(__file__).resolve().parent / 'build_official_box64.py'
spec=importlib.util.spec_from_file_location('build_official_box64', SCRIPT)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def valid_elf(machine=183, etype=3, interpreter=b'/system/bin/linker64\0'):
    data=bytearray(256)
    data[:6]=b'\x7fELF\x02\x01'
    struct.pack_into('<HH',data,16,etype,machine)
    struct.pack_into('<Q',data,32,64)
    struct.pack_into('<HH',data,54,56,1)
    struct.pack_into('<I',data,64,3)
    struct.pack_into('<QQ',data,64+8,176,0)
    struct.pack_into('<Q',data,64+32,len(interpreter))
    data[176:176+len(interpreter)]=interpreter
    return bytes(data)

with tempfile.TemporaryDirectory() as folder:
    path=Path(folder)/'sample'
    path.write_bytes(valid_elf())
    module.verify_android_pie(path)
    for blob in (valid_elf(machine=62), valid_elf(etype=2), valid_elf(interpreter=b'/lib/ld-linux-aarch64.so.1\0'),b'text',valid_elf()[:70]):
        path.write_bytes(blob)
        try: module.verify_android_pie(path)
        except RuntimeError: pass
        else: raise AssertionError('Invalid Box64 ELF incorrectly accepted')
print('PASS: Box64 Android PIE architecture, dynamic linker and corruption guards')
