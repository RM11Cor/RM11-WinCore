#!/usr/bin/env python3
"""Deterministic minimal PE32+ (AMD64) smoke fixture; no imports, OS calls or DRM."""
from pathlib import Path
from struct import pack_into
import sys
buf = bytearray(1024)
buf[:2] = b'MZ'
pack_into('<I', buf, 0x3c, 0x80)
buf[0x80:0x84] = b'PE\0\0'
# IMAGE_FILE_HEADER
pack_into('<HHIIIHH', buf, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x0022)
o = 0x98  # PE32+ IMAGE_OPTIONAL_HEADER
pack_into('<H', buf, o, 0x20B)
pack_into('<III', buf, o+4, 0x200, 0, 0)
pack_into('<I', buf, o+16, 0x1000) # entry RVA
pack_into('<I', buf, o+20, 0x1000) # base of code
pack_into('<Q', buf, o+24, 0x140000000) # image base
pack_into('<II', buf, o+32, 0x1000, 0x200) # section and file alignment
pack_into('<HHHHHH', buf, o+40, 6, 0, 0, 0, 6, 0)
pack_into('<I', buf, o+56, 0x2000) # image size
pack_into('<I', buf, o+60, 0x200) # headers size
pack_into('<H', buf, o+68, 3) # console subsystem
pack_into('<Q', buf, o+72, 0x100000) # stack reserve
pack_into('<Q', buf, o+80, 0x1000) # stack commit
pack_into('<Q', buf, o+88, 0x100000) # heap reserve
pack_into('<Q', buf, o+96, 0x1000) # heap commit
pack_into('<I', buf, o+108, 16) # data directory count; import RVA 0
s = o + 0xF0
buf[s:s+8] = b'.text\0\0\0'
pack_into('<IIIIIIHHI', buf, s+8, 0x100, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
# 35 + 8 - 1 = 42 ; x86-64 register-only instructions, no OS imports
buf[0x200:0x210] = bytes.fromhex('B8 23 00 00 00 05 08 00 00 00 2D 01 00 00 00 C3')
path = Path(sys.argv[1]) if len(sys.argv)>1 else Path('rm11-smoke-pe64.exe')
path.parent.mkdir(parents=True, exist_ok=True)
path.write_bytes(buf)
print(path, len(buf))
