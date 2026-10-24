#!/usr/bin/env python3
"""v4.0.6: opt-in Winefile-only FreeType ELF load target.

Never patch the Wine stack archive or the stable signed win32u. A second
ARM64 Wine client ELF substitutes one length-bounded, NUL-terminated
FreeType lookup string. This changes the *client* request from
libfreetype.so to librm11_ft.so; no globally visible libfreetype.so is
introduced (v4.0.4 showed a wineserver regression after that).
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

ORIGINAL=b"libfreetype.so\0"
PRIVATE=b"librm11_ft.so\0\0"
assert len(ORIGINAL)==len(PRIVATE)==15

def sha(data):
    return hashlib.sha256(data).hexdigest()

def elf_arm64(data:bytes,label:str):
    if len(data)<4096 or data[:4]!=b"\x7fELF" or data[4]!=2 or data[5]!=1:
        raise RuntimeError(f"{label} is not 64-bit little-endian ELF")
    if int.from_bytes(data[18:20],"little")!=183:
        raise RuntimeError(f"{label} is not AArch64")

def verify_offset_readonly(data:bytes,index:int):
    # No mutation of executable instructions, dynamic symbol tables or program
    # headers. Require the exact string in a non-executable PT_LOAD segment.
    hdr=struct.unpack_from("<Q",data,32)[0] # e_phoff
    entsize=struct.unpack_from("<H",data,54)[0]
    count=struct.unpack_from("<H",data,56)[0]
    if not(64<=entsize<=128 and 1<=count<=256 and hdr+entsize*count<=len(data)):
        raise RuntimeError("invalid ELF program-header table")
    safe=False
    for i in range(count):
        off=hdr+i*entsize
        typ,flags=struct.unpack_from("<II",data,off)
        poff=struct.unpack_from("<Q",data,off+8)[0]
        psize=struct.unpack_from("<Q",data,off+32)[0]
        if typ==1 and not(flags & 1) and poff<=index and index+len(ORIGINAL)<=poff+psize:
            safe=True
    if not safe:
        raise RuntimeError("FreeType SONAME is not in a non-executable load segment")

def build(args):
    original=args.wine.read_bytes()
    core=args.freetype.read_bytes()
    elf_arm64(original,"Wine native win32u")
    elf_arm64(core,"NDK FreeType")
    if original.count(ORIGINAL)!=1:
        raise RuntimeError(f"expected precisely one win32u FreeType SONAME reference, found {original.count(ORIGINAL)}")
    if original.count(PRIVATE)>0 or original.count(b"libfreetype.so.6\0")>0:
        raise RuntimeError("ambiguous original FreeType loader name")
    offset=original.index(ORIGINAL)
    verify_offset_readonly(original,offset)
    patched=bytearray(original)
    patched[offset:offset+len(ORIGINAL)]=PRIVATE
    patched=bytes(patched)
    assert len(patched)==len(original)
    assert patched[:offset]==original[:offset]
    assert patched[offset+len(PRIVATE):]==original[offset+len(ORIGINAL):]
    assert patched.count(PRIVATE)==1 and patched.count(ORIGINAL)==0
    assert not args.out.is_symlink() and not args.alias.is_symlink()
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_bytes(patched)
    args.alias.write_bytes(core)
    metadata={
        "schema":"rm11.v406.isolated-wine-fontclient-elf.v1",
        "arch":"ELF64 AArch64",
        "original_wine_sha256":sha(original),
        "isolated_client_sha256":sha(patched),
        "isolated_native_ft_sha256":sha(core),
        "patched_offset":offset,
        "changed_byte_count":sum(a!=b for a,b in zip(original,patched)),
        "requested_original_soname":"libfreetype.so",
        "requested_isolated_soname":"librm11_ft.so",
        "isolated_wine_client":"librm11_win32u_fontclient.so",
        "native_font_alias":"librm11_ft.so",
        "original_wine_unchanged":True,
        "global_libfreetype_so_alias_absent":True,
        "wine_server_unchanged":True,
        "enabled_for_winefile_diagnostic_first_attempt_only":True,
        "device_text_visibility_proven":False,
    }
    args.manifest.parent.mkdir(parents=True,exist_ok=True)
    args.manifest.write_text(json.dumps(metadata,indent=2)+"\n")
    print("RM11_V406_ISOLATED_FONTCLIENT_ELF_PATCH_VERIFIED",json.dumps(metadata))

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--wine",type=Path,required=True)
    p.add_argument("--freetype",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--alias",type=Path,required=True)
    p.add_argument("--manifest",type=Path,required=True)
    build(p.parse_args())
