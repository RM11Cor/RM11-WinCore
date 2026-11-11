"""Strict original x86-64 ELF64 fixture audit before Android FEXCore packaging.

The source is assembled with GNU as and linked as a no-interpreter PIE.
Accepts the two observed GNU ld 16-KiB-aligned four-PT_LOAD layouts; rejects
relocations/dependencies and unexpected guest instruction/syscall bytes.
This is not general-purpose or unsafe user-supplied program execution.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import sys

MESSAGE = b"KERNIX_ELF64_GUEST_RUN_PASS\n"
GUEST_OPCODES = (
    b"\xb8\x01\x00\x00\x00"     # mov eax,1
    b"\xbf\x01\x00\x00\x00"     # mov edi,1
    b"\x48\x8d\x35\xef\x3f\x00\x00" # lea rsi,[rip + 0x3fef]
    b"\xba\x1c\x00\x00\x00"     # mov edx,28
    b"\x0f\x05"                     # syscall write
    b"\x89\xc3"                     # mov ebx,eax
    b"\xb8\x27\x00\x00\x00"     # mov eax,39
    b"\x0f\x05"                     # syscall getpid
    b"\x48\x01\xd8"                # add rax,rbx
    b"\xf4"                         # hlt
)
GUEST_CODE_SIZE = 37


def checked_slice(data: bytes, off: int, n: int) -> bytes:
    if off < 0 or n < 0 or off > len(data) or n > len(data)-off:
        raise ValueError("out-of-bounds ELF file reference")
    return data[off:off+n]


def check(data: bytes) -> dict[str, object]:
    if len(data) > 131072 or len(data) < 64:
        raise ValueError("invalid ELF size")
    if data[:16] != b"\x7fELF\x02\x01\x01" + b"\0"*9:
        raise ValueError("not ELF64 LE SystemV")
    hdr=struct.unpack_from("<16sHHIQQQIHHHHHH",data)
    _,typ,machine,version,entry,phoff,_,_,ehsize,phentsize,phnum,*_=hdr
    if (typ,machine,version,entry,ehsize,phentsize,phnum)!=(3,62,1,0x4000,64,56,7):
        raise ValueError("ELF x86 PIE header mismatch")
    table=checked_slice(data,phoff,phnum*phentsize)
    ph=[struct.unpack_from("<IIQQQQQQ",table,i*phentsize) for i in range(phnum)]
    loads=[p for p in ph if p[0]==1]
    if (len(loads)!=4 or [p[3] for p in loads[:3]]!=[0,0x4000,0x8000]
            or loads[3][3] not in (0xff20,0xff30)):
        raise ValueError("invalid fixed four-PT_LOAD layout")
    if [p[1] for p in loads] != [4,5,4,6]:
        raise ValueError("ELF R, RX, R, RW protections changed")
    for p in loads:
        kind,flags,off,vaddr,_,filesz,memsz,align=p
        if align!=16384 or off%16384!=vaddr%16384 or filesz>memsz or vaddr+memsz>65536:
            raise ValueError("unsafe ELF segment offsets")
        checked_slice(data,off,filesz)
    if any(p[0] in (3,7) for p in ph):
        raise ValueError("PT_INTERP or PT_TLS forbidden")
    dyn=[p for p in ph if p[0]==2]
    if len(dyn)!=1:
        raise ValueError("dynamic header missing")
    dynamic=checked_slice(data,dyn[0][2],dyn[0][5])
    if len(dynamic)%16:
        raise ValueError("misaligned dynamic table")
    tags=[struct.unpack_from("<qQ",dynamic,i)[0] for i in range(0,len(dynamic),16)]
    if not tags or tags[-1]!=0 or any(x in tags for x in (1,7,8,17,18,23,2,12,25,22)):
        raise ValueError("unresolved relocation/library or no DT_NULL")
    text=checked_slice(data,loads[1][2],loads[1][5])
    if text!=GUEST_OPCODES or len(text)!=GUEST_CODE_SIZE:
        raise ValueError("unexpected compiled x86 instructions")
    readonly=checked_slice(data,loads[2][2],loads[2][5])
    if readonly[:len(MESSAGE)]!=MESSAGE:
        raise ValueError("ELF .rodata guest message changed")
    if text.count(b"\x0f\x05")!=2:
        raise ValueError("ELF syscall sequence changed")
    return {
       "format":"ET_DYN ELF64 x86-64 SystemV",
       "entry":entry,"load_segments":len(loads),
       "relocation_free":True,"guest_message":MESSAGE.decode().strip(),
       "guest_syscalls":[1,39],"guest_jit_execution":False,
       "sha256":hashlib.sha256(data).hexdigest(),
       "size":len(data),
    }


def main() -> None:
    if len(sys.argv)!=2:
        raise SystemExit("usage: kernix_elf64_fixture_check.py fixture.elf")
    result=check(Path(sys.argv[1]).read_bytes())
    print("KERNIX_REAL_ASSEMBLED_ELF64_GUEST_OPCODE_LAYOUT_AND_NO_RELOCATION_PASS")
    print(result)


if __name__=="__main__":
    main()
