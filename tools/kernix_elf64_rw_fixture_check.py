"""KERNIX fixed ELF64 x86 guest RW memory fixture contract.

Validates genuine GNU as/ld ELF64 bytecode, six program headers, W^X,
rodata template and zero-initialized writable .data at ELF vaddr 0xc0f0.
The file is a signed-APK-embedded fixture, not arbitrary ELF execution.
"""
from __future__ import annotations
import hashlib
import struct
import sys
from pathlib import Path

MESSAGE = b"KERNIX_ELF_RW_MEMORY_PASS\n"
CODE = bytes.fromhex(
    "488d35f93f0000488d3de2800000b91a000000f3a4"
    "b801000000bf01000000488d35ca800000ba1a000000"
    "0f0589c3b8270000000f054801d8f4"
)
assert len(CODE) == 58
assert len(MESSAGE) == 26

def check(data: bytes) -> dict:
    if len(data) > 131072 or len(data) < 64:
        raise ValueError("bounded ELF length")
    if data[:16] != b"\x7fELF\x02\x01\x01" + b"\0"*9:
        raise ValueError("not ELF64 little-endian SYSV")
    hdr=struct.unpack_from("<16sHHIQQQIHHHHHH",data)
    _,typ,machine,version,entry,phoff,_,_,ehsize,phentsize,phnum,*_=hdr
    if (typ,machine,version,entry,ehsize,phentsize,phnum)!=(3,62,1,0x4000,64,56,6):
        raise ValueError("not independent ELF64 x86-64 PIE layout")
    if phoff > len(data) or phnum*phentsize > len(data)-phoff:
        raise ValueError("program header outside ELF")
    headers=[struct.unpack_from("<IIQQQQQQ",data,phoff+i*phentsize) for i in range(phnum)]
    loads=[h for h in headers if h[0]==1]
    if len(loads)!=4 or [h[3] for h in loads]!=[0,0x4000,0x8000,0xc020]:
        raise ValueError("unexpected PT_LOAD addresses")
    if [h[1] for h in loads]!=[4,5,4,6]:
        raise ValueError("PT_LOAD W^X / flags violation")
    if [h[5] for h in loads][1:] != [58,32,0xea]:
        raise ValueError("text/rodata/data layout lengths changed")
    for h in loads:
        typ,flags,off,vaddr,_,fileSize,memSize,align=h
        if align!=16384 or off%16384!=vaddr%16384 or fileSize>memSize or not fileSize or vaddr+memSize>65536:
            raise ValueError("guest load bounds and alignment")
        if off > len(data) or fileSize > len(data)-off:
            raise ValueError("segment file exceeds ELF bytes")
    if [h[0] for h in headers] != [1,1,1,1,2,0x6474e551]:
        raise ValueError("unknown ELF segment type")
    dynamic=headers[4]
    if dynamic[3]!=0xc020 or dynamic[5]!=0xd0 or dynamic[1]!=6:
        raise ValueError("dynamic guest metadata offset")
    if dynamic[2] > len(data) or dynamic[5] > len(data)-dynamic[2]:
        raise ValueError("dynamic data out of bounds")
    tags=[struct.unpack_from("<qQ",data,dynamic[2]+i)[0] for i in range(0,dynamic[5],16)]
    if not tags or tags[-1]!=0 or any(x in tags for x in (1,7,8,17,18,23,2,12,25,22)):
        raise ValueError("dependencies or relocations forbidden")
    text=loads[1];rodata=loads[2];rw=loads[3]
    if data[text[2]:text[2]+text[5]] != CODE:
        raise ValueError("x86 guest memory copy code changed")
    if data[rodata[2]:rodata[2]+len(MESSAGE)] != MESSAGE:
        raise ValueError("guest template changed")
    scratch=rw[2]+dynamic[5]
    if data[scratch:scratch+len(MESSAGE)] != b"\0"*len(MESSAGE):
        raise ValueError("writable guest data must start all zero")
    if CODE.count(b"\x0f\x05")!=2 or CODE[43:45]!=b"\x0f\x05" or CODE[52:54]!=b"\x0f\x05":
        raise ValueError("unexpected x86 syscall offsets")
    return {"sha256":hashlib.sha256(data).hexdigest(),"size":len(data),
            "guest_code_size":58,"guest_writable_offset":0xc0f0,
            "message_length":26,"guest_syscalls":[1,39],
            "runs_on_device":False}

if __name__ == "__main__":
    r=check(Path(sys.argv[1]).read_bytes())
    print("KERNIX_ELF64_GUEST_RO_TO_RW_MEMORY_COPY_OPCODE_AND_WX_PROOF_PASS")
    print(r)
