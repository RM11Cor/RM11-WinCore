"""Byte-accurate audit of original compiled x86-64 ELF heap syscall guest.

A four-PT_LOAD, 16-KiB-aligned, relocation-free GNU as/ld ELF fixture.
Only the exact 115-byte x86 guest with R10->RBP and R8->RBX low-register copies is accepted.
"""
import hashlib
import struct
import sys
from pathlib import Path

MESSAGE=b"KERNIX_ELF_RW_MEMORY_PASS\n"
CODE=bytes.fromhex(
    "b80900000031ffbe00400000ba0300000041ba2200000049c7c0ffffffff"
    "4531c94c89d54c89c30f054989c4488d35cd3f00004c89e7b91a000000f3a4"
    "b801000000bf010000004c89e6ba1a0000000f0589c3b8270000000f05"
    "4989c5b80b0000004c89e7be004000000f054c89e84801d8f4"
)
assert len(CODE)==115 and len(MESSAGE)==26

def check(data):
    if len(data)<64 or len(data)>131072:
        raise ValueError("bounded ELF size")
    if data[:16]!=b"\x7fELF\x02\x01\x01"+b"\0"*9:
        raise ValueError("ELF64 little-endian SystemV header")
    eh=struct.unpack_from("<16sHHIQQQIHHHHHH",data)
    _,kind,machine,version,entry,phoff,_,_,ehsize,phsize,phnum,*_=eh
    if (kind,machine,version,entry,ehsize,phsize,phnum)!=(3,62,1,0x4000,64,56,6):
        raise ValueError("expected x86-64 PIE / no executable interpreter")
    if phoff>len(data) or phnum*phsize>len(data)-phoff:
        raise ValueError("invalid program header table")
    ph=[struct.unpack_from("<IIQQQQQQ",data,phoff+i*56) for i in range(6)]
    if [p[0] for p in ph] != [1,1,1,1,2,0x6474e551]:
        raise ValueError("unknown segment type")
    load=ph[:4]
    if [p[1] for p in load] != [4,5,4,6] or [p[3] for p in load]!=[0,0x4000,0x8000,0xc020]:
        raise ValueError("R/RX/R/RW segment contract")
    for p in load:
        _,_,off,va,_,filesz,memsz,align=p
        if align!=0x4000 or off%align!=va%align or filesz>memsz or not memsz or va+memsz>65536 or off>len(data) or filesz>len(data)-off:
            raise ValueError("PT_LOAD bounds, alignment or W+X violation")
    if load[1][5]!=len(CODE) or load[2][5]!=32:
        raise ValueError("guest code or rodata length")
    dynamic=ph[4]
    if dynamic[3]!=0xc020 or dynamic[1]!=6 or dynamic[5] not in (0xd0,0xe0) or load[3][5]!=dynamic[5]+8:
        raise ValueError("dynamic header and initial RW scratch")
    if dynamic[2]>len(data) or dynamic[5]>len(data)-dynamic[2]:
        raise ValueError("dynamic table bounds")
    tags=[struct.unpack_from("<qQ",data,dynamic[2]+i)[0] for i in range(0,dynamic[5],16)]
    if not tags or tags[-1]!=0 or any(x in tags for x in (1,7,8,17,18,23,2,12,25,22)):
        raise ValueError("dynamic relocation/dependency not permitted")
    if data[load[1][2]:load[1][2]+len(CODE)] != CODE:
        raise ValueError("guest mmap/write/getpid/munmap opcode changed")
    if data[load[2][2]:load[2][2]+26]!=MESSAGE:
        raise ValueError("guest immutable text message changed")
    if data[load[3][2]+dynamic[5]:load[3][2]+dynamic[5]+8]!=bytes(8):
        raise ValueError("guest .data not zeroed")
    if [i for i in range(len(CODE)-1) if CODE[i:i+2]==b"\x0f\x05"] != [39,79,88,106]:
        raise ValueError("guest syscall offsets changed")
    return {"size":len(data),"sha256":hashlib.sha256(data).hexdigest(),
            "four_guest_linux_syscalls":[9,1,39,11],
            "guest_virtual_memory":16384,"guest_code_bytes":115,
            "android_execution_verified":False}

if __name__=="__main__":
    out=check(Path(sys.argv[1]).read_bytes())
    print("KERNIX_X86_ELF64_FOUR_SYSCALL_HEAP_FIXTURE_STRUCTURAL_AND_OPCODE_PASS")
    print(out)
