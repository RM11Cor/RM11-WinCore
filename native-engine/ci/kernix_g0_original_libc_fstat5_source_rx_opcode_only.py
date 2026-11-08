#!/usr/bin/env python3
"""Independent source-only AMD64 original GNU libc fstat(5) syscall RX check.

The real source-pinned FEX ARM64 Linux process after real libc/main/ldso
RELRO and prlimit64 requested fstat(5) with fd=1, guest buffer at
0x80300fbc0, and x86 RIP 0x804117249. The immutable libc x86 ELF file
must have 0f05 inside its original, source-proven RX PT_LOAD. No guest
fstat result, guest write or Android execution is claimed here.
"""
from __future__ import annotations
import hashlib
import json
import struct
import sys
from pathlib import Path
PIN="7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906"
FILE_BYTES=2118168
SOURCE_VA=0x117249
GUEST_RIP=0x804117249
class Invalid(ValueError):pass
def need(value,message):
    if not value:raise Invalid(message)
def classify(data,sha=True):
    if sha:
        need(len(data)==FILE_BYTES and hashlib.sha256(data).hexdigest()==PIN,
             "immutable original x86 libc SHA and length changed")
    need(len(data)>64 and data[:6]==bytes.fromhex("7f454c460201"),
         "not little-endian ELF64 original libc")
    need(struct.unpack_from("<HH",data,16)==(3,62),
         "source original libc not ET_DYN x86_64")
    phoff=struct.unpack_from("<Q",data,32)[0]
    entsize,n=struct.unpack_from("<HH",data,54)
    need(entsize==56 and 0<n<128 and phoff+entsize*n<=len(data),
         "source x86 ELF PHT out of bounds")
    matched=[]
    for i in range(n):
        t,flags,offset,va,_,filesz,memsz,_=struct.unpack_from("<IIQQQQQQ",
                                                                data,phoff+i*entsize)
        if t!=1 or not(flags&1) or flags&2:continue
        need(offset<=len(data) and filesz<=len(data)-offset and filesz<=memsz,
             "source libc RX PT_LOAD outside immutable ELF file")
        if va<=SOURCE_VA and SOURCE_VA-va<=filesz and
           filesz-(SOURCE_VA-va)>=2:
            matched.append(offset+SOURCE_VA-va)
    need(len(matched)==1,"source x86 fstat syscall offset not unique in original RX PT_LOAD")
    at=matched[0]
    need(data[at:at+2]==b"\x0f\x05",
         "original x86 libc fstat RIP bytes not syscall 0f05")
    return {
      "schema":"kernix.g0.source-original-libc-fstat5-stdout-guest-rip-immutable-elf-x86-rx-opcode.v1",
      "libc_sha256":PIN,
      "original_source_libc_guest_load_bias":"0x804000000",
      "original_source_libc_syscall_file_offset":hex(at),
      "original_guest_fstat5_source_RIP":hex(GUEST_RIP),
      "original_x86_syscall_opcode":"0f05",
      "observed_original_FEX_guest_x86_syscall_number":5,
      "observed_original_FEX_guest_stdout_descriptor":1,
      "observed_original_FEX_guest_x86_stat_output":"0x80300fbc0",
      "required_guest_Linux_x86_stat_struct_bytes":144,
      "FEX_guest_fstat_completed_proven":False,
      "native_kernel_fstat_completed_proven":False,
      "guest_owned_stack_stat144_write_proven":False,
      "source_guest_program_exit_zero_proven":False,
      "android_16K_bionic_wine_proton_games_proven":False
    }
def negatives(data):
    before=classify(data)
    at=int(before["original_source_libc_syscall_file_offset"],16)
    muts=[
      ("SHA last byte",len(data)-1,data[-1]^1,True),
      ("source x86 syscall 0f changed to 90",at,0x90,False),
      ("source x86 syscall 05 changed to 90",at+1,0x90,False),
      ("ELF class",4,1,False),
      ("wrong ELF machine",18,0,False),
      ("no program headers",56,0,False),
    ]
    for i,(label,idx,value,sha) in enumerate(muts,1):
        b=bytearray(data);b[idx]=value
        need(b!=data,"mutation did not alter original source "+label)
        try:classify(bytes(b),sha)
        except (Invalid,struct.error,ValueError):
            print(f"KERNIX_G0_LIBC_FSTAT5_SOURCE_FORGED_{i:02d}_REJECTED {label}")
        else:raise Invalid("forged libc original source fstat proof accepted: "+label)
    return len(muts)
def main(args):
    if len(args)!=3 or args[1]!="selftest":
        print("usage: fstat-source.py selftest ORIGINAL_LIBC_SO_6",file=sys.stderr)
        return 2
    data=Path(args[2]).read_bytes()
    report=classify(data)
    need(negatives(data)==6,"missing fake source mutation controls")
    print(json.dumps(report,indent=2,sort_keys=True))
    print("KERNIX_G0_ORIGINAL_LIBC_FSTAT5_SOURCE_RX_SYSCALL_0F05_SHA_PINNED_ONLY_GUEST_RESULT_UNPROVEN")
    return 0
if __name__=="__main__":
    try:raise SystemExit(main(sys.argv))
    except (Invalid,ValueError,IndexError,struct.error,KeyError,TypeError) as ex:
        print("KERNIX_G0_ORIGINAL_LIBC_FSTAT5_SOURCE_RX_FAIL_CLOSED: "+str(ex),file=sys.stderr)
        raise SystemExit(1)
