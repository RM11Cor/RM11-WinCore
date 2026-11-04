#!/usr/bin/env python3
"""KERNIX G2-C x86 guest ELF PT_LOAD page-permission isolation for Android.

This is a static, fail-closed layout gate for the limited MIT-only
direct-entry witness. A successful host check NEVER proves device FEX
execution, guest loader support, or Android 16KiB mmap behavior.
"""
import argparse
from pathlib import Path
import struct

ELF_HDR = struct.Struct("<16sHHIQQQIHHHHHH")
PHDR = struct.Struct("<IIQQQQQQ")
PT_LOAD = 1
PF_X = 1
PF_W = 2
PAGE = 16384


def load_ranges(path, page=PAGE):
    blob = Path(path).read_bytes()
    if len(blob) < ELF_HDR.size or len(blob) > 4 * 1024 * 1024:
        raise ValueError("Guest ELF outside immutable fixture bounds")
    (magic, etype, machine, _version, _entry, phoff, _shoff,
     _flags, _ehsize, phentsz, phnum, _shentsz, _shnum, _shstrndx) =         ELF_HDR.unpack_from(blob)
    if magic[:6] != b"\x7fELF\x02\x01" or etype != 3 or machine != 62:
        raise ValueError("Guest ELF is not little-endian x86_64 ET_DYN")
    if phnum == 0 or phnum > 128 or phentsz != PHDR.size or        phoff > len(blob) or phnum * PHDR.size > len(blob) - phoff:
        raise ValueError("Unbounded ELF program headers")
    occupied = {}
    load_count = 0
    executable = 0
    writable = 0
    for index in range(phnum):
        ptype, flags, off, addr, _phys, filesz, memsz, alignment =             PHDR.unpack_from(blob,phoff + index * phentsz)
        if ptype != PT_LOAD:
            continue
        load_count += 1
        if filesz > memsz or off > len(blob) or filesz > len(blob)-off:
            raise ValueError("Malformed guest load size")
        if addr > (1<<47) or memsz > (1<<47)-addr:
            raise ValueError("Guest load exceeds user VA space")
        if alignment < page or alignment & (alignment-1):
            raise ValueError("Guest PT_LOAD p_align too small for 16KiB Android host")
        if (addr-off) % page:
            raise ValueError("Guest PT_LOAD offset/VA misaligned to 16KiB host")
        if flags & PF_W and flags & PF_X:
            raise ValueError("Guest PT_LOAD requests RWX")
        if not memsz:
            continue
        if flags & PF_X:
            executable += 1
        if flags & PF_W:
            writable += 1
        start = addr // page
        end = (addr+memsz+page-1)//page
        for page_index in range(start,end):
            previous = occupied.get(page_index)
            if previous is not None and previous != index:
                raise ValueError(
                    "Different PT_LOAD segments share a 16KiB host page: unsafe permissions")
            occupied[page_index] = index
    if load_count < 2 or executable != 1 or writable != 1:
        raise ValueError("Guest must have exactly one RX and one RW load")
    return {
        "file":str(path),
        "host_page_bytes_checked":page,
        "load_phdr_count":load_count,
        "executable_loads":executable,
        "writable_loads":writable,
        "occupied_16k_host_pages":len(occupied),
        "shared_16k_host_pages":0,
        "guest_code_executed":False,
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("paths",nargs="+")
    p.add_argument("--expect-reject",action="store_true")
    args=p.parse_args()
    for name in args.paths:
        try:
            result=load_ranges(name)
        except ValueError as error:
            if not args.expect_reject:
                raise
            print("KERNIX_G2C_MIT_GUEST_16K_UNSAFE_V1_LAYOUT_REJECTED:",str(error))
        else:
            if args.expect_reject:
                raise ValueError("Unsafe legacy guest was incorrectly admitted")
            print("KERNIX_G2C_MIT_16K_HOST_ELF_PTLOAD_WX_ISOLATION_PASS_NOT_ANDROID",result)


if __name__=="__main__":
    main()
