#!/usr/bin/env python3
"""Source-only: original immutable x86 libc executable syscall instruction.

Original Linux ARM64 FEX reached original libc guest rip 0x80411d082
with prlimit64(302), pid0/resource3/new=NULL/old guest 0x80300fab0.
The file's original RX source MUST contain 0F 05 at source VA 0x11d082.
This source-only audit never proves a prlimit64 kernel call, guest output,
protected libc/main/ldso ELF or any game.
"""
from __future__ import annotations
import hashlib,json,struct,sys
from pathlib import Path
PIN="7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906"
SOURCE_VA=0x11d082
ORIGINAL_GUEST_RIP=0x80411d082
class Denied(ValueError): pass
def need(test,msg):
    if not test:raise Denied(msg)
def validate(raw,source_sha=True):
    if source_sha:
        need(len(raw)==2118168 and hashlib.sha256(raw).hexdigest()==PIN,
             "original libc source exact immutable SHA/size absent")
    need(raw[:6]==bytes.fromhex("7f454c460201") and
         struct.unpack_from("<HH",raw,16)==(3,62),"not x86_64 original libc ELF ET_DYN")
    pht=struct.unpack_from("<Q",raw,32)[0]
    sz,n=struct.unpack_from("<HH",raw,54)
    need(sz==56 and n>0 and n<128 and pht+sz*n<=len(raw),"ELF PHT corrupt")
    matches=[]
    for i in range(n):
        t,flags,offset,va,_,filesize,memsz,_=struct.unpack_from("<IIQQQQQQ",raw,pht+i*sz)
        if t!=1 or not(flags&1) or (flags&2):
            continue
        need(offset+filesize<=len(raw) and filesize<=memsz,"source RX PTLOAD invalid")
        if va<=SOURCE_VA and SOURCE_VA+2<=va+filesize:
            at=offset+SOURCE_VA-va
            matches.append((at,va,filesize))
    need(len(matches)==1,"source syscall RIP not uniquely in original libc RX PTLOAD")
    offset,va,size=matches[0]
    need(raw[offset:offset+2]==b"\x0f\x05",
         "source original libc syscall opcode must be 0F 05 at 0x11d082")
    return {
      "schema":"kernix.g0.source-original-libc-prlimit64-x86-elf-rx-syscall-only.v1",
      "original_libc_sha256":PIN,
      "guest_original_libc_load_bias":"0x804000000",
      "original_source_libc_syscall_va":hex(SOURCE_VA),
      "original_source_guest_syscall_rip":hex(ORIGINAL_GUEST_RIP),
      "original_source_libc_syscall_file_offset":hex(offset),
      "original_x86_64_syscall_opcode":"0f05",
      "observed_original_FEX_next_syscall_number":302,
      "observed_original_FEX_pid":0,
      "observed_original_FEX_resource_RLIMIT_STACK":3,
      "observed_original_FEX_new_limit_pointer":0,
      "observed_original_FEX_guest_old_limit_pointer":"0x80300fab0",
      "original_FEX_prlimit64_native_kernel_success_proven":False,
      "original_guest_stack_16byte_output_written_proven":False,
      "Android_16K_Wine_Proton_game_execution_proven":False
    }
def negatives(source):
    wrong=bytearray(source);wrong[-1]^=1
    try:validate(wrong)
    except Denied:print("KERNIX_G0_LIBC_PRLIMIT_OPCODE_FORGED_01_REJECTED sha")
    else:raise Denied("wrong SHA")
    checks=[
      ("opcode", lambda d:d.__setitem__(int(validate(source)["original_source_libc_syscall_file_offset"],16),0x90)),
      ("elf64 header",lambda d:d.__setitem__(4,1)),
      ("machine",lambda d:d.__setitem__(18,0)),
      ("source PHT entry count",lambda d:d.__setitem__(56,0)),
    ]
    for i,(name,change) in enumerate(checks,2):
        d=bytearray(source);change(d)
        try:validate(d,False)
        except Denied:print(f"KERNIX_G0_LIBC_PRLIMIT_OPCODE_FORGED_{i:02d}_REJECTED {name}")
        else:raise Denied("bad original libc source mutation accepted: "+name)
    return 5
def main(args):
    if len(args)!=3 or args[1]!="selftest":
        print("usage: validator.py selftest SOURCE_LIBC_SO_6",file=sys.stderr)
        return 2
    src=Path(args[2]).read_bytes()
    r=validate(src)
    need(negatives(src)==5,"missing 5 negative mutation tests")
    print(json.dumps(r,indent=2))
    print("KERNIX_G0_ORIGINAL_LIBC_PRLIMIT64_AUTHENTIC_X86_RX_SOURCE_SYSCALL_OPCODE_PROVEN_ONLY_NO_GUEST_RESPONSE")
    return 0
if __name__=="__main__":
    try:raise SystemExit(main(sys.argv))
    except (Denied,struct.error,ValueError,TypeError,IndexError) as e:
        print("KERNIX_G0_ORIGINAL_LIBC_PRLIMIT64_RX_SOURCE_FAIL_CLOSED: "+str(e),file=sys.stderr)
        raise SystemExit(1)
