#!/usr/bin/env python3
"""Fail-closed source-locked original GNU ldso PT_GNU_RELRO 4K page census.

Only source ELF PT_GNU_RELRO program-header bounds and source IRELATIVE
relocation determine whether the subsequent 0x801036000 x86 mprotect(10)
could possibly be a genuine self page protection. Does not grant a guest
kernel syscall, prove resolver guest entry or post-seal protection, or run
any app. Uses original immutable x86 ld-linux, never forged ELF metadata.
"""
from __future__ import annotations
import copy
import hashlib
import json
import struct
import sys
from pathlib import Path
LD_SHA="cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"
FEX_PIN="02e24ca5c01ed0c864466ed573db347336f70170"
BASE=0x801000000
PAGE=4096
TARGET=0x801036360
RESOLVER=0x80101a8e0
class Refuse(ValueError):pass
def must(b,s):
    if not b:raise Refuse(s)

def classify(data, check_sha=True):
    if check_sha:
        must(len(data)==235408 and hashlib.sha256(data).hexdigest()==LD_SHA,
             "original ld-linux SHA256/length mismatch")
    must(data[:6]==bytes.fromhex("7f454c460201"),"ELF64 little endian changed")
    must(struct.unpack_from("<H",data,16)[0]==3 and
         struct.unpack_from("<H",data,18)[0]==62,"not original x86-64 ET_DYN")
    off=struct.unpack_from("<Q",data,32)[0]
    sz,n=struct.unpack_from("<HH",data,54)
    must(sz==56 and 0<n<=128 and off+n*sz<=len(data),"PHT bounds unsafe")
    ph=[struct.unpack_from("<IIQQQQQQ",data,off+i*sz) for i in range(n)]
    loads=[p for p in ph if p[0]==1]
    assert loads
    def source_range(va,size):
        matches=[p for p in loads if
                 p[3]<=va and va+size<=p[3]+p[5] and
                 p[2]+p[5]<=len(data) and p[5]<=p[6]]
        must(len(matches)==1,"source range does not live in one file-backed PT_LOAD")
        p=matches[0]
        f=p[2]+va-p[3]
        must(0<=f and f+size<=len(data),"source file range overflow")
        return f
    relro=[p for p in ph if p[0]==0x6474e552]
    must(len(relro)==1 and relro[0][5]<=relro[0][6],
         "original ldso PT_GNU_RELRO count/source bounds")
    p=relro[0]
    va,size=p[3],p[6]
    must(size>0 and va+size>va and va+size<1<<64,"original loader PT_GNU_RELRO overflow")
    first=(va//PAGE)*PAGE
    end=((va+size)//PAGE)*PAGE
    must(first<end and first%PAGE==0 and end%PAGE==0,
         "source ldso must have complete 4k GNU RELRO page")
    must(va<=0x36360<va+size and first<=0x36360<end,
         "original source IRELATIVE slot not actually in full GNU RELRO page")
    must(end-first==4096 and first==0x36000 and end==0x37000,
         "original subsequent ldso mprotect request 0x801036000, 4KiB not proven by PHT")
    writable=[p for p in loads if (p[1]&2)!=0 and (p[1]&1)==0
              and p[3]<=0x36360 and 0x36360+8<=p[3]+p[6]]
    must(len(writable)==1,"original ldso RELRO qword is not exclusively in writable non-executable PT_LOAD")
    ix=source_range(0x36360,8)
    must(struct.unpack_from("<Q",data,ix)[0]==0,"original GNU self IRELATIVE initial source value not 0")
    must(data[source_range(0xfd60,3):source_range(0xfd60,3)+3]==bytes.fromhex("498906"),
         "GNU original self x86 source writer byte mismatch")
    must(data[source_range(0x1a8e0,4):source_range(0x1a8e0,4)+4]==bytes.fromhex("f30f1efa"),
         "GNU original IFUNC resolver guest entry mismatch")
    dyn=[p for p in ph if p[0]==2]
    must(len(dyn)==1,"not exactly one GNU loader PT_DYNAMIC")
    d=dyn[0]
    must(d[2]+d[5]<=len(data),"GNU DT_DYNAMIC source out of file")
    tags={}
    for i in range(d[2],d[2]+d[5],16):
        must(i+16<=len(data),"GNU dynamic tag truncated")
        k,v=struct.unpack_from("<QQ",data,i)
        if k==0:break
        must(k not in tags,"duplicate dynamic tag")
        tags[k]=v
    must(tags.get(9)==24 and tags.get(8,0)%24==0
         and tags.get(8,0)>0 and tags.get(8,0)<=10000,
         "source DT_RELA entries corrupted")
    rela=[struct.unpack_from("<QQq",data,source_range(tags[7]+i*24,24))
          for i in range(tags[8]//24)]
    must(rela.count((0x36360,37,0x1a8e0))==1,
         "original GNU IRELATIVE self slot / resolver source record missing")
    return {
      "schema":"kernix.g0.source-authentic-original-gnu-ldso-self-relro-4k-bounds-not-execution.v1",
      "source_original_ldso_sha256":LD_SHA,
      "source_upstream_FEX_commit":FEX_PIN,
      "source_original_ldso_load_bias":hex(BASE),
      "source_PT_GNU_RELRO_raw_vaddr":hex(va),
      "source_PT_GNU_RELRO_raw_length":hex(size),
      "source_PT_GNU_RELRO_entire_guest_4k_page_start":hex(BASE+first),
      "source_PT_GNU_RELRO_entire_guest_4k_page_end":hex(BASE+end),
      "original_self_irelative_guest_target":hex(TARGET),
      "original_resolver_source_guest_entry":hex(RESOLVER),
      "original_writer_source_guest_rip":hex(BASE+0xfd60),
      "source_irelative_slot_is_within_full_pt_gnu_relro_page":True,
      "source_irelative_slot_initial_zero":True,
      "source_original_x86_writer_three_bytes":"498906",
      "actual_FEX_self_resolver_guest_entry_and_return_proven":False,
      "actual_FEX_ldso_self_kernel_mprotect_executed":False,
      "actual_FEX_ldso_self_RELRO_sealed":False,
      "original_guest_linux_executable_exit_zero":False,
      "android_bionic_wine_proton_games_proven":False
    }

def negatives(data):
    cases=[
      ("alter source x86 writer",0xfd60,0x49^1),
      ("alter original source resolver first byte",0x1a8e0,0xf3^1),
      ("poison original ELF header",0,0),
    ]
    bad_sha=bytearray(data)
    bad_sha[-1]^=0x01
    try:classify(bytes(bad_sha))
    except Refuse:print("KERNIX_G0_ORIGINAL_LDSO_SOURCE_RELRO_NEGATIVE_01_REJECTED sha digest")
    else:raise Refuse("corrupt immutable original ldso SHA accepted")
    for i,(name,at,b) in enumerate(cases,2):
        bad=bytearray(data);bad[at]=b
        try:classify(bytes(bad),False)
        except Refuse:print(f"KERNIX_G0_ORIGINAL_LDSO_SOURCE_RELRO_NEGATIVE_{i:02d}_REJECTED {name}")
        else:raise Refuse("mutated ELF structure source accepted: "+name)
    return 4
def main(args):
    if len(args)!=3 or args[1]!="selftest":
        print("usage: source_ldso.py selftest SOURCE_LD_SO",file=sys.stderr)
        return 2
    data=Path(args[2]).read_bytes()
    report=classify(data)
    must(negatives(data)==4,"negative control count")
    print(json.dumps(report,indent=2,sort_keys=True))
    print("KERNIX_G0_SOURCE_GNU_LDSO_SELF_RELRO_4K_PHT_AND_IRELATIVE_BOUNDARY_PASS_NO_REAL_PROTECT")
    return 0
if __name__=="__main__":
    try:raise SystemExit(main(sys.argv))
    except (Refuse,IndexError,KeyError,TypeError,ValueError,struct.error) as ex:
        print("KERNIX_G0_SOURCE_LDSO_SELF_RELRO_FAIL_CLOSED: "+str(ex),file=sys.stderr)
        raise SystemExit(1)
