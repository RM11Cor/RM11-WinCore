#!/usr/bin/env python3
"""Fail-closed SHA256-pinned original ELF weak GLOB_DAT inventory.

Source-only: no guest execution, no weak GOT value/RELRO/gameplay claims.
"""
import hashlib
import json
import re
import struct
from pathlib import Path

MAIN = Path("dist/original-source-pinned-root/bin/kernix-g2e-dynamic-guest")
MAIN_SHA = "9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412"

def verify(ok, reason):
    if not ok: raise AssertionError(reason)

def run():
    b=MAIN.read_bytes()
    verify(len(b)==15976 and hashlib.sha256(b).hexdigest()==MAIN_SHA,
           "original main SHA256 mismatch")
    verify(b[:6]==bytes.fromhex("7f454c460201")
           and struct.unpack_from("<H",b,18)[0]==62,
           "original source is not x86_64 ELF64")
    off=struct.unpack_from("<Q",b,32)[0]
    size,count=struct.unpack_from("<HH",b,54)
    verify(size==56 and 0<count<=64 and off+56*count<=len(b),
           "invalid source PT headers")
    ph=[struct.unpack_from("<IIQQQQQQ",b,off+i*56) for i in range(count)]
    loads=[p for p in ph if p[0]==1]
    dyn=[p for p in ph if p[0]==2]
    relro=[p for p in ph if p[0]==0x6474e552]
    verify(len(loads)>1 and len(dyn)==1 and len(relro)==1,
           "source load/dynamic/RELRO program headers changed")
    def fileoff(va,n):
        choices=[p[2]+va-p[3] for p in loads
            if n>0 and va>=p[3] and va-p[3]+n<=p[5] and
            p[2]<=len(b) and p[5]<=len(b)-p[2]]
        verify(len(choices)==1,"ambiguous original VMA/file mapping")
        return choices[0]
    p=dyn[0]
    verify(p[5]%16==0 and p[2]+p[5]<=len(b),
           "invalid PT_DYNAMIC source size")
    tags={}
    ended=False
    for i in range(p[2],p[2]+p[5],16):
        tag,value=struct.unpack_from("<qQ",b,i)
        if tag==0:
            ended=True
            break
        if tag in (5,6,7,8,9,10,11):
            verify(tag not in tags,"duplicate DT tag")
            tags[tag]=value
    verify(ended and all(t in tags for t in (5,6,7,8,9,10,11)),
           "original ELF dynamic tags incomplete")
    verify(tags[8]==192 and tags[9]==24 and tags[11]==24 and
           0<tags[10]<=8192,"original DT_RELA inventory size changed")
    strings=b[fileoff(tags[5],tags[10]):][:tags[10]]
    rela=fileoff(tags[7],tags[8])
    rows=[]
    for i in range(8):
        target,info,addend=struct.unpack_from("<QQq",b,rela+i*24)
        rtype=info&0xffffffff
        index=info>>32
        if i<3:
            verify(rtype==8 and index==0,"original RELATIVE inventory changed")
            continue
        verify(rtype==6 and 0<index<65536,"original GLOB_DAT inventory changed")
        symoff=fileoff(tags[6]+index*24,24)
        nameidx,attr,_,section,value,_=struct.unpack_from("<IBBHQQ",b,symoff)
        verify(0<nameidx<len(strings),"bad source name index")
        end=strings.find(b"\0",nameidx)
        verify(end>nameidx and end-nameidx<=96,"bad source symbol name")
        name=strings[nameidx:end].decode("ascii")
        verify(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_@.]*",name),
               "unexpected source symbol name")
        start,finish=relro[0][3],relro[0][3]+relro[0][6]
        verify(start<=target and target+8<=finish,"GOT outside original RELRO")
        initial=struct.unpack_from("<Q",b,fileoff(target,8))[0]
        verify(addend==0 and initial==0,"unexpected GLOB_DAT source initializer")
        rows.append({"rela_index":i,"symbol":name,"symbol_index":index,
            "binding":attr>>4,"type":attr&15,"defined_section":section,
            "st_value":value,"r_offset":hex(target),
            "guest_target":hex(0x800000000+target),"source_initial":0})
    weak=[x for x in rows if x["binding"]==2]
    strong=[x for x in rows if x["binding"]==1]
    verify(len(weak)==4 and len(strong)==1 and
           strong[0]["symbol"]=="__libc_start_main" and
           strong[0]["r_offset"]=="0x3fd8",
           "four weak / one strong GLOB_DAT evidence changed")
    verify(len({x["guest_target"] for x in rows})==5,
           "duplicate original GLOB_DAT target")
    for sym in weak:
        verify(sym["defined_section"]==0 and sym["st_value"]==0,
               "source weak symbol is not originally undefined")
    report={"schema":"kernix.g0.source-original-weak-globdat.v1",
        "original_main_sha256":MAIN_SHA,"DT_RELA_count":8,
        "weak_GLOB_DAT":weak,"strong_GLOB_DAT_source":strong[0],
        "weak_imports_can_legitimately_resolve_to_zero":True,
        "weak_runtime_values_or_writers_proven":False,
        "all_original_main_relocations_proven":False,
        "original_main_RELRO_sealed":False,
        "android_bionic_or_gameplay_proven":False}
    Path("dist/original-main-weak-globdat-source-inventory.json").write_text(
        json.dumps(report,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_MAIN_FOUR_UNDEFINED_WEAK_GLOB_DAT_SOURCE_SHA256_INVENTORY_PASS")
    print(json.dumps({"weak_symbols":[z["symbol"] for z in weak],
        "runtime_writes_proven":False,"RELRO_sealed":False},sort_keys=True))

if __name__=="__main__":
    run()
