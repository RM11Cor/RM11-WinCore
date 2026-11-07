#!/usr/bin/env python3
"""Source-authenticate four weak GLOB_DAT observed GOT values at a real puts stop.

This verifies source-consistent values only, NOT original weak guest writers,
complete main relocation closure, main PT_GNU_RELRO sealing or Android games.
"""
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path

DIST=Path("dist")
ROOT=DIST/"original-source-pinned-root"
MAIN=ROOT/"bin/kernix-g2e-dynamic-guest"
LIBC=ROOT/"lib/x86_64-linux-gnu/libc.so.6"
LDSO=ROOT/"lib64/ld-linux-x86-64.so.2"
SRC=DIST/"original-main-weak-globdat-source-inventory.json"
SNAP=DIST/"original-four-weak-got-after-puts-hw-stop.json"
LOG=DIST/"original-main-puts-jumpslot-watch.log"
OUT=DIST/"original-four-weak-source-vs-live-got-evidence.json"
SHA={
    MAIN:("9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412",15976),
    LIBC:("7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906",2118168),
    LDSO:("cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae",235408),
}
EXPECTED=[
    ("_ITM_deregisterTMCloneTable",4,0x3fe0,0),
    ("__gmon_start__",5,0x3fe8,0),
    ("_ITM_registerTMCloneTable",6,0x3ff0,0),
    ("__cxa_finalize",7,0x3ff8,0x8040472a0),
]

def require(condition,label):
    if not condition:
        raise AssertionError(label)

def readelf(args,path):
    return subprocess.run(["readelf","-W",*args,str(path)],
        check=True,capture_output=True,text=True,timeout=15).stdout

def exported_symbols(blob):
    rows=[]
    for s in blob.splitlines():
        m=re.match(r"^\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+"
                   r"(\w+)\s+(\w+)\s+(\w+)\s+(\S+)\s+(\S+)",s)
        if m:
            va,size,typ,bind,vis,shndx,name=m.groups()
            rows.append(dict(va=int(va,16),size=int(size),type=typ,
                bind=bind,visibility=vis,section=shndx,name=name))
    return rows

def source_executable_range(data,va,n):
    require(data[:6]==bytes.fromhex("7f454c460201")
        and struct.unpack_from("<H",data,18)[0]==62,
        "not source x86-64 ELF")
    off=struct.unpack_from("<Q",data,32)[0]
    entsize,count=struct.unpack_from("<HH",data,54)
    require(entsize==56 and 1<=count<=64 and
            off+56*count<=len(data),"source program headers out of bounds")
    result=[]
    for i in range(count):
        kind,flags,foff,vaddr,_,fsize,msize,_=struct.unpack_from(
            "<IIQQQQQQ",data,off+i*56)
        if (kind==1 and flags&5==5 and flags&2==0 and
            vaddr<=va and va-vaddr+n<=fsize and
            foff<=len(data) and fsize<=len(data)-foff):
            result.append(foff+va-vaddr)
    require(len(result)==1,"source libc export not within one RX PT_LOAD")
    require(data[result[0]:result[0]+n]!=bytes(n),
            "source libc code at export unexpectedly all zero")
    return result[0]

def accepts(rows,expected_names,version,source_offset,load_bias,provider_ok):
    if len(rows)!=4 or expected_names!=[x[0] for x in EXPECTED]:
        return False
    if version!="GLIBC_2.2.5" or source_offset!=0x472a0 or load_bias!=0x804000000:
        return False
    if provider_ok is not True:
        return False
    return all(row["symbol"]==symbol and
               row["rela_index"]==index and
               int(row["r_offset"],16)==offset and
               int(row["observed_guest_GOT_value"],16)==value
               for row,(symbol,index,offset,value) in zip(rows,EXPECTED))

def main():
    contents={}
    for path,(sha,size) in SHA.items():
        data=path.read_bytes()
        require(len(data)==size and hashlib.sha256(data).hexdigest()==sha,
                "original ELF source hash mismatch: "+str(path))
        contents[path]=data
    source=json.loads(SRC.read_text())
    snapshot=json.loads(SNAP.read_text())
    log=LOG.read_text(errors="replace")
    require(source["schema"]=="kernix.g0.source-original-weak-globdat.v1"
        and source["original_main_sha256"]==SHA[MAIN][0]
        and source["all_original_main_relocations_proven"] is False,
        "weak source inventory must be original and fail-closed")
    require(snapshot["schema"]==
        "kernix.g0.original-four-weak-got-at-puts-hardware-stop.v1"
        and snapshot["original_main_sha256"]==SHA[MAIN][0]
        and snapshot["original_puts_exact_guest_writer_RIP_proven"] is True
        and snapshot["weak_GOT_values_read_at_hardware_stop"] is True
        and snapshot["weak_GLOB_DAT_actual_guest_writers_proven"] is False
        and snapshot["original_main_RELRO_sealed"] is False,
        "read-only live weak GOT snapshot not authentic or claims writers")
    names=[z["symbol"] for z in source["weak_GLOB_DAT"]]
    rows=snapshot["weak_source_GOT_snapshot"]
    require(len(rows)==4 and rows==[
        {**src,"observed_guest_GOT_value":snap["observed_guest_GOT_value"],
         "observed_is_zero":snap["observed_is_zero"]}
        for src,snap in zip(source["weak_GLOB_DAT"],rows)],
        "live weak entries do not preserve original source row identities")
    require(all(z["observed_is_zero"]==
        (int(z["observed_guest_GOT_value"],16)==0) for z in rows),
        "live zero status inconsistent with read-only snapshot")
    require(log.count(
        "KERNIX_G0_ORIGINAL_FOUR_WEAK_GLOB_DAT_GOT_VALUES_READONLY_AT_REAL_PUTS_HW_STOP_PASS"
        )==0,"must use observed GDB log, not fabricated a prior pass marker")
    begin="KERNIX_G0_FOUR_SOURCE_WEAK_GOT_AT_AUTHENTIC_PUTS_JUMP_SLOT_WRITE_BEGIN"
    end="KERNIX_G0_FOUR_SOURCE_WEAK_GOT_AT_AUTHENTIC_PUTS_JUMP_SLOT_WRITE_END"
    require(log.count(begin)==1 and log.count(end)==1 and
            log.index(begin)<log.index(end),
            "genuine read-only GDB source data delimiters absent")
    region=log.split(begin,1)[1].split(end,1)[0]
    mem=re.findall(
        r"(?m)^[ \t]*(0x[0-9a-fA-F]+):\s*(0x[0-9a-fA-F]+)[ \t]*$",region)
    require(len(mem)==4,"four real weak guest GOT GDB rows not present")
    for row,(address,value) in zip(rows,mem):
        require(int(address,16)==int(row["guest_target"],16) and
                int(value,16)==int(row["observed_guest_GOT_value"],16),
                "source weak GOT evidence does not match actual GDB memory")
    libc_rows=exported_symbols(readelf(["--dyn-syms"],LIBC))
    ldso_rows=exported_symbols(readelf(["--dyn-syms"],LDSO))
    main_rows=exported_symbols(readelf(["--dyn-syms"],MAIN))
    needed=re.findall(r"\(NEEDED\)\s+Shared library:\s+\[([^\]]+)\]",
        readelf(["-d"],MAIN))
    require(needed==["libc.so.6"],"other source DSOs might provide weak symbols")
    for name in names[:3]:
        require(not any(
            z["name"].split("@",1)[0]==name and z["section"]!="UND"
            for z in [*libc_rows,*ldso_rows,*main_rows]),
            "a supposedly unresolved weak symbol has source provider: "+name)
        imported=[z for z in main_rows if z["name"]==name]
        require(len(imported)==1 and imported[0]["bind"]=="WEAK"
                and imported[0]["section"]=="UND",
                "source weak import classification changed: "+name)
    last=[z for z in main_rows if z["name"]==
        "__cxa_finalize@GLIBC_2.2.5"]
    require(len(last)==1 and last[0]["bind"]=="WEAK" and
            last[0]["section"]=="UND",
            "source __cxa_finalize required version changed")
    provider=[z for z in libc_rows if
        z["name"]=="__cxa_finalize@@GLIBC_2.2.5"]
    require(len(provider)==1 and provider[0]["type"]=="FUNC"
        and provider[0]["bind"]=="GLOBAL"
        and provider[0]["visibility"]=="DEFAULT"
        and provider[0]["section"]!="UND"
        and provider[0]["va"]==0x472a0 and provider[0]["size"]>0,
        "original libc __cxa_finalize versioned provider changed")
    off=source_executable_range(contents[LIBC],provider[0]["va"],8)
    mapped=re.search(
        r"KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_LIBC_MMAP9_LARGE_PRIVATE_RO_SOURCE_"
        r"\d+_REQUEST_0x[0-9a-f]+_FD100_OFFSET0_WX_SAFE_EOF_GUARD_PASS "
        r"guest_base=([0-9a-fA-F]+)",log)
    require(mapped is not None,"real guest libc source mapping absent")
    load_bias=int(mapped.group(1),16)
    check=accepts(rows,names,"GLIBC_2.2.5",provider[0]["va"],load_bias,True)
    require(check,"real weak GLOB_DAT values do not match original sources")
    tests=[]
    for index in range(4):
        altered=[dict(x) for x in rows]
        altered[index]["observed_guest_GOT_value"]=hex(
            1 if index<3 else 0x8040472a1)
        tests.append(not accepts(altered,names,"GLIBC_2.2.5",
                                 provider[0]["va"],load_bias,True))
    for args in (
        (rows,names,"GLIBC_2.34",provider[0]["va"],load_bias,True),
        (rows,names,"GLIBC_2.2.5",provider[0]["va"]+1,load_bias,True),
        (rows,names,"GLIBC_2.2.5",provider[0]["va"],load_bias+4096,True),
        (rows,names,"GLIBC_2.2.5",provider[0]["va"],load_bias,False),
        (rows,names[::-1],"GLIBC_2.2.5",provider[0]["va"],load_bias,True),
    ): tests.append(not accepts(*args))
    require(len(tests)==9 and all(tests),
        "corrupt source/live weak GOT comparator input accepted")
    evidence=dict(snapshot)
    evidence.update(
        schema="kernix.g0.weak-globdat-source-consistent-runtime-snapshot.v1",
        source_libc_sha256=SHA[LIBC][0],
        source_ldso_sha256=SHA[LDSO][0],
        original_main_source_NEEDED=["libc.so.6"],
        original_libc_cxa_finalize_export=
            "__cxa_finalize@@GLIBC_2.2.5",
        original_libc_cxa_finalize_st_value=hex(provider[0]["va"]),
        original_libc_guest_base=hex(load_bias),
        source_cxa_finalize_rx_file_offset=hex(off),
        weak_GOT_values_at_puts_stop_source_consistent=True,
        original_weak_GLOB_DAT_writer_guest_RIPs_proven=False,
        original_weak_GLOB_DAT_symbol_resolution_execution_proven=False,
        all_original_main_relocations_proven=False,
        original_main_RELRO_sealed=False,
        Android_Bionic_or_phone_executed=False,
        Wine_Proton_or_gameplay_proven=False)
    OUT.write_text(json.dumps(evidence,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_WEAK_GLOB_DAT_FOUR_LIVE_GOT_VALUES_SOURCE_CONSISTENT_PASS")
    print("KERNIX_G0_ORIGINAL_WEAK_GLOB_DAT_NINE_NEGATIVE_CONTROLS_PASS")
    print("KERNIX_G0_WEAK_WRITER_GUEST_RIPS_AND_MAIN_RELRO_STILL_UNPROVEN")

if __name__=="__main__":
    main()
