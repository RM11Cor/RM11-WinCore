#!/usr/bin/env python3
"""Source-verify weak __cxa_finalize GOT snapshot at the real puts write.

This is NOT proof of the original GNU loader writer RIP or any GOT write
to the weak slot; it is an independent frozen ELF + live snapshot
symbol/version/address agreement for one source undefined weak import.
"""
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path

DIST=Path("dist")
ORIG=DIST/"original-source-pinned-root"
MAIN=ORIG/"bin/kernix-g2e-dynamic-guest"
LIBC=ORIG/"lib/x86_64-linux-gnu/libc.so.6"
SNAP=DIST/"original-four-weak-got-after-puts-hw-stop.json"
OUT=DIST/"original-weak-cxa-finalize-source-symbol-snapshot-evidence.json"
MAIN_SHA="9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412"
LIBC_SHA="7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906"

def guard(value,why):
    if not value:raise AssertionError(why)

def find_libc_rx(data,vma,n):
    guard(data[:6]==bytes.fromhex("7f454c460201")
          and struct.unpack_from("<H",data,18)[0]==62,"original libc is not ELF64/x86-64")
    phoff=struct.unpack_from("<Q",data,32)[0]
    entsz,num=struct.unpack_from("<HH",data,54)
    guard(entsz==56 and 0<num<=64 and phoff+num*entsz<=len(data),
          "invalid original libc program header")
    hits=[]
    for i in range(num):
        typ,flags,off,va,_,filesz,memsz,_=struct.unpack_from(
           "<IIQQQQQQ",data,phoff+i*entsz)
        if (typ==1 and flags&5==5 and flags&2==0
            and vma>=va and vma-va+n<=filesz
            and off<=len(data) and filesz<=len(data)-off):
            hits.append(off+vma-va)
    guard(len(hits)==1,"__cxa_finalize not in unique pinned original libc RX PT_LOAD")
    piece=data[hits[0]:hits[0]+n]
    guard(piece!=bytes(n),"original libc __cxa_finalize source code unexpectedly zero")
    return hits[0],piece

def accepted(expected,observed,imported,exported,source_rx):
    return (expected==observed==0x472a0
            and imported=="__cxa_finalize@GLIBC_2.2.5"
            and exported=="__cxa_finalize@@GLIBC_2.2.5"
            and bool(source_rx))

def run():
    mb=MAIN.read_bytes()
    cb=LIBC.read_bytes()
    guard(len(mb)==15976 and hashlib.sha256(mb).hexdigest()==MAIN_SHA,
          "original source main size or SHA mismatch")
    guard(len(cb)==2118168 and hashlib.sha256(cb).hexdigest()==LIBC_SHA,
          "original source libc size or SHA mismatch")
    source=json.loads(SNAP.read_text())
    guard(source["schema"]=="kernix.g0.original-four-weak-got-at-puts-hardware-stop.v1"
          and source["original_main_sha256"]==MAIN_SHA
          and source["weak_GOT_values_read_at_hardware_stop"] is True
          and source["original_puts_exact_guest_writer_RIP_proven"] is True
          and source["weak_GLOB_DAT_actual_guest_writers_proven"] is False,
          "read-only weak source snapshot unverified or incorrectly upgraded")
    weak=source["weak_source_GOT_snapshot"]
    guard(len(weak)==4,"four source undefined weak GOT cells required")
    names=["_ITM_deregisterTMCloneTable","__gmon_start__",
           "_ITM_registerTMCloneTable","__cxa_finalize"]
    expected=[0,0,0,0x8040472a0]
    guest_targets=["0x800003fe0","0x800003fe8","0x800003ff0","0x800003ff8"]
    for row,name,value,target in zip(weak,names,expected,guest_targets):
        guard(row["symbol"]==name and row["guest_target"]==target
              and int(row["observed_guest_GOT_value"],16)==value
              and row["binding"]==2 and row["defined_section"]==0
              and row["source_initial"]==0,
              "original weak live GOT snapshot changed")
    rels=subprocess.run(["readelf","-W","-r",str(MAIN)],text=True,
         capture_output=True,check=True,timeout=12).stdout
    rr=[s for s in rels.splitlines() if "R_X86_64_GLOB_DAT" in s
        and "__cxa_finalize@" in s]
    guard(len(rr)==1 and int(rr[0].split()[0],16)==0x3ff8
          and "__cxa_finalize@GLIBC_2.2.5" in rr[0],
          "original main weak source relocation/version mismatch")
    syms=subprocess.run(["readelf","-W","--dyn-syms",str(LIBC)],
         text=True,capture_output=True,check=True,timeout=12).stdout
    pattern=(r"(?m)^\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+"
             r"FUNC\s+GLOBAL\s+DEFAULT\s+(\S+)\s+"
             r"__cxa_finalize@@GLIBC_2\.2\.5\s*$")
    match=list(re.finditer(pattern,syms))
    guard(len(match)==1,"missing unique original versioned __cxa_finalize export")
    vma=int(match[0].group(1),16)
    size=int(match[0].group(2),10)
    guard(match[0].group(3)!="UND" and size>=12,
          "original libc __cxa_finalize not a defined function")
    file_offset,code=find_libc_rx(cb,vma,12)
    got_value=int(weak[3]["observed_guest_GOT_value"],16)
    # Source-pinned original guest base is independently attested by
    # existing G0 libc mmap9 event before this authentic puts HW stop.
    log=(DIST/"original-main-puts-jumpslot-watch.log").read_text(errors="replace")
    m=re.search(r"KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_LIBC_MMAP9_LARGE_PRIVATE_RO_SOURCE_"
                r"\d+_REQUEST_0x[0-9a-f]+_FD100_OFFSET0_WX_SAFE_EOF_GUARD_PASS "
                r"guest_base=([0-9a-fA-F]+)",log)
    guard(m is not None and int(m.group(1),16)==0x804000000,
          "original guest libc mapping base not witnessed")
    observed=got_value-0x804000000
    guard(accepted(vma,observed,"__cxa_finalize@GLIBC_2.2.5",
                   "__cxa_finalize@@GLIBC_2.2.5",[file_offset]),
          "weak __cxa_finalize GOT snapshot disagrees with original versioned libc")
    mutants=[
      (vma+1,observed,"__cxa_finalize@GLIBC_2.2.5",
       "__cxa_finalize@@GLIBC_2.2.5",[file_offset]),
      (vma,observed+8,"__cxa_finalize@GLIBC_2.2.5",
       "__cxa_finalize@@GLIBC_2.2.5",[file_offset]),
      (vma,observed,"__cxa_finalize@GLIBC_2.34",
       "__cxa_finalize@@GLIBC_2.2.5",[file_offset]),
      (vma,observed,"__cxa_finalize@GLIBC_2.2.5",
       "__cxa_finalize@@GLIBC_2.34",[file_offset]),
      (vma,observed,"__cxa_finalize@GLIBC_2.2.5",
       "__cxa_finalize@@GLIBC_2.2.5",[])]
    guard(all(not accepted(*mut) for mut in mutants),
          "corrupted source libc/weak snapshot evidence accepted")
    report=dict(source)
    report.update(
      schema="kernix.g0.weak-cxa-finalize-source-correct-snapshot.v1",
      original_libc_sha256=LIBC_SHA,
      source_imported_symbol="__cxa_finalize@GLIBC_2.2.5",
      libc_versioned_export="__cxa_finalize@@GLIBC_2.2.5",
      libc_export_st_value=hex(vma),
      libc_export_RX_file_offset=hex(file_offset),
      libc_source_code_12bytes=code.hex(),
      weak_cxa_finalize_GOT_snapshot_value=hex(got_value),
      weak_cxa_finalize_source_symbol_pointer_matches=True,
      weak_cxa_finalize_actual_guest_writer_RIP_proven=False,
      all_original_main_relocations_proven=False,
      original_main_RELRO_sealed=False,
      android_bionic_or_gameplay_proven=False)
    OUT.write_text(json.dumps(report,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_WEAK_CXA_FINALIZE_GOT_SNAPSHOT_SHA256_VERSIONED_LIBC_SOURCE_MATCH_PASS")
    print("KERNIX_G0_WEAK_CXA_FINALIZE_SOURCE_FIVE_MUTATION_NEGATIVES_PASS")
    print("KERNIX_G0_CXA_FINALIZE_GUEST_WRITER_RIP_AND_FULL_RELRO_NOT_PROVEN")

if __name__=="__main__":
    run()
