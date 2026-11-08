#!/usr/bin/env python3
"""Source-authentic GNU main 8-slot PT_GNU_RELRO inventory and native x86 snapshot gate.

This witness is only for original Linux x86-64 execution before authentic
mprotect(10). It neither executes FEX nor authorizes guest mprotect or RELRO
sealing in the ARM64 diagnostic harness or on Android.
"""
from __future__ import annotations
import copy
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

MAIN_SHA="9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412"
LIBC_SHA="7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906"
LDSO_SHA="cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"
SOURCE_SCHEMA="kernix.g0.source-original-main-8-relro-targets.v1"
NATIVE_SCHEMA="kernix.g0.native-x86-original-main-eight-relro-targets-before-real-mprotect.v1"
MAIN_PAGE=0x3000
MAIN_BASE_FEX=0x800000000
EXPECTED_MAIN_SYMBOLS={
    "puts":(7,1,0x3fd0),
    "__libc_start_main":(6,1,0x3fd8),
    "_ITM_deregisterTMCloneTable":(6,2,0x3fe0),
    "__gmon_start__":(6,2,0x3fe8),
    "_ITM_registerTMCloneTable":(6,2,0x3ff0),
    "__cxa_finalize":(6,2,0x3ff8),
}
# Source SHA-locked libc exports, independently observed as source ELF VAs
# in earlier FEX read-only source-libc-symbol witness. These values are not
# evidence of the x86/GNU original symbol lookup algorithm itself.
SOURCE_LIBC_EXPORT_VA={"puts":0x87bc0, "__libc_start_main":0x2a200, "__cxa_finalize":0x472a0}
WEAK_ZERO={"_ITM_deregisterTMCloneTable","__gmon_start__","_ITM_registerTMCloneTable"}

class GateError(ValueError):
    pass

def check(ok, reason):
    if not ok:raise GateError(reason)

def unpack(fmt, data, offset):
    check(offset>=0 and offset+struct.calcsize(fmt)<=len(data),"ELF source out-of-bounds")
    return struct.unpack_from(fmt,data,offset)

def parse_main(source):
    check(len(source)==15976 and hashlib.sha256(source).hexdigest()==MAIN_SHA,"wrong original main source hash")
    check(source[:6]==b"\x7fELF\x02\x01" and unpack("<H",source,18)[0]==62,"not pinned ELF64 LE x86_64")
    phoff=unpack("<Q",source,32)[0]
    phentsize,n=unpack("<HH",source,54)
    check(phentsize==56 and 1<=n<=32 and phoff+n*56<=len(source),"original ELF phdr corrupted")
    ph=[unpack("<IIQQQQQQ",source,phoff+56*i) for i in range(n)]
    def file(va,size):
        owners=[p for p in ph if p[0]==1 and p[3]<=va and size<=p[5]
                and va-p[3]<=p[5]-size and p[2]+p[5]<=len(source)]
        check(len(owners)==1,"not uniquely original file-backed PT_LOAD "+hex(va))
        return owners[0][2]+va-owners[0][3]
    relro=[p for p in ph if p[0]==0x6474e552]
    check(len(relro)==1 and relro[0][5]>0,"original main RELRO missing")
    start=relro[0][3] & ~4095
    end=(relro[0][3]+relro[0][6]) & ~4095
    check(start==MAIN_PAGE and end==MAIN_PAGE+4096,"original main GNU_RELRO full-page range changed")
    # ELF's PT_LOAD p_vaddr may begin *inside* the 4K file-backed page.
    # Kernel mappings are rounded down at the start and up at the end.
    # Require that exactly one original writable (nonexecuting) PT_LOAD
    # owns this ENTIRE aligned RELRO page, not that p_vaddr==page_start.
    owner=[p for p in ph if p[0]==1 and p[1]==6 and (p[3]&~4095)<=start
           and start+4096<=((p[3]+p[6]+4095)&~4095)
           and p[6]>=p[5] and p[6]>0]
    check(len(owner)==1,"main RELRO page not inside original RW PT_LOAD memory range")
    dyn=[p for p in ph if p[0]==2]
    check(len(dyn)==1 and dyn[0][5]%16==0 and dyn[0][2]+dyn[0][5]<=len(source),"original PT_DYNAMIC invalid")
    tags={}
    for i in range(dyn[0][5]//16):
        tag,value=unpack("<qQ",source,dyn[0][2]+i*16)
        if tag==0:break
        if tag in (7,8,9,2,20,23,5,6,10,11):check(tag not in tags,"duplicate source dynamic tag")
        tags[tag]=value
    check(all(k in tags for k in (7,8,9,2,20,23,5,6,10,11)),"source dynamic relocation/symbol table incomplete")
    check(tags[8]==8*24 and tags[2]==24 and tags[9]==24 and tags[20]==7 and tags[11]==24,
          "original DT_RELA or DT_JMPREL shape changed")
    check(0<tags[10]<=4096,"invalid source string table")
    sym_off=lambda i:file(tags[6]+i*24,24)
    str_off=file(tags[5],tags[10])
    def sym_name(i):
        start=unpack("<I",source,sym_off(i))[0]
        check(start<tags[10],"ELF symbol name OOB")
        end=source.find(b"\x00",str_off+start,str_off+tags[10])
        check(end>=str_off+start,"source symbol name not terminated")
        return source[str_off+start:end].decode("ascii")
    entries=[]
    for table,va,size in (("DT_RELA",tags[7],tags[8]),("DT_JMPREL",tags[23],tags[2])):
        pos=file(va,size)
        for idx in range(size//24):
            offset,info,addend=unpack("<QQq",source,pos+idx*24)
            typ=info&0xffffffff
            symbol=info>>32
            if offset<MAIN_PAGE or offset+8>MAIN_PAGE+4096:continue
            check(offset%8==0,"RELRO relocation target unaligned")
            check(typ in (6,7,8),"unexpected in-RELRO relocation type")
            name=sym_name(symbol) if symbol else ""
            check((typ==8 and symbol==0 and table=="DT_RELA")
                  or (typ==6 and table=="DT_RELA" and name in EXPECTED_MAIN_SYMBOLS)
                  or (typ==7 and table=="DT_JMPREL" and name=="puts"),"unexpected source main RELRO relocation")
            entries.append({"source_target":hex(offset),"target_offset":offset,
                            "source_table":table,"type":typ,"symbol_index":symbol,
                            "source_symbol":name,"source_addend":addend})
    check(len(entries)==8 and len({x["target_offset"] for x in entries})==8,"exact main RELRO eight targets missing")
    check(sum(x["type"]==8 for x in entries)==2,"not exactly two RELATIVE main slots")
    check(sum(x["type"]==6 for x in entries)==5,"not exactly five GLOB_DAT main slots")
    check(sum(x["type"]==7 for x in entries)==1,"not exactly one PLT JUMP_SLOT")
    named=[e for e in entries if e["type"]!=8]
    check({e["source_symbol"] for e in named}==set(EXPECTED_MAIN_SYMBOLS),"unexpected exact main symbols")
    for e in named:
        t,binding,target=EXPECTED_MAIN_SYMBOLS[e["source_symbol"]]
        check((e["type"],e["target_offset"])==(t,target),"wrong symbol type or target offset")
        name_off=sym_off(e["symbol_index"])
        info=source[name_off+4]
        check(info>>4==binding,"original strong/weak dynamic ELF binding changed")
    return {"schema":SOURCE_SCHEMA,"main_sha256":MAIN_SHA,
            "source_guest_main_relro_page":hex(MAIN_PAGE),
            "source_guest_main_relro_bytes":4096,
            "source_main_rela_count":8,"source_main_plt_rela_count":1,
            "source_relro_dynamic_target_count":8,
            "dynamic_source_targets":sorted(entries,key=lambda e:e["target_offset"]),
            "source_has_2_relative_5_globdat_1_jumpslot":True,
            "source_guest_relro_owner_RW_PTLOAD":True,
            "native_real_mprotect_applied":False,
            "FEX_original_guest_relocations_closed":False,
            "FEX_main_PT_GNU_RELRO_sealed":False,
            "Android_or_Wine_games_proven":False}

def classify(source, receipt):
    check(isinstance(receipt,dict) and receipt.get("schema")==NATIVE_SCHEMA,"not authentic native x86 main RELRO capture")
    check(receipt.get("source_main_sha256")==MAIN_SHA and receipt.get("source_libc_sha256")==LIBC_SHA
          and receipt.get("source_ldso_sha256")==LDSO_SHA,"original x86 source trio not locked")
    check(receipt.get("original_native_mprotect10_trap_hit") is True,"native main mprotect syscall entry not trapped")
    check(receipt.get("native_mprotect_linux_syscall_number")==10
          and receipt.get("native_mprotect_prot")=="0x1"
          and receipt.get("native_mprotect_size")=="0x1000","wrong original main PROT_READ mprotect syscall")
    check(receipt.get("native_rax_at_linux_mprotect_entry")=="0xffffffffffffffda",
          "not actual Linux x86 mprotect syscall entry")
    check(receipt.get("main_relro_writable_at_native_mprotect_entry") is True,
          "original main page was not writable at entry")
    check(receipt.get("native_main_exited_cleanly") is True and receipt.get("native_exit_code")==0
          and receipt.get("gdb_error") is None,"original native test did not execute cleanly")
    check(receipt.get("source_inventory_sha256")==hashlib.sha256(
          json.dumps(source,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
          "native collector source inventory did not match")
    check(receipt.get("native_main_guest_base") and receipt.get("native_libc_guest_base"),"missing genuine native PIE load biases")
    main_base=int(receipt["native_main_guest_base"],16)
    libc_base=int(receipt["native_libc_guest_base"],16)
    check(main_base%4096==0 and libc_base%4096==0
          and receipt.get("native_original_main_relro_mprotect_address")==hex(main_base+MAIN_PAGE),
          "native main mprotect page not source owned")
    values=receipt.get("original_main_relro_slot_values_at_native_mprotect_entry")
    check(isinstance(values,list) and len(values)==8,"native pre-mprotect source slots incomplete")
    by_source={e["target_offset"]:e for e in source["dynamic_source_targets"]}
    check({row.get("source_target_offset") for row in values}=={hex(o) for o in by_source},
          "native source main slots omitted or fabricated")
    evidence=[]
    for row in values:
        target=int(row["source_target_offset"],16)
        meta=by_source[target]
        check(row["source_relocation_type"]==meta["type"]
              and row["source_symbol"]==meta["source_symbol"],"wrong source relocation type or symbol")
        check(row["native_slot_address"]==hex(main_base+target),"native slot address mismatched source")
        actual=int(row["native_slot_value"],16)
        if meta["type"]==8:
            expected=(main_base+meta["source_addend"])&((1<<64)-1)
            status="relative_expected_from_original_addend"
        elif meta["source_symbol"] in WEAK_ZERO:
            expected=0
            status="unresolved_original_weak_zero_native_reference"
        else:
            expected=libc_base+SOURCE_LIBC_EXPORT_VA[meta["source_symbol"]]
            status="original_libc_source_export_expected_address_native_reference"
        check(actual==expected,("native x86 pre-main-relro value differs from original source attested expected",
                               meta["source_symbol"],hex(actual),hex(expected)))
        evidence.append({"source_target_offset":hex(target),"type":meta["type"],
                         "source_symbol":meta["source_symbol"],"native_value_matches_expected":True,
                         "expected_source_class":status})
    return {"schema":"kernix.g0.original-main-relro-8-of-8-native-x86-source-preseal-reference.v1",
            "main_original_ELF_sha256":MAIN_SHA,"native_x86_original_mprotect_page_rights_before":"rw-p",
            "source_DT_RELA_records":8,"source_DT_JMPREL_records":1,
            "source_PT_GNU_RELRO_inpage_relocation_targets":8,
            "original_native_x86_preseal_values_match_source_expected":8,
            "source_signed_addend_relative_targets":2,"source_globdat_symbols":5,
            "source_plt_jump_slot_symbols":1,"source_per_target_evidence":evidence,
            "original_native_linux_mprotect_success_applied_only_after_capture":True,
            "original_FEX_ARM64_main_all_relocation_writes_executed_proven":False,
            "original_FEX_ARM64_main_RELRO_sealed":False,
            "Android_Bionic_Wine_or_PC_gameplay_proven":False,
            "FEX_guest_mprotect10_implementation_or_fake_success_authorized":False}

def negatives(source,receipt):
    cases=[
        ("different source main digest",lambda x:x.update(source_main_sha256="0"*64)),
        ("fake native main RELRO seal",lambda x:x.update(main_relro_writable_at_native_mprotect_entry=False)),
        ("fake mprotect syscall result",lambda x:x.update(native_rax_at_linux_mprotect_entry="0x0")),
        ("wrong original protection",lambda x:x.update(native_mprotect_prot="0x7")),
        ("missing one original target",lambda x:x["original_main_relro_slot_values_at_native_mprotect_entry"].pop()),
        ("swap a source relative slot",lambda x:x["original_main_relro_slot_values_at_native_mprotect_entry"][0].update(native_slot_value="0x0")),
        ("fake zero weak slot",lambda x:x["original_main_relro_slot_values_at_native_mprotect_entry"][5].update(native_slot_value="0xdeadbeef")),
        ("false original native exit",lambda x:x.update(native_exit_code=117)),
        ("source ownership forged",lambda x:x.update(native_original_main_relro_mprotect_address="0x800000000")),
        ("tampered source inventory",lambda x:x.update(source_inventory_sha256="0"*64)),
        ("symbol source ownership forged",lambda x:x["original_main_relro_slot_values_at_native_mprotect_entry"][0].update(source_symbol="puts")),
        ("wrong libc load bias",lambda x:x.update(native_libc_guest_base="0x800000000")),
    ]
    for i,(description,edit) in enumerate(cases,1):
        modified=copy.deepcopy(receipt)
        edit(modified)
        try:
            classify(source,modified)
        except (GateError,ValueError,KeyError,TypeError):
            print("KERNIX_G0_ORIGINAL_MAIN_RELRO_EIGHT_NATIVE_FALSE_PROOF_%02d_REJECTED %s"%(i,description))
        else:
            raise GateError("false original RELRO proof accepted: "+description)
    return len(cases)

def main(args):
    if len(args)!=4 or args[1] not in ("validate","selftest"):
        print("Usage: gate.py validate|selftest ORIGINAL_MAIN_ELF NATIVE_RECEIPT_JSON",file=sys.stderr)
        return 2
    source=parse_main(Path(args[2]).read_bytes())
    receipt=json.loads(Path(args[3]).read_text())
    result=classify(source,receipt)
    print(json.dumps(result,sort_keys=True,indent=2))
    if args[1]=="selftest":check(negatives(source,receipt)==12,"negative control count changed")
    print("KERNIX_G0_PINNED_MAIN_RELRO_8_SOURCE_SLOTS_MATCH_NATIVE_X86_PRESEAL_VALUES_FEX_EXECUTION_AND_SEAL_REMAIN_OPEN")
    return 0

if __name__=="__main__":
    try:
        raise SystemExit(main(sys.argv))
    except (GateError,ValueError,KeyError,TypeError,struct.error) as e:
        print("KERNIX_G0_MAIN_RELRO_8_TARGET_PRESEAL_FAIL_CLOSED: "+str(e),file=sys.stderr)
        raise SystemExit(1)
