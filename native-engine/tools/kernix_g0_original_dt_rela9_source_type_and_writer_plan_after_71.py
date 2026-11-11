#!/usr/bin/env python3
"""Original GNU libc DT_RELA index1 exact SHA-pinned next nonIFUNC source only.

Do not assume index9's relocation type, native symbol semantics or TLS
behavior before decoding the original libc ELF. No new native proof here.
"""
from __future__ import annotations
import hashlib,json,struct,sys
from pathlib import Path

from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA,LDSO_SHA,decode_original_libc,classify,
)
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import (
    LIBC_BIAS,GUEST_MAIN,
)

INDEX=9
TYPES={1:"R_X86_64_64",18:"R_X86_64_TPOFF64",6:"R_X86_64_GLOB_DAT"}
NAME="original-libc-DT-RELA9-next-actual-source-type-symbol-hardware-writer-NO-NATIVE-PROOF"

def need(ok:bool,label:str):
    if not ok:raise AssertionError("ORIGINAL GNU DT_RELA9 EXACT SOURCE FAIL CLOSED: "+label)

def original_dynsym(data:bytes,number:int)->dict:
    e_phoff=struct.unpack_from("<Q",data,32)[0]
    e_phentsize,e_phnum=struct.unpack_from("<HH",data,54)
    need(e_phentsize==56 and 1<=e_phnum<=128,"ELF64 original program header count")
    ph=[struct.unpack_from("<IIQQQQQQ",data,e_phoff+i*e_phentsize)
        for i in range(e_phnum)]
    loads=[p for p in ph if p[0]==1]
    dynamic=[p for p in ph if p[0]==2]
    need(len(dynamic)==1 and len(loads)>=3,"original file backed PT_LOAD and DYNAMIC")
    def off(va:int,size:int):
        found=[x for x in loads if x[3]<=va and va+size<=x[3]+x[5]]
        need(len(found)==1,"original ELF unique VA-to-file address")
        idx=found[0][2]+va-found[0][3]
        need(idx+size<=len(data),"source bounds")
        return idx
    tags={}
    d=dynamic[0]
    need(d[2]+d[5]<=len(data) and d[5]%16==0,"actual PT_DYNAMIC table bounds")
    for where in range(d[2],d[2]+d[5],16):
        t,value=struct.unpack_from("<qQ",data,where)
        if t==0:break
        if t in (5,6,10,11):
            need(t not in tags,"unique dynstr dynsym tag")
            tags[t]=value
    need(all(t in tags for t in (5,6,10,11)) and tags[11]==24,
         "original GNU dynsym 24-byte entries")
    st=struct.unpack_from("<IBBHQQ",data,off(tags[6]+number*24,24))
    name_idx,info,other,section,value,size=st
    strings=data[off(tags[5],tags[10]):off(tags[5],tags[10])+tags[10]]
    need(name_idx<len(strings) and b"\0" in strings[name_idx:],
         "bounded original GNU dynamic symbol name")
    name=strings[name_idx:strings.index(b"\0",name_idx)].decode("utf-8")
    local_def=(section!=0)
    source_addr=None
    in_bss=None
    if local_def:
        loads_mem=[x for x in loads if x[3]<=value<x[3]+x[6]]
        if len(loads_mem)==1:
            in_bss=value>=loads_mem[0][3]+loads_mem[0][5]
            # TLS st_value is a module-relative offset, NOT a guest address.
            if info&15!=6:
                source_addr=hex(LIBC_BIAS+value)
    return {
        "symbol_index":number,
        "symbol_name":name,
        "symbol_binding":info>>4,
        "symbol_type":info&15,
        "symbol_visibility":other,
        "symbol_definition_section":section,
        "symbol_original_st_value":hex(value),
        "symbol_original_st_size":size,
        "symbol_defined_in_this_source_elf":local_def,
        "source_definition_address_candidate_if_non_TLS":source_addr,
        "source_definition_in_BSS_if_PT_LOAD_known":in_bss,
        "runtime_symbol_lookup_or_versioned_preemption_proven":False,
        "TLS_runtime_address_or_module_offset_proven":False,
    }

def run(triad:Path,ledger71:Path,repository:Path,out:Path)->dict:
    libcfile=triad/"lib/x86_64-linux-gnu/libc.so.6"
    ldsofile=triad/"lib64/ld-linux-x86-64.so.2"
    need(libcfile.is_file() and ldsofile.is_file()
         and not libcfile.is_symlink() and not ldsofile.is_symlink(),
         "real GNU SHA original libc and ldso files")
    libc,ldso=libcfile.read_bytes(),ldsofile.read_bytes()
    need(len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA,
         "original GNU libc immutable SHA")
    need(len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA,
         "original GNU loader immutable SHA")
    rows=decode_original_libc(libc)
    typ=classify(rows)
    need(typ["original_total_RELA_and_JMPREL"]==147,
         "immutable 147 source relocation rows")
    r=rows[INDEX]
    need(r["index"]==9 and r["table"]=="DT_RELA"
         and r["table_index"]==9 and r["r_type"] in TYPES
         and r["r_sym"]>=0 and r["original_source_qword"]=="0x0",
         "real sixth original non-IFUNC DT_RELA relocation and symbol")
    guest_target=r["source_guest_target"]
    need(guest_target==hex(LIBC_BIAS+int(r["r_offset"],16)),
         "original GNU source target guest address")
    where=source_offset(libc,int(r["r_offset"],16),8,6,nonexec=True)
    need(libc[where:where+8]==bytes(8),
         "original unmodified writable target QWORD zero")
    need(guest_target not in {x["source_guest_target"] for x in rows[:INDEX]},
         "must be distinct from all previous original source relocations")

    need(ledger71.is_file() and not ledger71.is_symlink(),
         "previously certified immutable all-147 original source ledger")
    ledger=json.loads(ledger71.read_text())
    need(ledger["schema"]==
         "kernix.g0.original-gnu-libc-147-relocation-cohort-native-writer-ledger71.v1",
         "exact prior GNU 63 native source proof ledger")
    need(ledger["source_original_libc_sha256"]==LIBC_SHA and
         ledger["source_original_ldso_sha256"]==LDSO_SHA and
         ledger["previously_independently_attested_native_writer_target_count"]==71 and
         ledger["remaining_requires_separate_native_hardware_evidence"]==76 and
         ledger["remaining_non_IFUNC_DT_RELA_indices"]==list(range(9,85)) and
         ledger["remaining_IFUNC_indices"]==[] and
         ledger["native_GNU_DT_RELA0_R64_res_REAL_FEX_ARM64_JIT_source_store_writer_independently_proven"] is True and
         ledger["native_GNU_DT_RELA1_TLS_TPOFF64_sym0_addend56_REAL_FEX_ARM64_STORE_independently_proven"] is True and
         ledger["native_GNU_DT_RELA2_TLS_TPOFF64_sym0_addend48_REAL_FEX_ARM64_STORE_independently_proven"] is True and
         ledger["native_GNU_DT_RELA3_TLS_TPOFF64_sym0_addend88_REAL_FEX_ARM64_STORE_independently_proven"] is True and
         ledger["native_GNU_DT_RELA4_TLS_TPOFF64_sym0_addend72_REAL_FEX_ARM64_STORE_independently_proven"] is True and
         ledger["native_GNU_DT_RELA5_TLS_TPOFF64_sym0_addend80_REAL_FEX_ARM64_STORE_independently_proven"] is True and
         ledger["native_GNU_DT_RELA6_TLS_TPOFF64_sym0_addend100_REAL_FEX_ARM64_STORE_independently_proven"] is True and
         ledger["native_GNU_DT_RELA7_TLS_TPOFF64_sym0_addend120_REAL_FEX_ARM64_STORE_independently_proven"] is True and
         ledger["native_GNU_DT_RELA8_TLS_TPOFF64_sym0_addend128_REAL_FEX_ARM64_STORE_independently_proven"] is True and
         9 not in ledger["previously_attested_original_source_indices"] and
         ledger["all_147_same_guest_native_execution_proven"] is False and
         ledger["Android_Bionic_Wine_Proton_games_proven"] is False,
         "genuine prior 71 and exactly 76 unfinished native writer target source rows")
    prevrow=ledger["original_147_relocation_source_records"][9]
    need(prevrow["source_index"]==9 and
         prevrow["original_source_guest_target"]==guest_target and
         prevrow["original_source_file_old_qword"]=="0x0",
         "previous all-source exact original qword and target independent reconciliation")

    sym=original_dynsym(libc,r["r_sym"])
    host=repository/GUEST_MAIN
    need(host.is_file() and not host.is_symlink(),"real original FEX guest host driver")
    marks=[i for i,line in enumerate(host.read_text().splitlines(),1)
           if line.strip()=="++RealOriginalLdsoLibcCloses;"]
    need(len(marks)==1,"unique source FEX GNU guest mapping pre-RELA closure marker")
    gdb=(
      "set pagination off\nset confirm off\nset breakpoint pending on\n"
      "handle SIGBUS nostop noprint pass\nhandle SIGCHLD nostop noprint pass\n"
      f"break {GUEST_MAIN}:{marks[0]}\n"
      "commands\nsilent\n"
      f'printf "KERNIX_G0_ORIGINAL_RELA9_NEXT_SOURCE_ARM type={TYPES[r["r_type"]]} target={guest_target} initial=0x0 NO_NATIVE_PROOF=1\\n"\n'
      f"x/gx {guest_target}\n"
      f"watch -location *(unsigned long long *){guest_target}\n"
      "condition 2 $pc >= 0xffff00000000 && $x28 >= 0xffff00000000\n"
      "continue\nend\nrun\n"
      f'printf "KERNIX_G0_ORIGINAL_RELA9_NEXT_RAW_HIT target={guest_target} pc=0x%lx x4=0x%lx x13=0x%lx x28=0x%lx RAW_NOT_INDEPENDENT=1\\n",$pc,$x4,$x13,$x28\n'
      f"x/gx {guest_target}\n"
      "x/i $pc-4\n"
      'printf "KERNIX_G0_ORIGINAL_RELA9_NEXT_ZERO_NATIVE_ATTESTATIONS=1\\n"\n'
      "quit\n"
    )
    need(gdb.count(f"watch -location *(unsigned long long *){guest_target}")==1,
         "single original unique source GDB hardware writer-only watch")
    need(gdb.count("KERNIX_G0_ORIGINAL_RELA9_NEXT_SOURCE_ARM")==1
         and gdb.count("KERNIX_G0_ORIGINAL_RELA9_NEXT_RAW_HIT")==1
         and gdb.count("KERNIX_G0_ORIGINAL_RELA9_NEXT_ZERO_NATIVE_ATTESTATIONS")==1
         and "KERNIX_G0_ORIGINAL_RELA1_" not in gdb,
         "GDB marker index MUST exactly match SHA-locked source DT_RELA9")
    result={
        "schema":"kernix.g0.original-gnu-dt-rela-index9-type-discovery-source-only.v1",
        "original_source_libc_sha256":LIBC_SHA,
        "original_source_ldso_sha256":LDSO_SHA,
        "original_source_index":9,
        "original_table":"DT_RELA",
        "original_table_ordinal":9,
        "original_relocation_type_id":r["r_type"],
        "original_relocation_type":TYPES[r["r_type"]],
        "original_symbol":sym,
        "original_source_signed_addend":r["r_addend"],
        "original_source_relocation_offset":r["r_offset"],
        "original_guest_target":guest_target,
        "original_source_initial_qword":"0x0",
        "original_71_native_source_writers_independently_attested":71,
        "new_native_writer_target_evidence_from_this_source_discovery":0,
        "source_only_no_native_writer_proven":True,
        "original_symbol_dynamic_binding_proven":False,
        "all_147_original_guest_relocations_completed_together":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/(NAME+".json")).write_text(json.dumps(result,indent=2)+"\n")
    (out/(NAME+".gdb")).write_text(gdb)
    print("KERNIX_G0_ORIGINAL_GNU_DT_RELA9_SHA_SOURCE_PLAN_HOLD_71_147",
          json.dumps({"type":result["original_relocation_type"],
                      "symbol":sym,"guest_target":guest_target,"signed_addend":r["r_addend"],"source_target_offset":r["r_offset"]},sort_keys=True))
    return result

if __name__=="__main__":
    need(len(sys.argv)==5,"usage original-gnu-triad original-68-ledger repo-root dist")
    run(*map(Path,sys.argv[1:]))
