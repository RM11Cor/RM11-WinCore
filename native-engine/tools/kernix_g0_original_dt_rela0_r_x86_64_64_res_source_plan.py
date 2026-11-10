#!/usr/bin/env python3
"""Original GNU libc DT_RELA #0 R_X86_64_64 _res source-only native watch.

Unlike IFUNC IRELATIVE, type R_X86_64_64 is a symbol lookup + addend.
A source-defined symbol value is only a candidate: preemption, version
selection, or TLS/runtime semantics are not certified from source inspection.
"""
from __future__ import annotations

import hashlib,json,struct,sys
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA,LDSO_SHA,decode_original_libc,classify,
)
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import GUEST_MAIN,LIBC_BIAS

INDEX=0
PREFIX="original-libc-DT-RELA0-R_X86_64_64-_res-source-only-NO-NATIVE-WRITER-PROOF"


def require(ok:bool,label:str)->None:
    if not ok:raise AssertionError("FAIL-CLOSED original GNU DT_RELA0 _res source: "+label)


def run(triad:Path,ledger62:Path,repository:Path,out:Path)->dict:
    libp=triad/"lib/x86_64-linux-gnu/libc.so.6"
    ldp=triad/"lib64/ld-linux-x86-64.so.2"
    require(libp.is_file() and ldp.is_file() and not libp.is_symlink() and not ldp.is_symlink(),
            "original immutable GNU source files")
    libc,ldso=libp.read_bytes(),ldp.read_bytes()
    require(len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA,
            "original GNU x86 libc SHA/size")
    require(len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA,
            "original GNU x86 ldso SHA/size")
    rows=decode_original_libc(libc)
    classification=classify(rows)
    require(classification["original_total_RELA_and_JMPREL"]==147 and
            classification["original_DT_RELA_type_counts"]==
            {"R_X86_64_64":8,"R_X86_64_TPOFF64":16,
             "R_X86_64_GLOB_DAT":61,"R_X86_64_IRELATIVE":1},
            "complete immutable GNU libc 147 source type counts")
    r=rows[INDEX]
    require((r["index"],r["table"],r["table_index"],r["r_type"],
             r["r_sym"],r["r_offset"],r["r_addend"],r["original_source_qword"])==
            (0,"DT_RELA",0,1,2726,"0x1ffc68",0,"0x0"),
            "exact original GNU R_X86_64_64 first relocation symbol and initial value")
    target=r["source_guest_target"]
    require(target=="0x8041ffc68" and
            int.from_bytes(libc[source_offset(libc,0x1ffc68,8,6,nonexec=True):
                                source_offset(libc,0x1ffc68,8,6,nonexec=True)+8],"little")==0,
            "true original writable nonexecuting ELF target qword zero")

    require(ledger62.is_file() and not ledger62.is_symlink(),
            "prior original GNU independent 62/147 source ledger")
    previous=json.loads(ledger62.read_text())
    require(previous["source_original_libc_sha256"]==LIBC_SHA and
            previous["source_original_ldso_sha256"]==LDSO_SHA and
            previous["original_relocations_total"]==147 and
            previous["previously_independently_attested_native_writer_target_count"]==62 and
            previous["remaining_requires_separate_native_hardware_evidence"]==85 and
            previous["remaining_IFUNC_indices"]==[] and
            0 in previous["remaining_non_IFUNC_DT_RELA_indices"] and
            0 not in previous["previously_attested_original_source_indices"] and
            previous["native_IFUNC85_DT_RELA_real_zero_to_zero_FEX_JIT_hardware_STORE_independently_proven"] is True and
            previous["all_147_same_guest_native_execution_proven"] is False and
            previous["Android_Bionic_Wine_Proton_games_proven"] is False,
            "immutable independently approved 62/147 prior proof, index0 still pending")
    row0=previous["original_147_relocation_source_records"][0]
    require(row0["source_index"]==0 and
            row0["source_relocation_type"]=="R_X86_64_64" and
            row0["original_source_guest_target"]==target and
            row0["original_source_file_old_qword"]=="0x0",
            "prior original ledger exact target match")

    phoff=struct.unpack_from("<Q",libc,32)[0]
    phsize,phcount=struct.unpack_from("<HH",libc,54)
    require(phsize==56 and phcount>0,"exact ELF64 PT_LOAD header layout")
    loads=[]
    dynamic=[]
    for i in range(phcount):
        x=struct.unpack_from("<IIQQQQQQ",libc,phoff+i*phsize)
        if x[0]==1:loads.append(x)
        if x[0]==2:dynamic.append(x)
    require(len(dynamic)==1 and len(loads)>=3,"original GNU libc PT_LOAD and DYNAMIC")
    def offset(va:int,size:int)->int:
        matches=[p for p in loads if p[3]<=va and va+size<=p[3]+p[5]]
        require(len(matches)==1,"unique ELF file-backed symbol/strtab VA")
        return matches[0][2]+va-matches[0][3]
    dyn=dynamic[0]
    tags={}
    for n in range(dyn[2],dyn[2]+dyn[5],16):
        kind,value=struct.unpack_from("<qQ",libc,n)
        if kind==0:break
        if kind in (5,6,10,11,7,8,9):
            require(kind not in tags,"unique relevant dynamic ELF tag")
            tags[kind]=value
    require(all(n in tags for n in (5,6,10,11,7,8,9)) and tags[11]==24,
            "original GNU ELF symtab and string table")
    off=offset(tags[6]+r["r_sym"]*tags[11],24)
    st_name,st_info,st_other,st_shndx,st_value,st_size=struct.unpack_from("<IBBHQQ",libc,off)
    names=libc[offset(tags[5],tags[10]):offset(tags[5],tags[10])+tags[10]]
    require(st_name<len(names) and b"\0" in names[st_name:],"bounded GNU symbol name")
    symbol=names[st_name:names.index(b"\0",st_name)].decode("ascii")
    require((symbol,st_info>>4,st_info&15,st_shndx,st_value)==
            ("_res",1,1,31,0x20b680),"exact source-defined global OBJECT _res")
    definition=[p for p in loads if p[3]<=st_value< p[3]+p[6]]
    require(len(definition)==1 and (definition[0][1]&2)==2,
            "symbol definition in writable guest PT_LOAD memory")
    in_bss=st_value>=definition[0][3]+definition[0][5]
    require(in_bss,"source-defined _res lies in BSS, not file-backed value")
    source_candidate=LIBC_BIAS+st_value
    require(source_candidate==0x80420b680,"source symbol candidate exact mapped address")

    host=repository/GUEST_MAIN
    require(host.is_file() and not host.is_symlink(),"original upstream FEX native main source")
    lines=host.read_text().splitlines()
    marks=[i for i,line in enumerate(lines,1) if line.strip()=="++RealOriginalLdsoLibcCloses;"]
    require(len(marks)==1,"unique original libc PT_LOAD close3 host boundary")
    gdb=(
        "set pagination off\nset confirm off\nset breakpoint pending on\n"
        "handle SIGBUS nostop noprint pass\nhandle SIGCHLD nostop noprint pass\n"
        f"break {GUEST_MAIN}:{marks[0]}\n"
        "commands\nsilent\n"
        f'printf "KERNIX_G0_RELA0_RES_SOURCE_ONLY_WATCH_ARM target={target} initial=0x0 candidate={hex(source_candidate)} NO_NATIVE_PROOF=1\\n"\n'
        f"x/gx {target}\n"
        f"watch -location *(unsigned long long *){target}\n"
        "condition 2 $pc >= 0xffff00000000 && $x28 >= 0xffff00000000\n"
        "continue\nend\nrun\n"
        f'printf "KERNIX_G0_RELA0_RES_NATIVE_RAW_WATCH target={target} pc=0x%lx x4=0x%lx x19=0x%lx x28=0x%lx RAW_NOT_INDEPENDENT=1\\n",$pc,$x4,$x19,$x28\n'
        f"x/gx {target}\n"
        "x/i $pc-4\n"
        'printf "KERNIX_G0_RELA0_RES_SOURCE_ONLY_NO_NATIVE_ATTESTATION=1\\n"\n'
        "quit\n"
    )
    require(gdb.count("watch -location *(unsigned long long *)"+target)==1 and
            "awatch -location" not in gdb and "rwatch -location" not in gdb,
            "one exact source target writer-only candidate watch")
    result={
       "schema":"kernix.g0.original-gnu-libc-dt-rela0-R_X86_64_64-res-source-only.v1",
       "original_source_libc_sha256":LIBC_SHA,
       "original_source_ldso_sha256":LDSO_SHA,
       "original_relocation_index":0,
       "original_table":"DT_RELA",
       "original_table_ordinal":0,
       "relocation_type":"R_X86_64_64",
       "original_symbol_index":2726,
       "original_symbol_name":symbol,
       "original_symbol_binding":"STB_GLOBAL",
       "original_symbol_type":"STT_OBJECT",
       "original_symbol_definition_section":st_shndx,
       "original_symbol_source_value":hex(st_value),
       "original_symbol_source_in_bss":in_bss,
       "original_symbol_file_backed_definition":False,
       "symbol_local_definition_candidate_guest_address":hex(source_candidate),
       "symbol_preemption_or_versioned_runtime_lookup_proven":False,
       "relocation_source_addend":r["r_addend"],
       "original_guest_target":target,
       "original_source_target_qword":"0x0",
       "previous_native_writer_targets_independently_certified":62,
       "new_native_writer_targets_in_this_source_only_stage":0,
       "source_only_not_native_FEX_writer_proof":True,
       "full_GNU_loader_same_process_relocation_closure_proven":False,
       "Android_Bionic_Wine_Proton_games_proven":False,
       "native_next_gate":"verify genuine symbol lookup/interposition, actual GNU source x86 STORE and AArch64 native write at target with independent anti-fabrication proof",
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/(PREFIX+".json")).write_text(json.dumps(result,indent=2)+"\n")
    (out/(PREFIX+".gdb")).write_text(gdb)
    print("KERNIX_G0_ORIGINAL_DT_RELA0_RES_DEFINED_BSS_SYMBOL_R_X86_64_64_SOURCE_ONLY_KEEP_NATIVE_LEDGER62_147")
    return result


if __name__=="__main__":
    require(len(sys.argv)==5,"usage original-gnu-triad prior-62-ledger repository-root output-dir")
    run(*map(Path,sys.argv[1:]))
