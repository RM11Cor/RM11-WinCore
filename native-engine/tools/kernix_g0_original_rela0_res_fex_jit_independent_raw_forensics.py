#!/usr/bin/env python3
"""Independent original GNU x86 libc RELA #0 _res ARM64 STLR/JIT RAW forensics.

This classifies a source-to-native candidate but NEVER independently attests
R_X86_64_64 symbol lookup or a new writer target. Only a later stronger,
separately reviewed gate with 147-row reconciliation can promote 62 -> 63.
"""
from __future__ import annotations
import hashlib,json,re,sys
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA,LDSO_SHA,decode_original_libc,classify,
)
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset

PREFIX="original-libc-DT-RELA0-R_X86_64_64-_res"
SRC=PREFIX+"-source-only-NO-NATIVE-WRITER-PROOF"
RAW=PREFIX+"-REAL-ARM64-FEX-RAW-NATIVE-WRITER"
JIT=PREFIX+"-REAL-ARM64-FEX-JIT-RAW-NATIVE-WRITER"
TARGET="0x8041ffc68"
CANDIDATE="0x80420b680"
BASE=0x804000000
LDSO_BASE=0x801000000

def need(ok:bool, what:str):
    if not ok:raise AssertionError("GNU REAL ORIGINAL RELA0 _res RAW forensic FAIL CLOSED: "+what)

def regular(p:Path)->bytes:
    need(p.is_file() and not p.is_symlink(),"regular original file "+str(p))
    return p.read_bytes()

def jload(p:Path)->dict:
    obj=json.loads(regular(p))
    need(isinstance(obj,dict),"expected JSON object "+str(p))
    return obj

def exactly(expr:str,s:str,label:str)->re.Match:
    found=list(re.finditer(expr,s,re.M))
    need(len(found)==1,label+" exactly one original event")
    return found[0]

def immutable_source(root:Path,src:Path,prior:Path)->tuple[str,str,bytes,bytes]:
    libc=regular(root/"lib/x86_64-linux-gnu/libc.so.6")
    ldso=regular(root/"lib64/ld-linux-x86-64.so.2")
    need(len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA,
         "original libc pinned immutable SHA")
    need(len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA,
         "original ldso pinned immutable SHA")
    rows=decode_original_libc(libc)
    need(classify(rows)["original_total_RELA_and_JMPREL"]==147,
         "all 147 original unmodified GNU rows")
    r=rows[0]
    need((r["index"],r["table"],r["table_index"],r["r_type"],r["r_sym"],
          r["r_offset"],r["r_addend"],r["source_guest_target"],
          r["original_source_qword"])==
         (0,"DT_RELA",0,1,2726,"0x1ffc68",0,TARGET,"0x0"),
         "real GNU first non-IFUNC relocation")
    q=source_offset(libc,0x1ffc68,8,6,nonexec=True)
    need(libc[q:q+8]==bytes(8),"original writable ELF target zero")
    plan=jload(src/(SRC+".json"))
    need(plan["original_source_libc_sha256"]==LIBC_SHA and
         plan["original_source_ldso_sha256"]==LDSO_SHA and
         plan["original_relocation_index"]==0 and
         plan["original_table"]=="DT_RELA" and
         plan["relocation_type"]=="R_X86_64_64" and
         plan["original_symbol_index"]==2726 and
         plan["original_symbol_name"]=="_res" and
         plan["original_symbol_source_in_bss"] is True and
         plan["original_guest_target"]==TARGET and
         plan["original_source_target_qword"]=="0x0" and
         plan["symbol_local_definition_candidate_guest_address"]==CANDIDATE and
         plan["previous_native_writer_targets_independently_certified"]==62 and
         plan["source_only_not_native_FEX_writer_proof"] is True and
         plan["new_native_writer_targets_in_this_source_only_stage"]==0 and
         plan["symbol_preemption_or_versioned_runtime_lookup_proven"] is False,
         "exact original source plan, zero new native claims")
    gdb=regular(src/(SRC+".gdb")).decode()
    need(gdb.startswith("set pagination off\nset confirm off\n") and
         gdb.count("watch -location *(unsigned long long *)"+TARGET)==1 and
         gdb.count("KERNIX_G0_RELA0_RES_NATIVE_RAW_WATCH")==1,
         "strict original x86 target watch plan")
    ledger=jload(prior/"original-libc-147-source-batch-native-proof-ledger62-NO-NEW-HW-RUN.json")
    need(ledger["previously_independently_attested_native_writer_target_count"]==62
         and ledger["remaining_requires_separate_native_hardware_evidence"]==85
         and 0 in ledger["remaining_non_IFUNC_DT_RELA_indices"]
         and 0 not in ledger["previously_attested_original_source_indices"]
         and ledger["native_IFUNC85_DT_RELA_real_zero_to_zero_FEX_JIT_hardware_STORE_independently_proven"] is True
         and ledger["all_147_same_guest_native_execution_proven"] is False
         and ledger["Android_Bionic_Wine_Proton_games_proven"] is False,
         "immutable prior proof ledger still 62/147")
    return gdb,plan,libc,ldso

def raw_files(native:Path,gdb:str)->tuple[str,str,dict,dict]:
    need(regular(native/(SRC+".gdb")).decode()==gdb,
         "raw native copied original source GDB unchanged")
    for suffix in (RAW,JIT):
        need(regular(native/(suffix+".exit")).decode().strip()=="0",
             suffix+" source-only GDB process exited cleanly")
    raw=regular(native/(RAW+".log")).decode(errors="replace")
    jit=regular(native/(JIT+".log")).decode(errors="replace")
    need(300<len(raw)<600000 and 300<len(jit)<600000,"bounded real ARM64 FEX native GDB logs")
    a=jload(native/(RAW+".json"))
    b=jload(native/(JIT+".json"))
    need(a["raw_native_log_sha256"]==hashlib.sha256(raw.encode()).hexdigest()
         and b["raw_log_sha256"]==hashlib.sha256(jit.encode()).hexdigest(),
         "both different real ARM64 FEX GDB processes SHA-pinned")
    need(a["original_guest_target"]==TARGET
         and a["original_relocation_index"]==0
         and a["native_hardware_write_independently_attested"] is False
         and a["prior_native_writer_count"]==62
         and b["original_source_target"]==TARGET
         and b["source_ONLY_prior_61_native_writers"]==62
         and b["native_source_hardware_writer_independently_attested"] is False
         and b["original_GNU_R_X86_64_64_symbol_preemption_and_version_lookup_proven"] is False,
         "raw reports cannot certify writer or interposition")
    derived=regular(native/(JIT+".gdb")).decode()
    need(derived.count("watch -location *(unsigned long long *)"+TARGET)==1
         and derived.count("KERNIX_G0_RELA0_FEX_ORIGINAL_SOURCE_JIT")==1
         and derived.count("KERNIX_G0_RELA0_NATIVE_REGS")==1
         and derived.count("x/16bx $entry")==1,
         "native JIT watch exactly same immutable original source target")
    return raw,jit,a,b

def candidate(log:str)->dict:
    arm=exactly(r"^KERNIX_G0_RELA0_RES_SOURCE_ONLY_WATCH_ARM target="+
                TARGET+r" initial=0x0 candidate="+CANDIDATE+
                r" NO_NATIVE_PROOF=1$",log,"armed original zero target")
    points=list(re.finditer(r"^Hardware watchpoint 2: -location "+
            re.escape("*(unsigned long long *)")+TARGET+r"$",log,re.M))
    need(len(points)==2,"real GNU native write watch armed once and fired once")
    old=exactly(r"^Old value = 0$",log,"old original target zero")
    new=exactly(r"^New value = ([0-9]+)$",log,"real relocated symbol target qword")
    need(int(new[1])==int(CANDIDATE,16),"genuine new target candidate equals original GNU BSS symbol")
    hit=exactly(r"^KERNIX_G0_RELA0_RES_JIT_RAW_WATCH target="+TARGET+
               r" pc=(0x[0-9a-f]+) x4=(0x[0-9a-f]+) x19=(0x[0-9a-f]+) x28=(0x[0-9a-f]+) RAW_NOT_INDEPENDENT=1$",
               log,"real ARM64 FEX post-write marker")
    vals=list(re.finditer(r"^"+TARGET+r":\s+(0x[0-9a-f]{16})$",log,re.M))
    need(len(vals)==2 and int(vals[0][1],16)==0 and
         int(vals[1][1],16)==int(CANDIDATE,16),
         "one source zero and one native real symbol pointer write qword")
    pc=int(hit[1],16)
    need(pc>=0xffff00000000 and hit[2]==TARGET
         and int(hit[4],16)>=0xffff00000000,
         "native AArch64 PC, guest target register x4 and FEX JIT context")
    ins=exactly(r"^\s*(0x[0-9a-f]+):\s+stlr\s+x13,\s*\[x4\]$",
                log,"native real ARM64 store is STLR x13,[x4]")
    need(int(ins[1],16)==pc-4,"hardware trap PC exactly past recorded native STLR")
    regs=exactly(r"^KERNIX_G0_RELA0_NATIVE_REGS x4=(0x[0-9a-f]+) x13=(0x[0-9a-f]+) x28=(0x[0-9a-f]+)$",
                 log,"native ARM64 registers in same real trap")
    need(regs[1]==TARGET and regs[2]==CANDIDATE and
         int(regs[3],16)>=0xffff00000000,
         "native x13 actual relocated BSS candidate stored to exact original target x4")
    jit=exactly(r"^KERNIX_G0_RELA0_FEX_ORIGINAL_SOURCE_JIT guest_entry=(0x[0-9a-f]+) source_size=(0x[0-9a-f]+) native_count=(\d+)$",
                log,"FEX live original GNU x86 JIT header")
    entry=int(jit[1],16);size=int(jit[2],16);count=int(jit[3])
    need(1<=size<=15 and count>=1,"bounded original x86 source instruction and native JIT count")
    footer=exactly(r"^KERNIX_G0_RELA0_RES_SOURCE_ONLY_NO_NATIVE_ATTESTATION=1$",
                   log,"raw no-certification footer")
    need(arm.start()<vals[0].start()<points[0].start()<points[1].start()
         <old.start()<new.start()<hit.start()<vals[1].start()<ins.start()
         <regs.start()<jit.start()<footer.start(),
         "same guest genuinely chronological hardware arm->write->native STLR/source")
    return {"native_stlr_pc":hex(pc-4),"native_stored_value":hex(int(new[1])),
            "original_guest_target":TARGET,"native_store_reg":"x13",
            "native_target_reg":"x4","jit_source_guest_entry":hex(entry),
            "jit_source_size":size,"jit_native_count":count}

def live_jit_original_bytes(raw:str,source_entry:int,source_size:int,
                            libc:bytes,ldso:bytes)->dict:
    # Require genuine runtime x/16bx bytes to agree with the immutable
    # original SHA-pinned GNU x86 source at the actual native JIT guest entry.
    m=re.search(r"^"+re.escape(hex(source_entry))+r":\s*((?:0x[0-9a-f]{2}\s*){1,16})$",
                raw,re.M)
    need(m is not None,"live original GDB source-byte dump at JIT guest entry")
    actual=bytes(int(v,16) for v in re.findall(r"0x[0-9a-f]{2}",m[1]))
    need(len(actual)>=min(source_size,8),"at least first source opcode bytes available")
    origin=None;source_name=None
    try:
        off=source_offset(ldso,source_entry-LDSO_BASE,source_size,5)
        origin=ldso[off:off+source_size];source_name="original-GNU-ld-linux-x86-64"
    except (AssertionError,ValueError,IndexError):
        pass
    if origin is None:
        try:
            off=source_offset(libc,source_entry-BASE,source_size,5)
            origin=libc[off:off+source_size];source_name="original-GNU-libc-x86-64"
        except (AssertionError,ValueError,IndexError):
            pass
    need(origin is not None,"source JIT entry must be original SHA-pinned x86 GNU text")
    require_count=min(len(actual),len(origin))
    need(actual[:require_count]==origin[:require_count],
         "original source bytes equal actual guest JIT byte dump")
    return {"original_gnu_source_binary":source_name,
            "original_sha_pinned_JIT_guest_entry":hex(source_entry),
            "source_instruction_length":source_size,
            "original_x86_source_instruction_hex":origin.hex(),
            "actual_live_GDB_guest_JIT_byte_prefix_hex":actual[:require_count].hex(),
            "original_guest_x86_code_bytes_SHA_verified":True,
            "original_GNU_symbol_version_preemption_lookup_fully_proven":False}

def run(triad:Path,source:Path,native:Path,prev:Path,out:Path):
    gdb,plan,libc,ldso=immutable_source(triad,source,prev)
    first,second,a,b=raw_files(native,gdb)
    # The first real FEX process is independent cross-check for the exact
    # original target and newly written source symbol BSS address.
    need(first.count("Hardware watchpoint 2: -location *(unsigned long long *)"+TARGET)==2,
         "separate first native hardware watch genuinely fired")
    need("New value = "+str(int(CANDIDATE,16)) in first and
         "stlr\tx13, [x4]" in first,
         "separate first genuine FEX native symbol target STORE candidate")
    data=candidate(second)
    source_detail=live_jit_original_bytes(second,int(data["jit_source_guest_entry"],16),
                                          data["jit_source_size"],libc,ldso)
    obj={"schema":"kernix.g0.original-gnu-rela0-res-dual-fex-native-stlr-source-jit-RAW-FORENSICS.v1",
         "original_libc_sha256":LIBC_SHA,"original_ldso_sha256":LDSO_SHA,
         "original_relocation_index":0,"original_type":"R_X86_64_64",
         "original_symbol_name":"_res","original_symbol_index":2726,
         "previously_independently_certified_native_writer_targets":62,
         "first_original_FEX_native_raw_log_sha256":a["raw_native_log_sha256"],
         "second_original_FEX_native_raw_log_sha256":b["raw_log_sha256"],
         "new_raw_hardware_writer_candidate":data,
         "source_jit_original_sha_byte_parity":source_detail,
         "original_GNU_R64_symbol_preemption_and_version_resolution_proven":False,
         "independently_certified_new_native_writer_targets":0,
         "original_R64_writer_fully_independently_attested":False,
         "new_native_writer_ledger_after_this_forensics":62,
         "all_147_same_guest_relocations_proven":False,
         "Android_Bionic_Wine_Proton_games_proven":False}
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(obj,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_GNU_RELA0_RES_DUAL_RAW_SOURCE_JIT_AUTHENTICATED_NO_NEW_NATIVE_WRITER_CERTIFICATION_KEEP_62_OF_147",json.dumps(obj,sort_keys=True))
    return obj

if __name__=="__main__":
    need(len(sys.argv)==6,"usage original-gnu-triad-source source-only native-artifacts prior62-ledger output-json")
    run(*map(Path,sys.argv[1:]))
