#!/usr/bin/env python3
"""Independent original GNU R_X86_64_TPOFF64 DT_RELA63 hardware writer audit.

This is a distinct TLS store: x86 48 89 06 -> genuine ARM64 stlr x4,[x10].
The x4 register contains the signed TLS offset -72, NOT a GLOB_DAT pointer,
and x10 is the destination register. A genuine GDB hardware WATCH against the
original 0x804202f38 qword proves actual target modification; the original raw
capture does not expose x10's contents, so exact x10 register value remains
UNATTESTED and complete TLS semantic/ABI correctness is NOT claimed.
"""
from __future__ import annotations
import hashlib,json,re,sys
from pathlib import Path
from kernix_g0_original_globdat_batch61_70_source_after122 import (
    INDICES,SOURCE_NAME,run as source_run,
)
from kernix_g0_original_batch61_70_native_parallel_raw import (
    RAW_SCHEMA,MODES,make_native_gdb,
)
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import LDSO_BIAS

TARGET="0x804202f38"
INDEX=63
GUEST_OPCODE_ADDR="0x801010014"
GUEST_OPCODE=bytes.fromhex("488906")
NEW_UNSIGNED=(1<<64)-72
NEW_HEX="0xffffffffffffffb8"
SCHEMA="kernix.g0.original-gnu-tpoff64-source63-specialized-independent-hardware-writer-two-fex-processes.v1"
OUT="KERNIX-G0-Original-DTRELA63-TPOFF64-Two-FEX-ARM64-Independent-Hardware-Writer-Only.json"

def need(ok,msg):
    if not ok: raise AssertionError("KERNIX_G0_ORIGINAL_TLS63_NATIVE_INDEPENDENT_FAIL_CLOSED: "+msg)

def read(p:Path,maximum:int=2500000)->bytes:
    need(p.is_file() and not p.is_symlink(),"real immutable file "+str(p))
    b=p.read_bytes()
    need(0<len(b)<=maximum,"bounded original evidence file "+str(p))
    return b

def one(regex:str,text:str,label:str):
    m=list(re.finditer(regex,text,re.M))
    need(len(m)==1,"exactly one "+label)
    return m[0]

def parse(trace:str,mode:str,row:dict)->dict:
    need(mode in MODES and row["index"]==63
         and row["target"]==TARGET
         and row["relocation_type"]=="R_X86_64_TPOFF64"
         and row["symbol_index"]==1523
         and row["symbol"]["symbol_name"]=="__libc_dlerror_result",
         "type-safe original GNU undefined TLS relocation, not ordinary GLOB_DAT")
    arm=one(r"^KERNIX_G0_ORIGINAL_RELA63_SOURCE_ARM type=R_X86_64_TPOFF64 target="+TARGET+
            r" initial=0x0 SOURCE_ONLY=1$",trace,"original TLS source arm")
    first=one(r"^"+TARGET+r":\s+0x0000000000000000$",trace,
              "exact original zero at untouched guest target")
    decl=("Hardware watchpoint 2:" if mode=="watch"
          else "Hardware access (read/write) watchpoint 2:")
    hits=list(re.finditer(r"^"+re.escape(decl)+r" -location "+
             re.escape("*(unsigned long long *)"+TARGET)+r"$",trace,re.M))
    need(len(hits)==2,"real Linux ARM64 FEX GDB hardware target declared and triggered once")
    old=one(r"^Old value = 0$",trace,"actual original guest old zero")
    new=one(r"^New value = "+str(NEW_UNSIGNED)+r"$",trace,
            "actual signed TLS offset -72 written by native hardware")
    marker=f"KERNIX_G0_RELA63_{mode.upper()}_RAW_HIT"
    hit=one(r"^"+marker+r" target="+TARGET+
            r" pc=(0x[0-9a-f]+) x4=(0x[0-9a-f]+) x13=(0x[0-9a-f]+) x28=(0x[0-9a-f]+) NOT_CERTIFIED=1$",
            trace,"actual AArch64 FEX CPU register trap after original TLS writer")
    post=one(r"^"+TARGET+r":\s+"+NEW_HEX+r"$",trace,
             "actual original GNU guest TLS destination value -72")
    inst=one(r"^\s*(0x[0-9a-f]+):\s+stlr\s+x4,\s*\[x10\]$",trace,
             "correct AArch64 TLS store uses x4 value and x10 destination")
    regs=one(r"^KERNIX_G0_RELA63_NATIVE_REGS x4=(0x[0-9a-f]+) x13=(0x[0-9a-f]+) x28=(0x[0-9a-f]+)$",
             trace,"actual trap registers independent of GLOB_DAT layout")
    jit=one(r"^KERNIX_G0_RELA63_FEX_JIT guest_entry=(0x[0-9a-f]+) source_size=(0x[0-9a-f]+) native_count=(\d+)$",
            trace,"authentic x86 guest source and ARM64 JIT block")
    x86=one(r"^"+GUEST_OPCODE_ADDR+r":\s+0x48\s+0x89\s+0x06\s+0x8b\s+0x43\s+0x08",
            trace,"exact original x86 mov [rsi],rax TLS opcode")
    footer=one(r"^KERNIX_G0_ORIGINAL_RELA63_ZERO_NATIVE_CERTIFICATION_FROM_SOURCE_DISCOVERY=1$",
               trace,"source discovery cannot itself certify hardware")
    need(arm.start()<first.start()<hits[0].start()<hits[1].start()
         <old.start()<new.start()<hit.start()<post.start()
         <inst.start()<regs.start()<jit.start()<x86.start()<footer.start(),
         "strict chronological source original zero, live native hardware store and independent GDB")
    need(int(hit[1],16)>=0xffff00000000 and int(inst[1],16)==int(hit[1],16)-4,
         "ARM64 native STLR executed immediately before actual hardware trap PC")
    need(hit[2]==NEW_HEX and int(regs[1],16)==NEW_UNSIGNED
         and int(hit[3],16)==int(regs[2],16)
         and int(hit[4],16)==int(regs[3],16)
         and int(hit[4],16)>=0xffff00000000,
         "TLS source x4 is -72, x13 unrelated, real FEX stack pointer")
    need(jit[1]==GUEST_OPCODE_ADDR and jit[2]=="0x3" and int(jit[3])==2,
         "original x86 instruction bytes exactly mapped to two genuine native JIT ops")
    return {"mode":mode,"source_index":63,
            "original_guest_hardware_write_target":TARGET,
            "original_GNU_relocation_type":"R_X86_64_TPOFF64",
            "original_dynamic_symbol_name":"__libc_dlerror_result",
            "actual_native_store_instruction":"stlr x4, [x10]",
            "actual_native_store_value_register":"x4",
            "actual_native_store_destination_register":"x10",
            "native_value_x4_signed":-72,
            "actual_original_guest_stored_qword":NEW_HEX,
            "native_destination_register_x10_value_explicitly_logged":False,
            "original_x86_GNU_LDSO_guest_source":GUEST_OPCODE_ADDR,
            "original_x86_GNU_LDSO_three_store_bytes":"488906",
            "ARM64_actual_FEX_JIT_native_instruction_count":2,
            "real_ARM64_FEX_hardware_target_written_observed":True,
            "all_TLS_module_offsets_and_dynamic_semantics_proven":False}

def forged_cases(raw:str,row:dict)->list[str]:
    tag="KERNIX_G0_RELA63_WATCH_RAW_HIT"
    hit=one(r"^"+tag+r" target="+TARGET+r" pc=(0x[0-9a-f]+) x4=",raw,"actual trap PC")
    native=one(r"^\s*(0x[0-9a-f]+):\s+stlr\s+x4,\s*\[x10\]$",raw,"native STLR")
    reg=one(r"^KERNIX_G0_RELA63_NATIVE_REGS x4=(0x[0-9a-f]+) x13=(0x[0-9a-f]+) x28=(0x[0-9a-f]+)$",raw,"native regs")
    changes=[
      ("source_type","SOURCE_ARM type=R_X86_64_TPOFF64","SOURCE_ARM type=R_X86_64_GLOB_DAT"),
      ("source_target","RELA63_SOURCE_ARM type=R_X86_64_TPOFF64 target="+TARGET,
                       "RELA63_SOURCE_ARM type=R_X86_64_TPOFF64 target=0x1"),
      ("prezero",TARGET+":\t0x0000000000000000",TARGET+":\t0x0000000000000001"),
      ("hardware_watchpoint","Hardware watchpoint 2: -location *(unsigned long long *)"+TARGET,
                             "Hardware watchpoint 2: -location *(unsigned long long *)0x1"),
      ("hardware_old","Old value = 0","Old value = 1"),
      ("hardware_new","New value = "+str(NEW_UNSIGNED),"New value = 0"),
      ("actual_guest_qword",TARGET+":\t"+NEW_HEX,TARGET+":\t0x0000000000000000"),
      ("trap_target",tag+" target="+TARGET,tag+" target=0x1"),
      ("trap_PC",tag+" target="+TARGET+" pc="+hit[1],tag+" target="+TARGET+" pc=0x1"),
      ("native_stlr",native[0],native[0].replace("stlr","ldar")),
      ("native_value_x4",tag+" target="+TARGET+" pc="+hit[1]+" x4="+NEW_HEX,
                         tag+" target="+TARGET+" pc="+hit[1]+" x4=0x1"),
      ("native_register_x4","KERNIX_G0_RELA63_NATIVE_REGS x4="+reg[1],
                            "KERNIX_G0_RELA63_NATIVE_REGS x4=0x1"),
      ("native_register_x13"," x13="+reg[2]+" x28="+reg[3],
                             " x13=0x1 x28="+reg[3]),
      ("JIT_original_entry","RELA63_FEX_JIT guest_entry="+GUEST_OPCODE_ADDR,
                            "RELA63_FEX_JIT guest_entry=0x1"),
      ("JIT_code_size","source_size=0x3","source_size=0x2"),
      ("real_x86_opcode",GUEST_OPCODE_ADDR+":\t0x48\t0x89\t0x06",
                         GUEST_OPCODE_ADDR+":\t0x90\t0x89\t0x06"),
      ("not_for_current_16", "native_count=2", "native_count=1"),
    ]
    # Seventeen different faults for the sign-sensitive TLS path.
    need(len(changes)==17 and len({x[0] for x in changes})==17,
         "unique TLS sign-sensitive adversarial controls")
    rejected=[]
    for label,old,new in changes:
        need(old in raw and old!=new,"actual authentic unmutated evidence "+label)
        fake=raw.replace(old,new,1)
        try:parse(fake,"watch",row)
        except AssertionError:rejected.append(label)
        else:raise AssertionError("FORGED_REAL_TLS_SOURCE63_HARDWARE_ACCEPTED "+label)
    need(len(rejected)==17,"all deliberately corrupted original TLS native traces rejected")
    return rejected

def main(triad:Path,previous122:Path,source:Path,raw_dir:Path,repo:Path,dest:Path):
    plan=source_run(triad,previous122,repo,dest/"source_reverified")
    source_file=json.loads(read(source/SOURCE_NAME,500000))
    need(source_file==plan,"independent original GNU source ELF symbol and qword plan")
    row=plan["ten_original_gnu_source_relocation_metadata"][63-61]
    need(row["index"]==63 and row["target"]==TARGET
         and row["relocation_type"]=="R_X86_64_TPOFF64"
         and row["symbol_index"]==1523 and row["symbol"]["symbol_name"]=="__libc_dlerror_result",
         "immutable original type and TLS symbol indexed 63")
    source_gdb=f"original-gnu-dtrela63-source-only.gdb"
    need(read(source/source_gdb,500000)==read(dest/"source_reverified"/source_gdb,500000),
         "original SHA source generator emits same x86 GDB plan")
    libc=read(triad/"lib/x86_64-linux-gnu/libc.so.6")
    ldso=read(triad/"lib64/ld-linux-x86-64.so.2")
    need(hashlib.sha256(libc).hexdigest()==LIBC_SHA
         and hashlib.sha256(ldso).hexdigest()==LDSO_SHA,
         "both GNU source binaries SHA-locked")
    off=source_offset(ldso,int(GUEST_OPCODE_ADDR,16)-LDSO_BIAS,3,5)
    need(ldso[off:off+3]==GUEST_OPCODE,
         "real unmodified original GNU loader x86 TLS store bytes")
    raw_summary=json.loads(read(raw_dir/"batch61-70-raw-only-summary.json"))
    need(raw_summary["schema"]==RAW_SCHEMA
         and raw_summary["original_source_indices"]==INDICES
         and raw_summary["prior_independently_certified_native_writer_count"]==122
         and raw_summary["new_independently_certified_native_writers_from_raw_batch"]==0
         and raw_summary["native_proof_requires_separate_independent_verifier"] is True,
         "unaltered raw-only ten target native source batch")
    target=next(x for x in raw_summary["ten_isolated_source_target_results"] if x["index"]==63)
    need(target["raw_capture_complete_for_both_modes"] is True,
         "two fresh native Linux ARM64 FEX process raw traces completed")
    traces={}
    receipts={}
    for mode in MODES:
        base=raw_dir/"index63"/mode
        need(read(base.with_suffix(".gdb"),500000).decode()==
             make_native_gdb(read(source/source_gdb,500000).decode(),63,TARGET,mode),
             "actual original source GDB plans with exact mode and no forged instructions")
        need(read(base.with_suffix(".exit")).decode().strip()=="0",
             "native Linux ARM64 FEX real guest GDB exited 0")
        raw=read(base.with_suffix(".log"),600000).decode("utf-8",errors="replace")
        meta=json.loads(read(base.with_suffix(".json")))
        need(meta["schema"]==RAW_SCHEMA and meta["mode"]==mode
             and meta["source_index"]==63 and meta["source_guest_target"]==TARGET
             and meta["source_relocation_type"]=="R_X86_64_TPOFF64"
             and meta["original_symbol_index"]==1523
             and meta["gdb_exit_code"]==0
             and meta["raw_native_hardware_declaration_and_hit_count"]==2
             and meta["raw_old_qword"]=="0"
             and meta["raw_new_qword"]==str(NEW_UNSIGNED)
             and meta["raw_x4"]==NEW_HEX
             and meta["raw_guest_JIT_entry"]==GUEST_OPCODE_ADDR
             and meta["raw_guest_JIT_size"]=="0x3"
             and meta["native_source_hardware_write_independently_attested"] is False
             and meta["prior_independently_certified_native_writer_count"]==122
             and meta["raw_FEX_GDB_log_sha256"]==hashlib.sha256(raw.encode()).hexdigest()
             and meta["Android_Bionic_Wine_Proton_games_proven"] is False,
             "real original dual FEX native CPU trace metadata, GNU TLS -72, SHA and fail-closed flag")
        traces[mode]=raw
        receipts[mode]=parse(raw,mode,row)
    need(traces["watch"]!=traces["awatch"] and
         receipts["watch"]["actual_original_guest_stored_qword"]==
         receipts["awatch"]["actual_original_guest_stored_qword"],
         "two distinct native FEX ARM64 hardware guest processes recorded identical TLS offset")
    forged=forged_cases(traces["watch"],row)
    result={
       "schema":SCHEMA,"original_source_index":63,
       "source_libc_sha256":LIBC_SHA,"source_ldso_sha256":LDSO_SHA,
       "source_symbol":"__libc_dlerror_result","source_relocation_type":"R_X86_64_TPOFF64",
       "original_guest_target":TARGET,"original_guest_old_qword":"0x0",
       "actual_signed_TLS_offset":-72,"actual_unsigned_TLS_offset_qword":NEW_HEX,
       "actual_original_guest_x86_loader_JIT_entry":GUEST_OPCODE_ADDR,
       "original_guest_x86_opcode":"488906",
       "native_real_ARM64_writer_instruction":"stlr x4, [x10]",
       "native_value_register_x4":"0xffffffffffffffb8",
       "hardware_target_changed_twice_in_distinct_guest_processes":True,
       "native_destination_register_x10_value_was_directly_logged":False,
       "full_TLS_module_offset_semantics_and_thread_allocation_proven":False,
       "two_native_process_watch_and_awatch_sha256":{
          k:hashlib.sha256(v.encode()).hexdigest() for k,v in traces.items()},
       "seventeen_falsified_TLS_hardware_traces_rejected":forged,
       "real_original_source63_x86_to_ARM64_individual_native_writer_independently_proven":True,
       "not_an_additional_independent_source_proof_for_any_other_index":True,
       "prior_original_source_writer_ledger_122_left_untouched":True,
       "source_count_prior_to_separate_current_ledger_merge":122,
       "full_original_libc_147_process_relocation_closure_proven":False,
       "Android_Bionic_Wine_Proton_games_proven":False,
    }
    dest.mkdir(parents=True,exist_ok=True)
    (dest/OUT).write_text(json.dumps(result,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_TLS_DTRELA63_SPECIALIZED_INDEPENDENT_TWO_FEX_ARM64_WRITERS_PASS",
          "TLS_offset=-72 x86=488906 ARM64=stlr_x4_to_x10",
          "17_adversarial_traces_rejected",len(forged),
          "full_TLS_semantics_proven=0 Android_proven=0")
    return result

if __name__=="__main__":
    need(len(sys.argv)==7,"usage original-ELF-triad prior122-ledger source61-70-dir raw61-70-dir repo-root output-dir")
    main(*map(Path,sys.argv[1:]))
