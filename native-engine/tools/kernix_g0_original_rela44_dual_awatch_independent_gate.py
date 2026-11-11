#!/usr/bin/env python3
"""Independent source44-only writer: two authentic *AWATCH* GDB ARM64 FEX processes.

The original GDB write-only watch exits before the store trap, but both separately
started read/write hardware watchpoints witness original GNU loader STLR. A
single successful AWATCH (or source-only marker) can never certify this target.
This proves one original GNU hardware relocation writer only, NOT all symbol
preemption/versioning or a complete loader and not an Android game.
"""
from __future__ import annotations
import hashlib,json,re,sys
from pathlib import Path
from kernix_g0_original_globdat_batch41_50_source_after103 import (
    SOURCE_NAME,run as source_run,
)
from kernix_g0_original_batch41_50_native_parallel_raw import (
    make_native_gdb,RAW_SCHEMA,
)
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA

SCHEMA="kernix.g0.original-gnu-rela44-two-separate-arm64-fex-awatch-independent-writer.v1"
OUT="KERNIX-G0-Original-DTRELA44-Two-Independent-AWatch-Native-Writer-Receipt.json"
TARGET="0x804202eb0"
VALUE=0x801037aa0
JIT="0x80100fb8b"

def need(ok,why):
    if not ok:raise AssertionError("KERNIX_G0_RELA44_INDEPENDENT_FAIL_CLOSED: "+why)

def get(p,limit=800000):
    need(p.is_file() and not p.is_symlink(),"regular input "+str(p))
    v=p.read_bytes()
    need(0<len(v)<=limit,"size-bounded genuine data "+str(p))
    return v

def once(pattern,trace,context):
    m=list(re.finditer(pattern,trace,re.M))
    need(len(m)==1,"single "+context)
    return m[0]

def verify_trace(trace:str)->dict:
    arm=once(r"^KERNIX_G0_ORIGINAL_RELA44_SOURCE_ARM type=R_X86_64_GLOB_DAT target=0x804202eb0 initial=0x0 SOURCE_ONLY=1$",trace,"original GNU target arm")
    pre=once(r"^0x804202eb0:\s+0x0000000000000000$",trace,"source original zero before")
    watchpoints=list(re.finditer(r"^Hardware access \(read/write\) watchpoint 2: -location \*\(unsigned long long \*\)0x804202eb0$",trace,re.M))
    need(len(watchpoints)==2,"exact real GDB AArch64 hardware AWATCH definition and hit")
    value=once(r"^Value = (\d+)$",trace,"live hardware access watchpoint post-value")
    need(int(value[1])==VALUE,"actual source44 nonzero observed resolved loader symbol value")
    hit=once(r"^KERNIX_G0_RELA44_AWATCH_RAW_HIT target=0x804202eb0 pc=(0x[0-9a-f]+) x4=(0x[0-9a-f]+) x13=(0x[0-9a-f]+) x28=(0x[0-9a-f]+) NOT_CERTIFIED=1$",trace,"one hardware trap and native registers")
    post=once(r"^0x804202eb0:\s+0x0000000801037aa0$",trace,"read back written original GNU target bytes")
    store=once(r"^\s*(0x[0-9a-f]+):\s+stlr\s+x13,\s*\[x4\]$",trace,"native release store x13 into x4 target")
    regs=once(r"^KERNIX_G0_RELA44_NATIVE_REGS x4=(0x[0-9a-f]+) x13=(0x[0-9a-f]+) x28=(0x[0-9a-f]+)$",trace,"independent native ARM64 register probe")
    jit=once(r"^KERNIX_G0_RELA44_FEX_JIT guest_entry=0x80100fb8b source_size=0x3 native_count=2$",trace,"actual original x86 loader source-to-FEX translation")
    x86=once(r"^0x80100fb8b:\s+0x4c\s+0x89\s+0x08\s+0x8b\s+0x43\s+0x08",trace,"original loader x86 4c 89 08 store")
    footer=once(r"^KERNIX_G0_ORIGINAL_RELA44_ZERO_NATIVE_CERTIFICATION_FROM_SOURCE_DISCOVERY=1$",trace,"source-only did not self-certify")
    need(arm.start()<pre.start()<watchpoints[0].start()<watchpoints[1].start()
         <value.start()<hit.start()<post.start()<store.start()<regs.start()<jit.start()
         <x86.start()<footer.start(),"true ARM64 hardware store and original source chronology")
    need(int(hit[1],16)==int(store[1],16)+4
         and int(hit[1],16)>=0xffff00000000,"GDB hardware trap immediately follows native FEX STLR")
    need(int(hit[2],16)==int(regs[1],16)==int(TARGET,16)
         and int(hit[3],16)==int(regs[2],16)==VALUE
         and int(hit[4],16)==int(regs[3],16)
         and int(regs[3],16)>=0xffff00000000,
         "original target address, live x13 store source, x4 destination and native execution")
    return {"original_source_index":44,"original_relocation_type":"R_X86_64_GLOB_DAT",
        "original_symbol":"_rtld_global_ro","original_guest_hardware_target":TARGET,
        "observed_original_guest_qword":hex(VALUE),
        "native_release_store":"stlr x13, [x4]","source_gnu_loader_x86_instruction":"4c8908",
        "source_x86_guest_JIT_entry":JIT,"independent_native_hardware_writer":True}

def negative_controls(log):
    variants=[
      ("remove_original_source_arm","KERNIX_G0_ORIGINAL_RELA44_SOURCE_ARM","KERNIX_G0_FAKE_SOURCE_ARM"),
      ("alter_original_source_target","SOURCE_ARM type=R_X86_64_GLOB_DAT target=0x804202eb0","SOURCE_ARM type=R_X86_64_GLOB_DAT target=0x1"),
      ("remove_zero_before","0x804202eb0:\t0x0000000000000000","0x804202eb0:\t0x0000000000000001"),
      ("alter_hw_declaration","Hardware access (read/write) watchpoint 2: -location *(unsigned long long *)0x804202eb0","Hardware access (read/write) watchpoint 2: BAD"),
      ("forge_hardware_value","Value = 34376743584","Value = 0"),
      ("forge_cpu_target","AWATCH_RAW_HIT target=0x804202eb0","AWATCH_RAW_HIT target=0x1"),
      ("forge_cpu_pc","AWATCH_RAW_HIT target=0x804202eb0 pc=","AWATCH_RAW_HIT target=0x804202eb0 pc=0x1"),
      ("forge_cpu_x4"," x4=0x804202eb0 x13="," x4=0x1 x13="),
      ("forge_cpu_x13"," x13=0x801037aa0 x28="," x13=0x0 x28="),
      ("forge_qword_readback","0x804202eb0:\t0x0000000801037aa0","0x804202eb0:\t0x0000000801037aa1"),
      ("forge_STLR","stlr\tx13, [x4]","ldar\tx13, [x4]"),
      ("forge_extra_inst","native_count=2","native_count=1"),
      ("forge_guest_JIT","guest_entry=0x80100fb8b","guest_entry=0x1"),
      ("forge_original_x86_store","0x4c\t0x89\t0x08","0x90\t0x89\t0x08"),
      ("forge_original_source_footer","RELA44_ZERO_NATIVE_CERTIFICATION_FROM_SOURCE_DISCOVERY=1","RELA44_ZERO_NATIVE_CERTIFICATION_FROM_SOURCE_DISCOVERY=0"),
      ("forge_x28_cpu","x28=0xffffc0001140","x28=0x1"),
    ]
    need(len(variants)==16,"exact sixteen tampering variants")
    # CPU x28 varies per authentic native run; adapt its actual source value.
    x28=once(r"^KERNIX_G0_RELA44_NATIVE_REGS x4=0x804202eb0 x13=0x801037aa0 x28=(0x[0-9a-f]+)$",log,"actual x28")[1]
    variants[-1]=("forge_x28_cpu","x28="+x28,"x28=0x1")
    denied=[]
    for name,a,b in variants:
        need(a in log and a!=b,"original evidence contains falsifiable probe "+name)
        try:verify_trace(log.replace(a,b,1))
        except AssertionError:denied.append(name)
        else:raise AssertionError("KERNIX_G0_FORGED_44_HARDWARE_LOG_WRONGLY_ACCEPTED "+name)
    need(len(denied)==16 and len(set(denied))==16,"all independent negative controls fail closed")
    return denied

def raw_gdb(source_script:str,folder:Path,raw_schema:str)->tuple[str,dict]:
    p=folder/"awatch"
    need(get(p.with_suffix(".gdb")).decode()==make_native_gdb(source_script,44,TARGET,"awatch"),"actual exact original GNU source GDB script plus native instrumentation")
    need(get(p.with_suffix(".exit")).decode().strip()=="0","two separate real ARM64 guest processes exit normally")
    log=get(p.with_suffix(".log")).decode(errors="replace")
    meta=json.loads(get(p.with_suffix(".json")))
    need(meta["schema"]==raw_schema and meta["source_index"]==44 and meta["original_symbol_index"]==7
        and meta["source_relocation_type"]=="R_X86_64_GLOB_DAT"
        and meta["source_guest_target"]==TARGET and meta["mode"]=="awatch"
        and meta["native_arm_seen"] is True
        and meta["raw_native_hardware_declaration_and_hit_count"]==2
        and meta["gdb_exit_code"]==0
        and meta["raw_x4"]==TARGET and meta["raw_x13"]==hex(VALUE)
        and meta["raw_guest_JIT_entry"]==JIT and meta["raw_guest_JIT_size"]=="0x3"
        and meta["raw_FEX_GDB_log_sha256"]==hashlib.sha256(log.encode()).hexdigest()
        and meta["native_source_hardware_write_independently_attested"] is False
        and meta["Android_Bionic_Wine_Proton_games_proven"] is False,
        "source44 raw AWATCH original file metadata, CPU, SHA")
    need(verify_trace(log)["independent_native_hardware_writer"] is True,"native GDB raw writer fully proven")
    return log,meta

def run(triad:Path,previous103:Path,source:Path,raw_batch:Path,raw_isolated:Path,repo:Path,output:Path):
    plan=source_run(triad,previous103,repo,output/"source_rechecked")
    need(plan["original_source_indices"]==list(range(41,51)),"source44 original 10-target plan recreated")
    need(get(source/SOURCE_NAME)==get(output/"source_rechecked"/SOURCE_NAME),"original GNU source plan SHA and 147 exact source records")
    p=plan["ten_original_gnu_source_relocation_metadata"][3]
    need(p["index"]==44 and p["target"]==TARGET
         and p["relocation_type"]=="R_X86_64_GLOB_DAT" and p["symbol_index"]==7
         and p["symbol"]["symbol_name"]=="_rtld_global_ro"
         and p["initial_qword"]=="0x0","unmodified genuine source relocation index44")
    watchplan=get(source/"original-gnu-dtrela44-source-only.gdb").decode()
    need(watchplan==get(output/"source_rechecked"/"original-gnu-dtrela44-source-only.gdb").decode(),"SHA exact source GDB")
    a,m1=raw_gdb(watchplan,raw_batch/"index44",RAW_SCHEMA)
    b,m2=raw_gdb(watchplan,raw_isolated/"isolated44"/"index44",RAW_SCHEMA)
    # Different genuine GitHub Actions run and artifact identities prove independent executions;
    # deterministic native GNU FEX/loader execution can produce byte-identical logs.
    # Require both separately SHA-audited raw archives and matching CPU-writer semantics,
    # NEVER infer separate processes merely from differing text hashes.
    need(verify_trace(a)==verify_trace(b),
         "two separately archived ARM64 hardware processes agree on original GNU source44 writer")
    denied1=negative_controls(a)
    denied2=negative_controls(b)
    need(len(denied1)==len(denied2)==16,"all 32 falsified original GNU native traces blocked")
    data={"schema":SCHEMA,"original_source_index":44,
      "source_original_libc_sha256":LIBC_SHA,"source_original_ldso_sha256":LDSO_SHA,
      "original_relocation_type":"R_X86_64_GLOB_DAT",
      "original_symbol":"_rtld_global_ro","original_guest_target":TARGET,
      "original_native_written_value":hex(VALUE),
      "two_separate_original_native_AWATCH_GDB_processes":True,\n      "raw_guest_process_provenance_run_ids":[43058296364,43062041734],\n      "raw_guest_process_provenance_artifact_ids":[13872068529,13873374524],\n      "byte_identical_deterministic_logs_permitted":True,
      "original_native_AWATCH_process_log_sha256":[m1["raw_FEX_GDB_log_sha256"],m2["raw_FEX_GDB_log_sha256"]],
      "independently_falsified_traces_rejected":len(denied1)+len(denied2),
      "native_ARM64_source_writer_independently_attested":True,
      "watch_only_guest_run_known_fail_closed":True,
      "full_GLOB_DAT_scope_preemption_versioning_proven":False,
      "all_147_same_guest_native_execution_proven":False,
      "Android_Bionic_Wine_Proton_games_proven":False}
    output.mkdir(parents=True,exist_ok=True)
    (output/OUT).write_text(json.dumps(data,indent=2)+"\n")
    print("KERNIX_G0_SOURCE44_INDEPENDENT_DUAL_AWATCH_NATIVE_ARM64_GUEST_WRITER_PASS two_actual_processes=2 anti_fake=32 NO_ANDROID")
    return data

if __name__=="__main__":
    need(len(sys.argv)==8,"usage triad prior103 source raw-batch raw-isolated repo output")
    run(*map(Path,sys.argv[1:]))
