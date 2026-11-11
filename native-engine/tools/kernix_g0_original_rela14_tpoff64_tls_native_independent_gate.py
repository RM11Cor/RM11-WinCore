#!/usr/bin/env python3
"""Independent genuine GNU DT_RELA index1 TPOFF64 native writer proof only.

Checks two separate source-locked original GNU x86 guest executions under
Linux ARM64 FEX, one GDB WATCH and one AWATCH, exact 3-byte original GNU x86
MOV [RSI],RAX source -> native ARM64 STLR X4,[X10], exact real 0->-128 target
hardware modification and 16 forged native evidence traces rejected.

This proves ONE actual source qword writer, NOT TLS module-layout correctness,
all dynamic TLS models, full GNU loader, one process for all 147, or Android.
"""
from __future__ import annotations
import hashlib,json,re,sys
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA,LDSO_SHA,decode_original_libc,classify,
)
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import LDSO_BIAS

PFX="original-libc-DT-RELA14-TPOFF64-TLS-REAL-ARM64-FEX-"
SRC="original-libc-DT-RELA14-next-actual-source-type-symbol-hardware-writer-NO-NATIVE-PROOF"
TGT="0x804202fd0"
NEW="0xffffffffffffff80"
UNSIGNED=(1<<64)-128
JIT="0x801010014"
OPCODE=b"\x48\x89\x06"
OUTPUT="original-libc-DT-RELA14-TPOFF64-TLS-One-Original-FEX-ARM64-Independent-Writer-PROOF.json"

def require(ok:bool,label:str):
    if not ok:raise AssertionError("ORIGINAL GNU DT_RELA14 TLS NATIVE WRITER FAIL-CLOSED: "+label)

def regular(path:Path)->bytes:
    require(path.is_file() and not path.is_symlink(),"regular source/artifact "+str(path))
    b=path.read_bytes()
    require(1<=len(b)<20_000_000,"bounded data bytes "+str(path))
    return b

def once(regex:str,s:str,label:str)->re.Match:
    m=list(re.finditer(regex,s,re.M))
    require(len(m)==1,label+" exactly once in genuine native FEX log")
    return m[0]

def authenticate_sources(triad:Path,source:Path,ledger76:Path)->tuple[bytes,bytes,str]:
    libc=regular(triad/"lib/x86_64-linux-gnu/libc.so.6")
    ldso=regular(triad/"lib64/ld-linux-x86-64.so.2")
    require(len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA,
            "immutable GNU libc x86 source SHA-256")
    require(len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA,
            "immutable GNU ldso x86 source SHA-256")
    records=decode_original_libc(libc)
    require(classify(records)["original_total_RELA_and_JMPREL"]==147,
            "exact 147 original GNU libc source ELF relocation records")
    r=records[14]
    require((r["index"],r["table"],r["table_index"],r["r_type"],r["r_sym"],
             r["r_offset"],r["r_addend"],r["source_guest_target"],
             r["original_source_qword"])==
            (14,"DT_RELA",14,18,0,"0x202fd0",8,TGT,"0x0"),
            "authentic original TPOFF64 sym0 positive signed addend8 and ZERO old qword")
    q=source_offset(libc,0x202fd0,8,6,nonexec=True)
    require(libc[q:q+8]==bytes(8),"actual original file zero source target")
    entry=int(JIT,16)
    src_off=source_offset(ldso,entry-LDSO_BIAS,3,5)
    require(ldso[src_off:src_off+3]==OPCODE,
            "immutable authentic GNU x86 loader JIT source MOV QWORD [RSI],RAX")
    original=json.loads(regular(source/(SRC+".json")))
    require(original["original_source_libc_sha256"]==LIBC_SHA
            and original["original_source_ldso_sha256"]==LDSO_SHA
            and original["original_source_index"]==14
            and original["original_table"]=="DT_RELA"
            and original["original_table_ordinal"]==14
            and original["original_relocation_type"]=="R_X86_64_TPOFF64"
            and original["original_relocation_type_id"]==18
            and original["original_symbol"]["symbol_index"]==0
            and original["original_symbol"]["symbol_name"]==""
            and original["original_source_signed_addend"]==8
            and original["original_source_relocation_offset"]=="0x202fd0"
            and original["original_source_initial_qword"]=="0x0"
            and original["original_guest_target"]==TGT
            and original["original_76_native_source_writers_independently_attested"]==76
            and original["new_native_writer_target_evidence_from_this_source_discovery"]==0
            and original["source_only_no_native_writer_proven"] is True
            and original["original_symbol"]["TLS_runtime_address_or_module_offset_proven"] is False
            and original["Android_Bionic_Wine_Proton_games_proven"] is False,
            "genuine source-only preflight and full negative TLS/Android claims")
    orig_gdb=regular(source/(SRC+".gdb")).decode()
    require(orig_gdb.startswith("set pagination off\nset confirm off\n")
            and orig_gdb.count("watch -location *(unsigned long long *)"+TGT)==1
            and orig_gdb.count("KERNIX_G0_ORIGINAL_RELA14_NEXT_RAW_HIT")==1
            and orig_gdb.count("x/i $pc-4\n")==1,
            "single source-locked original target hardware write-only source watch")
    prior=json.loads(regular(ledger76/
        "original-libc-147-source-batch-native-proof-ledger76-NO-NEW-HW-RUN.json"))
    require(prior["schema"]==
            "kernix.g0.original-gnu-libc-147-relocation-cohort-native-writer-ledger76.v1"
            and prior["source_original_libc_sha256"]==LIBC_SHA
            and prior["source_original_ldso_sha256"]==LDSO_SHA
            and prior["previously_independently_attested_native_writer_target_count"]==76
            and prior["remaining_requires_separate_native_hardware_evidence"]==71
            and prior["remaining_non_IFUNC_DT_RELA_indices"]==list(range(14,85))
            and prior["remaining_IFUNC_indices"]==[]
            and 14 not in prior["previously_attested_original_source_indices"]
            and prior["native_GNU_DT_RELA0_R64_res_REAL_FEX_ARM64_JIT_source_store_writer_independently_proven"] is True
            and prior["native_GNU_DT_RELA1_TLS_TPOFF64_sym0_addend56_REAL_FEX_ARM64_STORE_independently_proven"] is True
            and prior["native_GNU_DT_RELA2_TLS_TPOFF64_sym0_addend48_REAL_FEX_ARM64_STORE_independently_proven"] is True
            and prior["native_GNU_DT_RELA3_TLS_TPOFF64_sym0_addend88_REAL_FEX_ARM64_STORE_independently_proven"] is True
            and prior["native_GNU_DT_RELA4_TLS_TPOFF64_sym0_addend72_REAL_FEX_ARM64_STORE_independently_proven"] is True
            and prior["native_GNU_DT_RELA5_TLS_TPOFF64_sym0_addend80_REAL_FEX_ARM64_STORE_independently_proven"] is True
            and prior["native_GNU_DT_RELA6_TLS_TPOFF64_sym0_addend100_REAL_FEX_ARM64_STORE_independently_proven"] is True
            and prior["native_GNU_DT_RELA7_TLS_TPOFF64_sym0_addend120_REAL_FEX_ARM64_STORE_independently_proven"] is True
            and prior["native_GNU_DT_RELA8_TLS_TPOFF64_sym0_addend128_REAL_FEX_ARM64_STORE_independently_proven"] is True
            and prior["native_GNU_DT_RELA9_TLS_TPOFF64_sym0_addend24_REAL_FEX_ARM64_STORE_independently_proven"] is True
            and prior["native_GNU_DT_RELA10_TLS_TPOFF64_sym0_addend40_REAL_FEX_ARM64_STORE_independently_proven"] is True
            and prior["native_GNU_DT_RELA11_TLS_TPOFF64_sym0_addend16_REAL_FEX_ARM64_STORE_independently_proven"] is True
            and prior["native_GNU_DT_RELA12_TLS_TPOFF64_sym0_addend96_REAL_FEX_ARM64_STORE_independently_proven"] is True
            and prior["native_GNU_DT_RELA13_TLS_TPOFF64_sym0_addend0_REAL_FEX_ARM64_STORE_independently_proven"] is True
            and prior["all_147_same_guest_native_execution_proven"] is False
            and prior["Android_Bionic_Wine_Proton_games_proven"] is False,
            "previous unique 63 original native writers in strict source index 14 pending ledger")
    return libc,ldso,orig_gdb

def exact_native_gdb(original:str,mode:str)->str:
    require(mode in ("watch","awatch"),"valid source watch modes")
    g=original.replace("KERNIX_G0_ORIGINAL_RELA14_NEXT_RAW_HIT",
                       "KERNIX_G0_RELA14_"+mode.upper()+"_RAW_HIT")
    if mode=="awatch":
        g=g.replace("watch -location *(unsigned long long *)"+TGT,
                    "awatch -location *(unsigned long long *)"+TGT)
    addon=(
      'printf "KERNIX_G0_RELA14_TLS_NATIVE_REGS x4=0x%lx x13=0x%lx x28=0x%lx\\n",$x4,$x13,$x28\n'
      'set $hdr=*(unsigned long long *)$x28\n'
      'set $off=*(unsigned int *)$hdr\n'
      'set $tail=$hdr+$off\n'
      'set $entry=*(unsigned long long *)($tail+8)\n'
      'set $size=*(unsigned long long *)($tail+16)\n'
      'set $cnt=*(unsigned int *)($tail+24)\n'
      'printf "KERNIX_G0_RELA14_TLS_FEX_JIT guest_entry=0x%lx source_size=0x%lx native_count=%u\\n",$entry,$size,$cnt\n'
      'x/16bx $entry\n'
    )
    return g.replace("x/i $pc-4\n","x/i $pc-4\n"+addon)

def validate_real_hardware(log:str,mode:str)->dict:
    require(mode in ("watch","awatch"),"real native hardware FEX guest mode")
    mark=once(r"^KERNIX_G0_ORIGINAL_RELA14_NEXT_SOURCE_ARM type=R_X86_64_TPOFF64 target="+
              TGT+r" initial=0x0 NO_NATIVE_PROOF=1$",log,
              "original source GDB armed zero qword")
    watch=("Hardware watchpoint 2:" if mode=="watch"
           else "Hardware access (read/write) watchpoint 2:")
    real=list(re.finditer(r"^"+re.escape(watch)+r" -location "+
         re.escape("*(unsigned long long *)")+TGT+r"$",log,re.M))
    require(len(real)==2,"both true native hardware watchpoint declaration and trap")
    pre=once(r"^"+TGT+r":\s+0x0000000000000000$",log,
             "unaltered original target before original GNU relocation")
    old=once(r"^Old value = 0$",log,"original ELF target prewrite raw value")
    new=once(r"^New value = ([0-9]+)$",log,
             "actual signed negative TLS target as unsigned GDB qword")
    require(int(new[1])==UNSIGNED,"native target observed -128 as true unsigned 64-bit write")
    hit=once(r"^KERNIX_G0_RELA14_"+mode.upper()+r"_RAW_HIT target="+TGT+
             r" pc=(0x[0-9a-f]+) x4=(0x[0-9a-f]+) x13=(0x[0-9a-f]+) x28=(0x[0-9a-f]+) RAW_NOT_INDEPENDENT=1$",
             log,"real original target hardware watch triggered post-ARM64 store")
    post=once(r"^"+TGT+r":\s+0xffffffffffffff80$",log,
              "exact observed final TLS signed -128 qword at correct guest target")
    instr=once(r"^\s*(0x[0-9a-f]+):\s+stlr\s+x4,\s*\[x10\]$",
               log,"genuine AArch64 STLR x4,[x10] native store not read")
    native=once(r"^KERNIX_G0_RELA14_TLS_NATIVE_REGS x4=(0x[0-9a-f]+) x13=(0x[0-9a-f]+) x28=(0x[0-9a-f]+)$",
                log,"same-trap actual Linux ARM64 source/value/FEX registers")
    jit=once(r"^KERNIX_G0_RELA14_TLS_FEX_JIT guest_entry=(0x[0-9a-f]+) source_size=(0x[0-9a-f]+) native_count=(\d+)$",
             log,"same true original FEX guest source JIT recording")
    op=once(r"^"+re.escape(JIT)+r":\s+0x48\s+0x89\s+0x06\s+0x8b\s+0x43\s+0x08",
            log,"exact original immutable GNU x86 loader guest source opcode byte dump")
    footer=once(r"^KERNIX_G0_ORIGINAL_RELA14_NEXT_ZERO_NATIVE_ATTESTATIONS=1$",log,
                "raw-only guest log footer")
    require(mark.start()<pre.start()<real[0].start()<real[1].start()
            <old.start()<new.start()<hit.start()<post.start()<instr.start()
            <native.start()<jit.start()<op.start()<footer.start(),
            "source-locked chronological ARM64 guest target arm/write/STLR/JIT order")
    pc=int(hit[1],16)
    require(pc>=0xffff00000000 and int(instr[1],16)==pc-4,
            "actual AArch64 hardware trap PC at immediately following STLR")
    require(int(hit[2],16)==UNSIGNED and
            int(native[1],16)==UNSIGNED and
            native[2]=="0x804000000" and
            int(native[3],16)>=0xffff00000000 and
            int(hit[4],16)==int(native[3],16),
            "native AArch64 source x4 really stored -128 and FEX context exact")
    require(jit[1]==JIT and jit[2]=="0x3" and int(jit[3])==2,
            "exact original x86 3-byte GNU source instruction, two compiled native instructions")
    return {
      "genuine_source_index":14,
      "original_table":"DT_RELA",
      "original_relocation_type":"R_X86_64_TPOFF64",
      "source_symbol_index":0,
      "original_source_signed_addend":8,
      "source_original_qword":"0x0",
      "observed_native_writer_qword":NEW,
      "observed_native_signed_value":-128,
      "original_guest_hardware_write_target":TGT,
      "native_real_AArch64_store":"stlr x4, [x10]",
      "native_store_PC":hex(pc-4),
      "native_source_value_register":"x4",
      "native_source_register_value":NEW,
      "original_x86_GNU_loader_JIT_entry":JIT,
      "original_GNU_x86_loader_store_opcode":"488906",
      "original_GNU_x86_loader_store_instruction":"mov qword ptr [rsi], rax",
      "native_real_FEX_JIT_instruction_count":2,
      "source_guest_x86_to_ARM64_hardware_writer_proven":True,
      "original_TLS_module_offset_and_all_TP_semantics_proven":False,
      "original_all_147_same_guest_relocations_proven":False,
    }

def authenticate_native(native:Path,orig_gdb:str)->tuple[str,str,dict,dict]:
    logs={}
    metas={}
    for mode in ("watch","awatch"):
        prefix=PFX+mode+"-JIT-RAW"
        original=exact_native_gdb(orig_gdb,mode)
        require(regular(native/(prefix+".gdb")).decode()==original,
                "only original GNU source watch/awatch and safe JIT logging inserted "+mode)
        exitcode=regular(native/(prefix+".exit")).decode().strip()
        require(exitcode=="0","real Linux ARM64 FEX GDB debugger exit status 0 "+mode)
        log=regular(native/(prefix+".log")).decode(errors="replace")
        require(300<len(log)<600000,"bounded actual original FEX native GDB raw log "+mode)
        meta=json.loads(regular(native/(prefix+".json")))
        require(meta["schema"]=="kernix.g0.original-rela14-tpoff64-sym0-raw-"+mode+".v1"
                and meta["original_index"]==14
                and meta["original_table"]=="DT_RELA"
                and meta["original_type"]=="R_X86_64_TPOFF64"
                and meta["original_symbol_index"]==0
                and meta["original_signed_addend"]==8
                and meta["original_guest_target"]==TGT
                and meta["original_qword"]=="0x0"
                and meta["mode"]==mode
                and meta["native_arm_seen"] is True
                and meta["raw_native_hardware_declaration_and_hit_count"]==2
                and meta["raw_post_arm_hardware_access_candidate"] is True
                and meta["raw_old_qword"]=="0"
                and meta["raw_new_qword"]==str(UNSIGNED)
                and meta["raw_native_x4"]==NEW
                and meta["raw_FEX_JIT_original_source_guest_entry"]==JIT
                and meta["raw_FEX_JIT_original_guest_size"]=="0x3"
                and meta["previous_certified_native_writer_target_count"]==76
                and meta["TLS_runtime_value_or_tp_module_offset_proven"] is False
                and meta["native_source_hardware_write_independently_attested"] is False
                and meta["all_147_same_guest_completed"] is False
                and meta["Android_Bionic_Wine_Proton_games_proven"] is False
                and meta["gdb_exit_code"]==0
                and meta["real_native_fex_raw_log_sha256"]==hashlib.sha256(log.encode()).hexdigest(),
                "real original GNU TLS watch source register and SHA log state "+mode)
        logs[mode]=log
        metas[mode]=meta
    require(logs["watch"]!=logs["awatch"],
            "two independently executed real original FEX native guest process trace types")
    return logs["watch"],logs["awatch"],metas["watch"],metas["awatch"]

def forged_cases(raw:str)->list[str]:
    hit_line=once(r"^KERNIX_G0_RELA14_WATCH_RAW_HIT target="+TGT+
                  r" pc=(0x[0-9a-f]+) x4=",raw,"native original TLS false-PC control")
    true_hit_prefix="KERNIX_G0_RELA14_WATCH_RAW_HIT target="+TGT+" pc="+hit_line[1]+" x4="
    fake_hit_prefix="KERNIX_G0_RELA14_WATCH_RAW_HIT target="+TGT+" pc=0x1 x4="
    pairs=[
      ("false_arm","initial=0x0 NO_NATIVE_PROOF=1","initial=0x1 NO_NATIVE_PROOF=1"),
      ("no_original_zero",TGT+":\t0x0000000000000000",TGT+":\t0x0000000000000001"),
      ("missing_true_hw_trap","Hardware watchpoint 2: -location *(unsigned long long *)"+TGT,
                               "Hardware watchpoint 2: MISSING_REAL_NATIVE_TRAP"),
      ("false_new_qword","New value = "+str(UNSIGNED),"New value = 0"),
      ("false_native_target", "KERNIX_G0_RELA14_WATCH_RAW_HIT target="+TGT,
                              "KERNIX_G0_RELA14_WATCH_RAW_HIT target=0x1"),
      ("wrong_guest_native_PC",true_hit_prefix,fake_hit_prefix),
      ("read_disguised_as_write","stlr\tx4, [x10]","ldar\tx4, [x10]"),
      ("wrong_native_qword_register","KERNIX_G0_RELA14_TLS_NATIVE_REGS x4="+NEW,
                                     "KERNIX_G0_RELA14_TLS_NATIVE_REGS x4=0x0"),
      ("wrong_FEX_state_x28"," x28=0xffffc0001140"," x28=0x1"),
      ("false_source_jit","KERNIX_G0_RELA14_TLS_FEX_JIT guest_entry="+JIT,
                          "KERNIX_G0_RELA14_TLS_FEX_JIT guest_entry=0x1"),
      ("wrong_jit_instruction_size","source_size=0x3","source_size=0x4"),
      ("wrong_jit_instruction_count","native_count=2","native_count=1"),
      ("forged_first_GNU_byte",JIT+":\t0x48\t0x89\t0x06",
                               JIT+":\t0x90\t0x89\t0x06"),
      ("forged_second_GNU_byte",JIT+":\t0x48\t0x89\t0x06",
                                JIT+":\t0x48\t0x90\t0x06"),
      ("wrong_target_after",TGT+":\t0xffffffffffffff80",
                             TGT+":\t0x0000000000000000"),
      ("invalid_footer","KERNIX_G0_ORIGINAL_RELA14_NEXT_ZERO_NATIVE_ATTESTATIONS=1",
                        "KERNIX_G0_ORIGINAL_RELA14_NEXT_ZERO_NATIVE_ATTESTATIONS=0"),
    ]
    require(len(pairs)==16,"exact sixteen distinct falsified original GNU target logs")
    rejected=[]
    for name,old,new in pairs:
        require(old in raw and old!=new,"counterfeit premiss actually in raw true hardware trace "+name)
        forged=raw.replace(old,new,1)
        require(forged!=raw,"counterfeit changed source log "+name)
        try: validate_real_hardware(forged,"watch")
        except AssertionError:rejected.append(name)
        else:raise AssertionError("FAIL OPEN: allowed forged original TLS ARM64 FEX writer trace "+name)
    require(len(rejected)==16 and len(set(rejected))==16,
            "all sixteen forged original native source writer logs rejected")
    return rejected

def run(triad:Path,source:Path,native:Path,prior76:Path,out:Path)->dict:
    libc,ldso,orig_gdb=authenticate_sources(triad,source,prior76)
    w,a,wm,am=authenticate_native(native,orig_gdb)
    rw=validate_real_hardware(w,"watch")
    ra=validate_real_hardware(a,"awatch")
    require(rw["observed_native_writer_qword"]==ra["observed_native_writer_qword"]==NEW
            and rw["original_x86_GNU_loader_JIT_entry"]==ra["original_x86_GNU_loader_JIT_entry"]==JIT
            and rw["native_real_AArch64_store"]==ra["native_real_AArch64_store"]=="stlr x4, [x10]"
            and rw["original_guest_hardware_write_target"]==ra["original_guest_hardware_write_target"]==TGT,
            "two genuine real FEX guest processes agree on exact original GNU TPOFF64 writer")
    bs=bytes.fromhex(rw["original_GNU_x86_loader_store_opcode"])
    off=source_offset(ldso,int(JIT,16)-LDSO_BIAS,len(bs),5)
    require(ldso[off:off+3]==bs==OPCODE
            and (bs[0],bs[1],bs[2])==(0x48,0x89,0x06),
            "original GNU x86 MOV RAX -> [RSI] source bytes sha verified")
    rejected=forged_cases(w)
    result={
      "schema":"kernix.g0.original-gnu-dt-rela14-tpoff64-real-native-arm64-fex-independent-writer.v1",
      "original_source_libc_sha256":LIBC_SHA,
      "original_source_ldso_sha256":LDSO_SHA,
      "original_source_indices":[14],
      "prior_independently_certified_native_hardware_target_count":76,
      "new_distinct_original_GNU_native_hardware_writer_targets":1,
      "unique_original_libc_native_hardware_writer_target_count":77,
      "two_separate_FEX_guest_original_TLS_hardware_write_processes":True,
      "one_original_GNU_RELA14_TLS_TPOFF64_native_writer_receipt":rw,
      "sixteen_fake_original_TLS_native_hardware_traces_rejected":rejected,
      "true_native_watch_raw_log_sha256":wm["real_native_fex_raw_log_sha256"],
      "true_native_awatch_raw_log_sha256":am["real_native_fex_raw_log_sha256"],
      "original_undefined_symbol_zero_TLS_model_and_runtime_module_offset_fully_proven":False,
      "one_single_FEX_guest_process_for_all_77_writers_proven":False,
      "original_147_relocations_all_in_single_guest_proven":False,
      "original_GNU_CALL_RET_stack_READ_for_this_TPOFF64_writer_proven":False,
      "Android_Bionic_Wine_Proton_games_proven":False,
    }
    require(len(rejected)==16 and rw["source_guest_x86_to_ARM64_hardware_writer_proven"] is True,
            "one source verified writer proof and anti-forgery controls")
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_GNU_TLS_TPOFF64_RELA14_REAL_ARM64_FEX_NATIVE_HARDWARE_WRITER_INDEPENDENTLY_ATTESTED_77_147_NO_ANDROID")
    return result

if __name__=="__main__":
    require(len(sys.argv)==6,
            "usage original-GNU-triad original-TLS-source actual-FEX-native-logs prior76-ledger output")
    run(*map(Path,sys.argv[1:]))
