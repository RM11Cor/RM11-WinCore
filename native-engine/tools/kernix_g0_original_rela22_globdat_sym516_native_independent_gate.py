#!/usr/bin/env python3
"""Fail-closed original GNU libc DT_RELA22 GLOB_DAT free native writer.

Proves one source qword store via independent two-process Linux ARM64 FEX hardware
WATCH/AWATCH and 16 falsified-trace controls. Does NOT prove complete dynamic
preemption/versioning, one process for 147 relocations, Android or game support.
"""
from __future__ import annotations
import hashlib
import json
import re
import sys
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA, LDSO_SHA, decode_original_libc, classify,
)
from kernix_g0_original_dt_rela22_source_type_and_writer_plan_after_84 import original_dynsym
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import LDSO_BIAS

SRC = "original-libc-DT-RELA22-next-actual-source-type-symbol-hardware-writer-NO-NATIVE-PROOF"
PFX = "original-libc-DT-RELA22-GLOBDAT-SYM516-REAL-ARM64-FEX-"
OUT = "original-libc-DT-RELA22-GLOBDAT-Sym516-One-Original-FEX-ARM64-Independent-Writer-PROOF.json"
TGT = "0x804202e08"
NEW = "0x8040adbe0"
POST = "0x00000008040adbe0"
UNSIGNED = int(NEW, 16)
JIT = "0x80100fb8b"
OPCODE = bytes.fromhex("4c8908")
REG = "KERNIX_G0_RELA22_GLOBDAT_SYM516_NATIVE_REGS"
JIT_MARK = "KERNIX_G0_RELA22_GLOBDAT_SYM516_FEX_JIT"

def require(ok, label):
    if not ok:
        raise AssertionError("GNU_GLOBDAT22_FEX_INDEPENDENT_FAIL_CLOSED: " + label)

def regular(path):
    require(path.is_file() and not path.is_symlink(), "regular input " + str(path))
    b = path.read_bytes()
    require(1 <= len(b) < 20_000_000, "bounded input " + str(path))
    return b

def once(pattern, text, label):
    hits = list(re.finditer(pattern, text, re.M))
    require(len(hits) == 1, "exactly one " + label)
    return hits[0]

def authenticate_sources(triad, source, prior84):
    libc = regular(triad / "lib/x86_64-linux-gnu/libc.so.6")
    ldso = regular(triad / "lib64/ld-linux-x86-64.so.2")
    require(len(libc) == 2118168 and hashlib.sha256(libc).hexdigest() == LIBC_SHA,
            "original GNU libc SHA256")
    require(len(ldso) == 235408 and hashlib.sha256(ldso).hexdigest() == LDSO_SHA,
            "original GNU ldso SHA256")
    rows = decode_original_libc(libc)
    require(classify(rows)["original_total_RELA_and_JMPREL"] == 147,
            "full original 147 relocation source manifest")
    r = rows[22]
    require((r["index"], r["table"], r["table_index"], r["r_type"], r["r_sym"],
             r["r_offset"], r["r_addend"], r["source_guest_target"],
             r["original_source_qword"]) ==
            (22, "DT_RELA", 22, 6, 516, "0x202e08", 0, TGT, "0x0"),
            "unaltered GLOB_DAT original source tuple")
    q = source_offset(libc, 0x202e08, 8, 6, nonexec=True)
    require(libc[q:q+8] == bytes(8), "unaltered original zero qword")
    opoff = source_offset(ldso, int(JIT,16)-LDSO_BIAS, len(OPCODE), 5)
    require(ldso[opoff:opoff+3] == OPCODE, "original GNU x86 mov [RAX],R9 bytes 4c8908")
    sym = original_dynsym(libc, 516)
    require(sym["symbol_name"] == "free"
            and sym["symbol_index"] == 516
            and sym["symbol_binding"] == 1
            and sym["symbol_original_st_value"] == "0xadbe0"
            and sym["symbol_original_st_size"] == 271
            and sym["symbol_defined_in_this_source_elf"] is True
            and sym["source_definition_in_BSS_if_PT_LOAD_known"] is False
            and sym["source_definition_address_candidate_if_non_TLS"] == NEW
            and sym["runtime_symbol_lookup_or_versioned_preemption_proven"] is False,
            "independent SHA-locked original GLOB_DAT PT_LOAD symbol source")
    d = json.loads(regular(source/(SRC+".json")))
    require(d["original_source_libc_sha256"] == LIBC_SHA
            and d["original_source_ldso_sha256"] == LDSO_SHA
            and d["original_source_index"] == 22
            and d["original_table"] == "DT_RELA"
            and d["original_table_ordinal"] == 22
            and d["original_relocation_type_id"] == 6
            and d["original_relocation_type"] == "R_X86_64_GLOB_DAT"
            and d["original_symbol"] == sym
            and d["original_source_signed_addend"] == 0
            and d["original_source_relocation_offset"] == "0x202e08"
            and d["original_source_initial_qword"] == "0x0"
            and d["original_guest_target"] == TGT
            and d["original_84_native_source_writers_independently_attested"] == 84
            and d["new_native_writer_target_evidence_from_this_source_discovery"] == 0
            and d["source_only_no_native_writer_proven"] is True
            and d["original_symbol_dynamic_binding_proven"] is False
            and d["Android_Bionic_Wine_Proton_games_proven"] is False,
            "exact independent source22 metadata with unproven dynamic semantics")
    original = regular(source/(SRC+".gdb")).decode()
    require(original.startswith("set pagination off\nset confirm off\n")
            and original.count("watch -location *(unsigned long long *)"+TGT) == 1
            and original.count("KERNIX_G0_ORIGINAL_RELA22_NEXT_RAW_HIT") == 1
            and original.count("x/i $pc-4\n") == 1,
            "original single GLOB_DAT hardware watch script")
    p = json.loads(regular(prior84/
        "original-libc-147-source-batch-native-proof-ledger84-NO-NEW-HW-RUN.json"))
    require(p["schema"] ==
            "kernix.g0.original-gnu-libc-147-relocation-cohort-native-writer-ledger84.v1"
            and p["source_original_libc_sha256"] == LIBC_SHA
            and p["source_original_ldso_sha256"] == LDSO_SHA
            and p["previously_independently_attested_native_writer_target_count"] == 84
            and p["remaining_requires_separate_native_hardware_evidence"] == 63
            and p["remaining_non_IFUNC_DT_RELA_indices"] == list(range(22,85))
            and p["remaining_IFUNC_indices"] == []
            and 22 not in p["previously_attested_original_source_indices"]
            and p["native_GNU_DT_RELA21_GLOBDAT_sym1042___libc_single_threaded_REAL_FEX_ARM64_STORE_independently_proven"] is True
            and p["all_147_same_guest_native_execution_proven"] is False
            and p["Android_Bionic_Wine_Proton_games_proven"] is False,
            "independently pinned 84 unique previous writer targets")
    return original

def exact_native_gdb(original, mode):
    require(mode in ("watch", "awatch"), "original watch or awatch")
    text = original.replace("KERNIX_G0_ORIGINAL_RELA22_NEXT_RAW_HIT",
                            "KERNIX_G0_RELA22_"+mode.upper()+"_RAW_HIT")
    if mode == "awatch":
        text = text.replace("watch -location *(unsigned long long *)"+TGT,
                            "awatch -location *(unsigned long long *)"+TGT)
    addon = (
      'printf "'+REG+' x4=0x%lx x13=0x%lx x28=0x%lx\\n",$x4,$x13,$x28\n'
      'set $hdr=*(unsigned long long *)$x28\n'
      'set $off=*(unsigned int *)$hdr\n'
      'set $tail=$hdr+$off\n'
      'set $entry=*(unsigned long long *)($tail+8)\n'
      'set $size=*(unsigned long long *)($tail+16)\n'
      'set $cnt=*(unsigned int *)($tail+24)\n'
      'printf "'+JIT_MARK+' guest_entry=0x%lx source_size=0x%lx native_count=%u\\n",$entry,$size,$cnt\n'
      'x/16bx $entry\n'
    )
    return text.replace("x/i $pc-4\n", "x/i $pc-4\n"+addon)

def validate_real_hardware(log, mode):
    require(mode in ("watch","awatch"), "real guest mode")
    armed = once(r"^KERNIX_G0_ORIGINAL_RELA22_NEXT_SOURCE_ARM type=R_X86_64_GLOB_DAT target="+TGT+
                 r" initial=0x0 NO_NATIVE_PROOF=1$", log, "source lock armed")
    decl = ("Hardware watchpoint 2:" if mode=="watch"
            else "Hardware access (read/write) watchpoint 2:")
    hw = list(re.finditer(r"^"+re.escape(decl)+r" -location "+
                        re.escape("*(unsigned long long *)")+TGT+r"$", log, re.M))
    require(len(hw) == 2, "real hardware declaration and trap")
    pre = once(r"^"+TGT+r":\s+0x0000000000000000$", log, "prewrite zero qword")
    old = once(r"^Old value = 0$", log, "old zero")
    new = once(r"^New value = ([0-9]+)$", log, "observed new value")
    require(int(new[1]) == UNSIGNED, "native resolved symbol address observed, not assumed")
    hit = once(r"^KERNIX_G0_RELA22_"+mode.upper()+r"_RAW_HIT target="+TGT+
               r" pc=(0x[0-9a-f]+) x4=(0x[0-9a-f]+) x13=(0x[0-9a-f]+) x28=(0x[0-9a-f]+) RAW_NOT_INDEPENDENT=1$",
               log, "actual hardware poststore registers")
    post = once(r"^"+TGT+r":\s+"+POST+r"$", log, "actual native final qword")
    instr = once(r"^\s*(0x[0-9a-f]+):\s+stlr\s+x13,\s*\[x4\]$", log,
                 "actual native STLR x13,[x4] store")
    regs = once(r"^"+REG+r" x4=(0x[0-9a-f]+) x13=(0x[0-9a-f]+) x28=(0x[0-9a-f]+)$",
                log, "actual ARM64 value and address registers")
    jit = once(r"^"+JIT_MARK+r" guest_entry=(0x[0-9a-f]+) source_size=(0x[0-9a-f]+) native_count=(\d+)$",
               log, "exact FEX JIT source block")
    x86 = once(r"^"+re.escape(JIT)+r":\s+0x4c\s+0x89\s+0x08\s+0x8b\s+0x43\s+0x08",
               log, "SHA-locked original x86 GNU source 4c8908")
    footer = once(r"^KERNIX_G0_ORIGINAL_RELA22_NEXT_ZERO_NATIVE_ATTESTATIONS=1$",
                  log, "raw-only footer")
    require(armed.start() < pre.start() < hw[0].start() < hw[1].start()
            < old.start() < new.start() < hit.start() < post.start()
            < instr.start() < regs.start() < jit.start() < x86.start() < footer.start(),
            "real source watch -> native trap -> qword -> STLR -> original guest JIT chronology")
    pc = int(hit[1],16)
    require(pc>=0xffff00000000 and int(instr[1],16)==pc-4,
            "real ARM64 store trap immediately follows STLR")
    require(int(hit[2],16)==int(TGT,16)
            and int(hit[3],16)==UNSIGNED
            and int(regs[1],16)==int(TGT,16)
            and int(regs[2],16)==UNSIGNED
            and int(regs[3],16)>=0xffff00000000
            and int(hit[4],16)==int(regs[3],16),
            "native x4 destination and x13 source value match actual GLOB_DAT memory write")
    require(jit[1]==JIT and jit[2]=="0x3" and int(jit[3])==2,
            "3 exact source x86 bytes and two native JIT instructions")
    return {
        "genuine_source_index":22,
        "original_table":"DT_RELA",
        "original_relocation_type":"R_X86_64_GLOB_DAT",
        "source_symbol_index":516,
        "source_symbol_name":"free",
        "original_source_signed_addend":0,
        "source_original_qword":"0x0",
        "observed_native_writer_qword":NEW,
        "observed_native_pointer_value":UNSIGNED,
        "source_defined_ELF_address_candidate":NEW,
        "actual_two_guest_native_value_matches_original_ELF_candidate":True,
        "original_guest_hardware_write_target":TGT,
        "native_real_AArch64_store":"stlr x13, [x4]",
        "native_store_PC":hex(pc-4),
        "native_source_value_register":"x13",
        "native_source_register_value":NEW,
        "native_target_address_register":"x4",
        "native_target_register_value":TGT,
        "original_x86_GNU_loader_JIT_entry":JIT,
        "original_GNU_x86_loader_store_opcode":"4c8908",
        "original_GNU_x86_loader_store_instruction":"mov qword ptr [rax], r9",
        "native_real_FEX_JIT_instruction_count":2,
        "source_guest_x86_to_ARM64_hardware_writer_proven":True,
        "full_GLOB_DAT_symbol_scope_preemption_versioning_proven":False,
        "original_all_147_same_guest_relocations_proven":False,
    }

def authenticate_native(native, orig_gdb):
    logs={}
    meta={}
    for mode in ("watch","awatch"):
        prefix=PFX+mode+"-JIT-RAW"
        require(regular(native/(prefix+".gdb")).decode()==exact_native_gdb(orig_gdb,mode),
                "unaltered source GDB plus only original native trap trace "+mode)
        require(regular(native/(prefix+".exit")).decode().strip()=="0",
                "real GDB ARM64 FEX guest exit status zero "+mode)
        text=regular(native/(prefix+".log")).decode(errors="replace")
        require(300 < len(text) < 600_000, "real native FEX guest raw trace "+mode)
        data=json.loads(regular(native/(prefix+".json")))
        require(data["schema"]=="kernix.g0.original-rela22-globdat-sym516-raw-"+mode+".v1"
                and data["original_index"]==22
                and data["original_table"]=="DT_RELA"
                and data["original_type"]=="R_X86_64_GLOB_DAT"
                and data["original_symbol_index"]==516
                and data["original_signed_addend"]==0
                and data["original_guest_target"]==TGT
                and data["original_qword"]=="0x0"
                and data["mode"]==mode
                and data["native_arm_seen"] is True
                and data["raw_native_hardware_declaration_and_hit_count"]==2
                and data["raw_post_arm_hardware_access_candidate"] is True
                and data["raw_old_qword"]=="0"
                and data["raw_new_qword"]==str(UNSIGNED)
                and data["raw_native_x4"]==TGT
                and data["raw_native_x13"]==NEW
                and data["raw_FEX_JIT_original_source_guest_entry"]==JIT
                and data["raw_FEX_JIT_original_guest_size"]=="0x3"
                and data["original_defined_symbol_name"]=="free"
                and data["original_definition_candidate_from_ELF"]==NEW
                and data["previous_certified_native_writer_target_count"]==84
                and data["runtime_binding_or_preemption_proven"] is False
                and data["source_only_candidate_must_not_replace_observed_native_qword"] is True
                and data["native_source_hardware_write_independently_attested"] is False
                and data["all_147_same_guest_completed"] is False
                and data["Android_Bionic_Wine_Proton_games_proven"] is False
                and data["gdb_exit_code"]==0
                and data["real_native_fex_raw_log_sha256"]==hashlib.sha256(text.encode()).hexdigest(),
                "independent per-guest raw metadata, exact registers and SHA256 "+mode)
        logs[mode]=text
        meta[mode]=data
    require(logs["watch"]!=logs["awatch"],"two independent guest processes")
    return logs,meta

def forged_cases(raw):
    hit=once(r"^KERNIX_G0_RELA22_WATCH_RAW_HIT target="+TGT+
             r" pc=(0x[0-9a-f]+) x4=",raw,"real native trigger for fake-PC tests")
    true_hit="KERNIX_G0_RELA22_WATCH_RAW_HIT target="+TGT+" pc="+hit[1]+" x4="
    fake_hit="KERNIX_G0_RELA22_WATCH_RAW_HIT target="+TGT+" pc=0x1 x4="
    pairs=[
      ("false_source_arm","initial=0x0 NO_NATIVE_PROOF=1","initial=0x1 NO_NATIVE_PROOF=1"),
      ("false_old_qword",TGT+":\t0x0000000000000000",TGT+":\t0x0000000000000001"),
      ("missing_real_hardware_trap","Hardware watchpoint 2: -location *(unsigned long long *)"+TGT,
                                     "Hardware watchpoint 2: MISSING_NATIVE_TRAP"),
      ("false_written_qword","New value = "+str(UNSIGNED),"New value = 0"),
      ("false_source_target","KERNIX_G0_RELA22_WATCH_RAW_HIT target="+TGT,
                             "KERNIX_G0_RELA22_WATCH_RAW_HIT target=0x1"),
      ("wrong_native_PC",true_hit,fake_hit),
      ("fake_read_not_store","stlr\tx13, [x4]","ldar\tx13, [x4]"),
      ("wrong_native_value_register",REG+" x4="+TGT+" x13="+NEW,
                                     REG+" x4="+TGT+" x13=0x0"),
      ("wrong_native_FEX_context_x28"," x28=0xffffc0001140"," x28=0x1"),
      ("false_guest_source_JIT",JIT_MARK+" guest_entry="+JIT,JIT_MARK+" guest_entry=0x1"),
      ("wrong_original_guest_size","source_size=0x3","source_size=0x4"),
      ("wrong_native_instruction_count","native_count=2","native_count=1"),
      ("corrupt_original_x86_first_byte",JIT+":\t0x4c\t0x89\t0x08",
                                         JIT+":\t0x90\t0x89\t0x08"),
      ("corrupt_original_x86_second_byte",JIT+":\t0x4c\t0x89\t0x08",
                                          JIT+":\t0x4c\t0x90\t0x08"),
      ("false_target_after",TGT+":\t"+POST,TGT+":\t0x0000000000000000"),
      ("invalid_original_source_footer","KERNIX_G0_ORIGINAL_RELA22_NEXT_ZERO_NATIVE_ATTESTATIONS=1",
                                        "KERNIX_G0_ORIGINAL_RELA22_NEXT_ZERO_NATIVE_ATTESTATIONS=0"),
    ]
    require(len(pairs)==16,"exact 16 forged source trace controls")
    denied=[]
    for name,old,new in pairs:
        require(old in raw and old!=new, "negative trace premise really exists "+name)
        modified=raw.replace(old,new,1)
        try:
            validate_real_hardware(modified,"watch")
        except AssertionError:
            denied.append(name)
        else:
            raise AssertionError("FORGED GLOB_DAT22 HARDWARE TRACE ACCEPTED: "+name)
    require(len(denied)==16 and len(set(denied))==16,
            "all 16 counterfeit native hardware proofs rejected")
    return denied

def run(triad,source,native,prior84,out):
    orig_gdb=authenticate_sources(triad,source,prior84)
    logs,metas=authenticate_native(native,orig_gdb)
    w=validate_real_hardware(logs["watch"],"watch")
    a=validate_real_hardware(logs["awatch"],"awatch")
    require(w["observed_native_writer_qword"]==a["observed_native_writer_qword"]==NEW
            and w["original_x86_GNU_loader_JIT_entry"]==a["original_x86_GNU_loader_JIT_entry"]==JIT
            and w["native_real_AArch64_store"]==a["native_real_AArch64_store"]=="stlr x13, [x4]"
            and w["original_guest_hardware_write_target"]==a["original_guest_hardware_write_target"]==TGT,
            "two independent guest runs agree on original GLOB_DAT native writer")
    rejected=forged_cases(logs["watch"])
    result={
        "schema":"kernix.g0.original-gnu-dt-rela22-globdat-sym516-real-native-arm64-fex-independent-writer.v1",
        "original_source_libc_sha256":LIBC_SHA,
        "original_source_ldso_sha256":LDSO_SHA,
        "original_source_indices":[22],
        "prior_independently_certified_native_hardware_target_count":84,
        "new_distinct_original_GNU_native_hardware_writer_targets":1,
        "unique_original_libc_native_hardware_writer_target_count":85,
        "two_separate_FEX_guest_original_GLOBDAT_hardware_write_processes":True,
        "one_original_GNU_RELA22_GLOBDAT_Sym516_native_writer_receipt":w,
        "sixteen_fake_original_GLOBDAT_native_hardware_traces_rejected":rejected,
        "true_native_watch_raw_log_sha256":metas["watch"]["real_native_fex_raw_log_sha256"],
        "true_native_awatch_raw_log_sha256":metas["awatch"]["real_native_fex_raw_log_sha256"],
        "original_GLOB_DAT_full_dynamic_symbol_scope_preemption_and_versioning_proven":False,
        "one_single_FEX_guest_process_for_all_85_writers_proven":False,
        "original_147_relocations_all_in_single_guest_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    require(len(rejected)==16 and w["source_guest_x86_to_ARM64_hardware_writer_proven"] is True,
            "independent one original GNU GLOB_DAT writer verified")
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_GNU_GLOBDAT_RELA22_REAL_ARM64_FEX_NATIVE_HARDWARE_WRITER_INDEPENDENTLY_ATTESTED_85_147_NO_ANDROID")
    return result

if __name__=="__main__":
    require(len(sys.argv)==6,"usage original-GNU-triad original-GLOBDAT22-source FEX-raw prior84-ledger output")
    run(*map(Path,sys.argv[1:]))
