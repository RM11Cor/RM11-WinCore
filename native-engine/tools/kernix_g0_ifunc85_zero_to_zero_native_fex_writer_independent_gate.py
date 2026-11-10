#!/usr/bin/env python3
"""Independent fail-closed original GNU IFUNC85 ZERO->ZERO hardware writer check.

A raw GDB awatch by itself is NOT a writer proof. This demands exact SHA-pinned
GNU x86 DT_RELA index85 source, arm-before-hit chronology, native AArch64 STLR,
x4=zero, x19=the original guest target, and FEX JIT guest entry at the original
GNU ld-linux STORE (49 89 06). No CALL/RET stack read or Android claim.
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
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import (
    STORE, CALL, CALLER_RETURN, LIBC_BIAS, LDSO_BIAS,
)

TARGET="0x8042014c8"
SOURCE="original-libc-IFUNC85-DT_RELA-zero-source-only-NO-NATIVE-PROOF"
RAW="original-libc-IFUNC85-DT_RELA-zero-REAL-ARM64-FEX-JIT-RAW-AWATCH"
PREV="original-libc-IFUNC145-146-two-independent-native-hardware-writer-batch-PROOF.json"
OUT="original-libc-IFUNC85-DT_RELA-zero-native-FEX-HW-WRITER-INDEPENDENT-PROOF.json"


def require(ok:bool,what:str)->None:
    if not ok:
        raise AssertionError("IFUNC85 REAL NATIVE ZERO-TO-ZERO WRITER FAIL-CLOSED: "+what)


def exact(pattern:str,src:str,label:str)->re.Match:
    m=list(re.finditer(pattern,src,re.MULTILINE))
    require(len(m)==1,label+" must occur exactly once")
    return m[0]


def file(path:Path,minimum:int=1,maximum:int=20_000_000)->bytes:
    require(path.is_file() and not path.is_symlink(), "regular file "+str(path))
    data=path.read_bytes()
    require(minimum<=len(data)<=maximum, "bounded bytes "+str(path))
    return data


def source_auth(triad:Path,source:Path,prev:Path)->tuple[list[dict],str,str]:
    libc=file(triad/"lib/x86_64-linux-gnu/libc.so.6")
    ldso=file(triad/"lib64/ld-linux-x86-64.so.2")
    require(len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA,
            "unaltered original x86 libc bytes")
    require(len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA,
            "unaltered original x86 ld-linux bytes")
    rows=decode_original_libc(libc)
    require(classify(rows)["original_total_RELA_and_JMPREL"]==147,
            "original 147 source entries")
    row=rows[85]
    require((row["index"],row["table"],row["table_index"],
             row["r_type"],row["r_sym"],row["original_source_qword"])==
            (85,"DT_RELA",85,37,0,"0x0"),"single GNU DT_RELA IRELATIVE zero relocation")
    require(row["r_offset"]=="0x2014c8" and row["r_addend"]==0xc8570
            and row["source_guest_target"]==TARGET,
            "original GNU IFUNC85 resolver/target offset")
    offset=source_offset(libc,0x2014c8,8,6,nonexec=True)
    require(libc[offset:offset+8]==bytes(8),"actual source target zero QWORD")
    for addr,hx in ((0xc8570,"f30f1efa"),(0xc860b,"31c0"),(0xc860d,"c3")):
        bs=bytes.fromhex(hx)
        off=source_offset(libc,addr,len(bs),5)
        require(libc[off:off+len(bs)]==bs,"unaltered resolver original x86 byte "+hex(addr))
    for addr,hx in ((CALL,"ffd0"),(CALLER_RETURN,"4883c318"),(STORE,"498906")):
        bs=bytes.fromhex(hx)
        off=source_offset(ldso,addr-LDSO_BIAS,len(bs),5)
        require(ldso[off:off+len(bs)]==bs,"unaltered x86 loader CALL/caller/STORE "+hex(addr))

    report=json.loads(file(source/(SOURCE+".json")).decode())
    require(report["original_relocation_index"]==85
            and report["original_table"]=="DT_RELA"
            and report["original_table_ordinal"]==85
            and report["original_guest_resolver"]==hex(LIBC_BIAS+row["r_addend"])
            and report["original_guest_target"]==TARGET
            and report["original_unmodified_target_qword"]=="0x0"
            and report["original_source_libc_sha256"]==LIBC_SHA
            and report["original_source_ldso_sha256"]==LDSO_SHA
            and report["source_only_not_native_hardware_proof"] is True
            and report["new_native_writer_attestations"]==0
            and report["previously_independently_certified_native_writers"]==61,
            "exact source-only preflight with no false native proof")
    original_gdb=file(source/(SOURCE+".gdb")).decode()
    require(original_gdb.startswith("set pagination off\nset confirm off\n"),
            "true multiline GDB script")
    require(original_gdb.count("watch -location *(unsigned long long *)"+TARGET)==1,
            "one exact GNU original writer-only source watch")

    previous=json.loads(file(prev/PREV).decode())
    require(previous["original_source_libc_sha256"]==LIBC_SHA
            and previous["original_source_ldso_sha256"]==LDSO_SHA
            and previous["original_source_indices"]==[145,146]
            and previous["prior_independently_certified_native_hardware_target_count"]==59
            and previous["new_distinct_original_GNU_native_hardware_writer_targets"]==2
            and previous["unique_original_libc_native_hardware_writer_target_count"]==61
            and len(previous["two_independent_native_hardware_writer_receipts"])==2
            and all(q["native_source_hardware_write_independently_attested"] is True
                    for q in previous["two_independent_native_hardware_writer_receipts"])
            and sum(map(len,previous["twenty_native_hardware_tamper_cases_rejected"].values()))==20
            and previous["one_single_FEX_guest_process_for_both_writes_proven"] is False
            and previous["all_147_original_libc_RELA_JMPREL_writers_same_process_proven"] is False
            and previous["Android_Bionic_Wine_Proton_games_proven"] is False,
            "immutable prior 61 real FEX writer target evidence")
    return rows,original_gdb,hashlib.sha256(libc).hexdigest()


def native_artifacts(native:Path,src_gdb:str)->tuple[str,dict]:
    actual_gdb=file(native/(RAW+".gdb")).decode()
    original_needle="watch -location *(unsigned long long *)"+TARGET
    changed=src_gdb.replace(original_needle,
                            "awatch -location *(unsigned long long *)"+TARGET).replace(
        "KERNIX_G0_IFUNC85_DT_RELA_RAW_UNVERIFIED_HIT",
        "KERNIX_G0_IFUNC85_DT_RELA_JIT_RAW_AWATCH_HIT",
    )
    marker="x/i $pc-4\n"
    require(changed.count(marker)==1, "original x86 GDB native instruction insertion anchor")
    injection=(
      'printf "KERNIX_G0_IFUNC85_NATIVE_REGS x4=0x%lx x19=0x%lx x28=0x%lx\\n",$x4,$x19,$x28\n'
      'set $hdr=*(unsigned long long *)$x28\n'
      'set $off=*(unsigned int *)$hdr\n'
      'set $tail=$hdr+$off\n'
      'set $entry=*(unsigned long long *)($tail+8)\n'
      'set $size=*(unsigned long long *)($tail+16)\n'
      'set $cnt=*(unsigned int *)($tail+24)\n'
      'printf "KERNIX_G0_IFUNC85_SOURCE_GNU_JIT guest_entry=0x%lx source_size=0x%lx native_count=%u\\n",$entry,$size,$cnt\n'
      'x/8bx $entry\n'
      f'x/8bx {hex(STORE)}\n'
    )
    require(actual_gdb==changed.replace(marker,marker+injection),
            "native GDB same original source with ONLY original awatch/JIT controls added")
    require(actual_gdb.count("awatch -location *(unsigned long long *)"+TARGET)==1,
            "only the exact immutable source target under awatch")
    require("rwatch -location" not in actual_gdb, "no fabricated read-only GDB watch")

    raw=file(native/(RAW+".log"),300,600000).decode(errors="replace")
    exitval=file(native/(RAW+".exit"),1,20).decode().strip()
    summary=json.loads(file(native/(RAW+".json")).decode())
    require(exitval=="0" and summary["process_gdb_exit_code"]==0,
            "native debugger must have completed")
    require(summary["original_source_target"]==TARGET
            and summary["original_source_qword"]=="0x0"
            and summary["source_ONLY_prior_61_native_writers"]==61
            and summary["raw_log_sha256"]==hashlib.sha256(raw.encode()).hexdigest(),
            "SHA-pinned actual raw FEX JIT diagnostic")
    require(summary["native_hardware_writer_independently_attested"] is False
            and summary["original_dt_rela_x86_guest_store_proven_by_this_RAW_probe"] is False
            and summary["all_147_same_guest_proven"] is False
            and summary["Android_Bionic_Wine_Proton_games_proven"] is False,
            "raw probe alone must not certify")
    return raw,summary


def verify(raw:str)->dict:
    arm=exact(r"^KERNIX_G0_IFUNC85_DT_RELA_CANDIDATE_PREWATCH target="+
              TARGET+r" original_zero=1 NOT_NATIVE_PROOF=1$",raw,"real source arm")
    points=list(re.finditer(
        r"^Hardware access \(read/write\) watchpoint 2: -location "+
        re.escape("*(unsigned long long *)")+TARGET+r"$",raw,re.MULTILINE))
    require(len(points)==2,"one genuine hardware arm declaration and one actual access trap")
    hit=exact(
        r"^KERNIX_G0_IFUNC85_DT_RELA_JIT_RAW_AWATCH_HIT target="+TARGET+
        r" pc=(0x[0-9a-f]+) x19=(0x[0-9a-f]+) RAW_NOT_INDEPENDENT=1$",
        raw,"actual original target ARM64 hardware trap")
    regs=exact(
        r"^KERNIX_G0_IFUNC85_NATIVE_REGS x4=(0x[0-9a-f]+) x19=(0x[0-9a-f]+) x28=(0x[0-9a-f]+)$",
        raw,"real x86 source FEX native registers")
    jit=exact(
        r"^KERNIX_G0_IFUNC85_SOURCE_GNU_JIT guest_entry=(0x[0-9a-f]+) source_size=(0x[0-9a-f]+) native_count=(\d+)$",
        raw,"authenticated native FEX JIT guest source")
    done=exact(r"^KERNIX_G0_IFUNC85_DT_RELA_NO_NATIVE_ATTESTATION=1$",raw,
               "raw guest-access footer")
    vals=list(re.finditer(r"^"+TARGET+r":\s+(0x[0-9a-f]{16})\s*$",raw,re.MULTILINE))
    require(len(vals)>=2 and vals[0].group(1)=="0x0000000000000000"
            and vals[1].group(1)=="0x0000000000000000",
            "zero original DT_RELA target at both arm and native access")
    require(re.search(r"^Value = 0$",raw,re.MULTILINE) is not None,
            "original GDB access trap read-back remains zero")
    require(arm.start()<vals[0].start()<points[0].start()<points[1].start()
            <hit.start()<vals[1].start()<regs.start()<jit.start()<done.start(),
            "single FEX guest true arm->hw access->native regs->GNU source JIT order")
    pc=int(hit[1],16)
    require(pc>=0xffff00000000 and int(hit[2],16)==int(TARGET,16),
            "native PC and x19 exact original target")
    require(int(regs[1],16)==0 and int(regs[2],16)==int(TARGET,16)
            and int(regs[3],16)>=0xffff00000000,
            "native AArch64 store zero value through x19 and FEX source state")
    require(jit[1]==hex(STORE) and jit[2]=="0x3" and int(jit[3])>=1,
            "native FEX JIT maps to original GNU x86 MOV RAX,[R14] STORE bytes")
    instr=exact(r"^\s*(0x[0-9a-f]+):\s+stlr\s+x4,\s*\[x19\]\s*$",
                raw,"actual native AArch64 store not mere read")
    require(int(instr[1],16)==pc-4 and hit.start()<instr.start()<regs.start(),
            "native hardware awatch fired exactly after source ARM64 STLR instruction")
    # GDB x/8bx prints 8 source bytes at both the real FEX JIT guest_entry
    # and the SHA-pinned ldso STORE address. Validate a single displayed
    # 0x49, 0x89, 0x06 original x86 opcode at the exact guest start.
    op=rf"^{re.escape(hex(STORE))}:\s+0x49\s+0x89\s+0x06\b"
    require(len(list(re.finditer(op,raw,re.MULTILINE)))>=1,
            "x86 GNU x/8bx JIT source exactly contains original MOV opcode")
    return {
        "original_source_index":85,
        "original_table":"DT_RELA",
        "original_guest_target":TARGET,
        "original_source_initial_qword":"0x0",
        "native_AArch64_STLR_PC":hex(pc-4),
        "native_AArch64_store":"stlr x4, [x19]",
        "native_AArch64_store_value":"0x0",
        "native_AArch64_target_address":TARGET,
        "FEX_original_GNU_guest_STORE_JIT_source":hex(STORE),
        "FEX_guest_STORE_source_size":jit[2],
        "native_hardware_awatch_READ_vs_WRITE_disambiguated_by_same_event_native_STLR":True,
        "native_source_hardware_write_independently_attested":True,
        "native_same_guest_RET_hardware_read_attested":False,
    }


def tamper_controls(raw:str)->list[str]:
    changes=[
        ("wrong_arm", "original_zero=1 NOT_NATIVE_PROOF=1",
         "original_zero=0 NOT_NATIVE_PROOF=1"),
        ("wrong_hw_target",
         "KERNIX_G0_IFUNC85_DT_RELA_JIT_RAW_AWATCH_HIT target="+TARGET,
         "KERNIX_G0_IFUNC85_DT_RELA_JIT_RAW_AWATCH_HIT target=0x1"),
        ("wrong_real_x19",
         "KERNIX_G0_IFUNC85_NATIVE_REGS x4=0x0 x19="+TARGET,
         "KERNIX_G0_IFUNC85_NATIVE_REGS x4=0x0 x19=0x1"),
        ("wrong_store_value",
         "KERNIX_G0_IFUNC85_NATIVE_REGS x4=0x0",
         "KERNIX_G0_IFUNC85_NATIVE_REGS x4=0x1"),
        ("wrong_source_jit",
         "SOURCE_GNU_JIT guest_entry="+hex(STORE),
         "SOURCE_GNU_JIT guest_entry=0x1"),
        ("wrong_guest_source_size", "source_size=0x3","source_size=0x4"),
        ("read_instead_of_store", "stlr\tx4, [x19]","ldar\tx4, [x19]"),
        ("no_real_hw_event",
         "Hardware access (read/write) watchpoint 2:",
         "Hardware access (read/write) LOST ACCESS watchpoint 2:"),
        ("missing_footer","KERNIX_G0_IFUNC85_DT_RELA_NO_NATIVE_ATTESTATION=1",
         "FORGED_NO_NATIVE_ATTESTATION=1"),
        ("wrong_zero_original_target",
         TARGET+":\t0x0000000000000000",
         TARGET+":\t0x0000000000000001"),
    ]
    rejected=[]
    for label,old,new in changes:
        require(old in raw,"negative control premise "+label)
        fake=raw.replace(old,new,1)
        require(fake!=raw,"mutation changed raw log "+label)
        try: verify(fake)
        except AssertionError: rejected.append(label)
        else: raise AssertionError("FAIL OPEN: accepted forged native data "+label)
    require(len(rejected)==10,"all ten actual altered original hardware logs rejected")
    return rejected


def run(triad:Path,source:Path,native:Path,prev:Path,out:Path)->dict:
    rows,src_gdb,source_sha=source_auth(triad,source,prev)
    raw,summary=native_artifacts(native,src_gdb)
    receipt=verify(raw)
    rejected=tamper_controls(raw)
    obj={
        "schema":"kernix.g0.original-gnu-ifunc85-dt-rela-zero-real-native-hw-writer-independent.v1",
        "original_source_libc_sha256":LIBC_SHA,
        "original_source_ldso_sha256":LDSO_SHA,
        "original_source_indices":[85],
        "prior_independently_certified_native_hardware_target_count":61,
        "new_distinct_original_GNU_native_hardware_writer_targets":1,
        "unique_original_libc_native_hardware_writer_target_count":62,
        "one_original_IFUNC85_native_writer_receipt":receipt,
        "ten_native_hardware_tamper_cases_rejected":rejected,
        "native_raw_log_sha256":hashlib.sha256(raw.encode()).hexdigest(),
        "original_IFUNC85_CALL_C3_RET_stack_HW_READ_proven":False,
        "all_147_original_libc_RELA_JMPREL_writers_same_process_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    require(obj["one_original_IFUNC85_native_writer_receipt"]
            ["native_source_hardware_write_independently_attested"] is True,
            "actual original x86 mapped GNU source zero to zero native write")
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(obj,indent=2)+"\n")
    return obj


if __name__=="__main__":
    require(len(sys.argv)==6,"usage original-triad source-only native-artifacts prior61-proof output-json")
    obj=run(*map(Path,sys.argv[1:]))
    print("KERNIX_G0_ORIGINAL_IFUNC85_REAL_ZERO_TO_ZERO_FEX_ARM64_NATIVE_WRITER_INDEPENDENTLY_ATTESTED_62_147_NO_ANDROID",obj["unique_original_libc_native_hardware_writer_target_count"])
