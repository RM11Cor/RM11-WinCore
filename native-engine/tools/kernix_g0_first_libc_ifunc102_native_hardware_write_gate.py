#!/usr/bin/env python3
"""Fail closed for FIRST genuine libc IFUNC #102 native ARM64 hardware STORE.

A genuine R_X86_64_IRELATIVE target write is NOT by itself proof of IFUNC
resolver entry, return instruction, complete ABI semantics, or libc closure.
The source-original GNU writer uses x86 49 89 06, native STLR x4,[x19].
"""
import hashlib
import json
import re
import sys
from pathlib import Path

from kernix_g0_original_libc_relocation_type_transition_gate import (
    decode_original_libc, classify, LIBC_SHA, LDSO_SHA
)
from kernix_g0_next_libc_symbolic_live_writer_gate import (
    source_offset, unique
)
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import (
    OUT_JSON as PLAN, TARGET, BEFORE, RESOLVER, STORE, LIBC_BIAS, LDSO_BIAS
)

LOG="original-libc-first-IRELATIVE-102-real-FEX-native-hw.log"
OUTPUT="original-libc-first-IRELATIVE-102-real-FEX-native-writer-only-proof.json"

def attest(dist:Path, *, raw_override=None):
    root=dist/"original-source-pinned-root"
    libc=(root/"lib/x86_64-linux-gnu/libc.so.6").read_bytes()
    ldso=(root/"lib64/ld-linux-x86-64.so.2").read_bytes()
    assert len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA
    assert len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
    rows=decode_original_libc(libc)
    t=classify(rows)
    assert t==json.loads((dist/"original-libc-147-rela-jmprel-typed-source-next-stage-plan.json").read_text())
    assert rows[102]["r_type"]==37 and rows[102]["r_sym"]==0
    assert rows[102]["r_addend"]==RESOLVER-LIBC_BIAS
    assert int(rows[102]["source_guest_target"],16)==TARGET
    assert rows[102]["original_source_qword"]==hex(BEFORE)
    typed_ifunc=json.loads(
        (dist/"original-libc-46-IFUNC-IRELATIVE-42-unique-resolver-source-only-plan.json").read_text())
    assert typed_ifunc["original_IFUNC_source_relocation_count"]==46
    assert typed_ifunc["first_initial_IFUNC_candidate_index"]==102
    assert typed_ifunc["IFUNC_execution_real_native_FEX_witness_proven"] is False
    plan=json.loads((dist/PLAN).read_text())
    assert plan["source_original_libc_sha256"]==LIBC_SHA
    assert plan["source_original_ldso_sha256"]==LDSO_SHA
    assert plan["all_16_previous_JUMP_SLOT_individually_native_FEX_writers_source_proven"] is True
    assert plan["first_IFUNC_source_index"]==102
    assert plan["source_guest_resolver_entry"]==hex(RESOLVER)
    assert plan["source_relocation_target"]==hex(TARGET)
    assert plan["source_relocation_initial_qword"]==hex(BEFORE)
    assert plan["source_GNU_loader_x86_writer_guest_address"]==hex(STORE)
    assert plan["source_GNU_loader_x86_writer_opcode"]=="498906"
    assert plan["real_FEX_first_IFUNC_guest_executed"] is False
    assert plan["original_IFUNC_resolver_return_to_caller_observed"] is False
    previous=json.loads((dist/"original-libc-last-jumpslot-101-real-fex-hw-verified.json").read_text())
    assert previous["all_16_JUMP_SLOT_individual_native_hardware_writers_proven_count"]==16
    assert previous["last_JUMP_SLOT_real_ARM64_hardware_store_proven"] is True
    assert previous["source_original_libc_sha256"]==LIBC_SHA
    assert previous["source_original_gnu_ldso_sha256"]==LDSO_SHA

    raw=((dist/LOG).read_text(errors="replace")
         if raw_override is None else raw_override)
    arm=unique(
        r"^KERNIX_G0_FIRST_LIBC_IFUNC_102_SOURCE_WRITE_WATCH_ARMED "
        r"index=(\d+) target=(0x[0-9a-fA-F]+) original=(0x[0-9a-fA-F]+) "
        r"resolver=(0x[0-9a-fA-F]+) PROOF_PENDING=1$",raw)
    assert (int(arm[0]),int(arm[1],16),int(arm[2],16),int(arm[3],16))==(
        102,TARGET,BEFORE,RESOLVER)
    regs=re.findall(
        r"^Hardware watchpoint 2: -location \*\(unsigned long long \*\)0x([0-9a-fA-F]+)$",raw,re.M)
    assert len(regs)==2 and all(int(x,16)==TARGET for x in regs)
    old=int(unique(r"^Old value = (0x[0-9a-fA-F]+)$",raw),16)
    new=int(unique(r"^New value = (0x[0-9a-fA-F]+)$",raw),16)
    assert old==BEFORE and new!=old and new!=0
    assert re.search(r"^0x%x:\s+0x%016x$"%(TARGET,new),raw,re.M)
    live=unique(
        r"^KERNIX_G0_FIRST_LIBC_IFUNC_102_NATIVE_HW_AFTER_WRITE "
        r"target=(0x[0-9a-fA-F]+) pc=(0x[0-9a-fA-F]+) "
        r"x4_rax=(0x[0-9a-fA-F]+) x19_r14=(0x[0-9a-fA-F]+) "
        r"x8_rsp=(0x[0-9a-fA-F]+) x28_state=(0x[0-9a-fA-F]+) "
        r"SOURCE_ONLY_CONTEXT_NO_RESOLVER_RET_CLAIM=1$",raw)
    target,pc,x4,x19,rsp,state=[int(x,16) for x in live]
    assert target==TARGET and x19==TARGET and x4==new
    assert pc>=0xffff00000000 and pc%4==0
    assert 0x803000000<=rsp<0x803010000 and state>=0xffff00000000
    stores=re.findall(
        r"^\s*0x%x:\s+(stlr\s+x4,\s*\[x19\])\s*$"%(pc-4),raw,re.M)
    assert len(stores)>=1
    h=unique(
        r"^KERNIX_G0_FIRST_LIBC_IFUNC_102_NATIVE_FEX_GNU_SOURCE_JIT_ENTRY "
        r"guest_entry=(0x[0-9a-fA-F]+) guest_size=(0x[0-9a-fA-F]+) "
        r"inst_count=(\d+) host_after_pc=(0x[0-9a-fA-F]+)$",raw)
    guest,size,inst_count,hostpc=int(h[0],16),int(h[1],16),int(h[2]),int(h[3],16)
    assert (guest,size,inst_count,hostpc)==(STORE,3,2,pc)
    original_writer=ldso[
        source_offset(ldso,guest-LDSO_BIAS,3,5):
        source_offset(ldso,guest-LDSO_BIAS,3,5)+3]
    assert original_writer==bytes.fromhex("498906")
    original_print=unique(
        r"^0x%x:\s+((?:0x[0-9a-fA-F]{2}\s+){7}0x[0-9a-fA-F]{2})\s*$"%STORE,raw)
    source_bytes=bytes(int(x,16) for x in re.findall(r"0x[0-9a-fA-F]{2}",original_print))
    assert source_bytes[:3]==original_writer
    assert source_bytes==ldso[
        source_offset(ldso,STORE-LDSO_BIAS,8,5):
        source_offset(ldso,STORE-LDSO_BIAS,8,5)+8]
    start=source_offset(libc,RESOLVER-LIBC_BIAS,4,5)
    assert libc[start:start+4]==bytes.fromhex("f30f1efa")
    assert re.search(r"^0x%x:\s+0xf3\s+0x0f\s+0x1e\s+0xfa"%RESOLVER,raw,re.M)
    locate=[]
    for name,elf,bias in (("libc",libc,LIBC_BIAS),("ld-linux",ldso,LDSO_BIAS)):
        try:source_offset(elf,new-bias,1,5)
        except AssertionError:continue
        locate.append(name)
    assert len(locate)==1 and locate[0]=="libc", (
        "first strnlen IFUNC resolver result must be source-backed libc RX",hex(new),locate)
    assert raw.index("KERNIX_G0_FIRST_LIBC_IFUNC_102_SOURCE_WRITE_WATCH_ARMED")<(
        raw.index("Old value = ")<raw.index("New value = ")<
        raw.index("KERNIX_G0_FIRST_LIBC_IFUNC_102_NATIVE_HW_AFTER_WRITE")<
        raw.index("KERNIX_G0_FIRST_LIBC_IFUNC_102_NATIVE_FEX_GNU_SOURCE_JIT_ENTRY"))
    assert raw.count("KERNIX_G0_FIRST_LIBC_IFUNC_102_WRITER_DIAGNOSTIC_END_IFUNC_CALL_RETURN_NOT_YET_PROVEN=1")==1
    return {
        "schema":"kernix.g0.first-libc-IRELATIVE-102-source-FEX-aarch64-TRUE-hardware-writer-only.v1",
        "original_libc_sha256":LIBC_SHA,
        "original_ldso_sha256":LDSO_SHA,
        "all_16_previous_JUMP_SLOT_genuine_source_writers_proven":True,
        "first_IFUNC_source_index":102,
        "source_resolver_guest_entry":hex(RESOLVER),
        "source_relocation_guest_target":hex(TARGET),
        "original_source_qword":hex(old),
        "actual_native_hardware_writer_qword":hex(new),
        "actual_native_FEX_writer_after_pc":hex(pc),
        "actual_native_FEX_ARM64_opcode":"stlr x4, [x19]",
        "actual_source_GNU_x86_writer_guest_RIP":hex(guest),
        "actual_source_GNU_x86_writer_opcode":original_writer.hex(),
        "source_returned_pointer_original_libc_RX":True,
        "first_IFUNC_native_hardware_target_write_proven":True,
        "original_IFUNC_resolver_JIT_entry_observed":False,
        "original_guest_IFUNC_resolver_RET_opcode_executed_proven":False,
        "original_IFUNC_resolver_call_return_same_process_proven":False,
        "original_IFUNC_function_ABI_complete_proven":False,
        "all_46_IFUNC_resolver_relocations_closed":False,
        "other_85_RELA_relocations_closed":False,
        "all_147_original_libc_RELA_JMPREL_closed_one_process":False,
        "Android_Bionic_Wine_Proton_games_proven":False
    }


def negative_controls(dist:Path):
    raw=(dist/LOG).read_text(errors="replace")
    changes=[]
    def one(name,pattern,replacement):
        changed,n=re.subn(pattern,replacement,raw,count=1,flags=re.M)
        assert n==1 and changed!=raw,("negative generator failed",name,n)
        changes.append((name,changed))
    one("native_hardware_old_forged",r"^Old value = 0x[0-9a-fA-F]+$","Old value = 0x1")
    one("native_hardware_new_forged",r"^New value = 0x[0-9a-fA-F]+$","New value = 0x1")
    one("live_FEX_x19_target_forged",
        r"^(KERNIX_G0_FIRST_LIBC_IFUNC_102_NATIVE_HW_AFTER_WRITE .+ x19_r14=)0x[0-9a-fA-F]+",
        r"\g<1>0x1")
    one("live_FEX_x4_stored_value_forged",
        r"^(KERNIX_G0_FIRST_LIBC_IFUNC_102_NATIVE_HW_AFTER_WRITE .+ x4_rax=)0x[0-9a-fA-F]+",
        r"\g<1>0x1")
    one("native_GNU_x86_guest_writer_entry_forged",
        r"^(KERNIX_G0_FIRST_LIBC_IFUNC_102_NATIVE_FEX_GNU_SOURCE_JIT_ENTRY guest_entry=)0x[0-9a-fA-F]+",
        r"\g<1>0x1")
    pat=r"^([ \t]*0x[0-9a-fA-F]+:[ \t]+)stlr[ \t]+x4,[ \t]*\[x19\]$"
    altered,n=re.subn(pat,r"\g<1>ldr x4, [x19]",raw,flags=re.M)
    assert n>=1 and not re.search(pat,altered,re.M)
    changes.append(("all_original_native_STLR_writer_disassemblies_replaced",altered))
    pat=r"^Hardware watchpoint 2: -location \*\(unsigned long long \*\)0x[0-9a-fA-F]+$"
    altered,n=re.subn(pat,"Hardware watchpoint disabled",raw,flags=re.M)
    assert n==2 and not re.search(pat,altered,re.M)
    changes.append(("both_native_hardware_watch_records_deleted",altered))
    assert len(changes)==7
    for name,corrupt in changes:
        try:attest(dist,raw_override=corrupt)
        except AssertionError:continue
        raise AssertionError("FAIL OPEN accepted forged original IFUNC #102 hardware log "+name)
    return [name for name,_ in changes]


def main(dist:Path):
    obj=attest(dist)
    names=negative_controls(dist)
    assert len(names)==7
    obj["seven_actual_native_FEX_log_tamper_controls_rejected"]=True
    obj["negative_names"]=names
    (dist/OUTPUT).write_text(json.dumps(obj,indent=2)+"\n")
    print("KERNIX_G0_FIRST_ORIGINAL_LIBC_IFUNC102_REAL_ARM64_NATIVE_HARDWARE_WRITE_PASS_RESOLVER_CALL_RET_NOT_PROVEN")


if __name__=="__main__":
    assert len(sys.argv)==2
    main(Path(sys.argv[1]))
