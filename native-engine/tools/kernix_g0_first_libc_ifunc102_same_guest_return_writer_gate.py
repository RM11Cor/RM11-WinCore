#!/usr/bin/env python3
"""Strict SAME-process original GNU libc IFUNC102 native FEX hardware-chain gate.

Native source CALL -> real resolver JIT entry -> original caller return-site
JIT header -> real GNU IFUNC target store MUST occur in ONE guest. Caller JIT
entry alone never proves an explicit x86 RET opcode; mark it unproven.

Do not accept generated markers without actual native GDB HW traps, original
source ELF x86 bytes, real AArch64 store, native register/value attribution.
"""
from pathlib import Path
import hashlib
import json
import re
import sys

from kernix_g0_first_libc_ifunc102_original_fex_source_watch import (
    LIBC_SHA,LDSO_SHA,LIBC_BIAS,LDSO_BIAS,RESOLVER,TARGET,BEFORE,
    CALL,CALLER_RETURN,STORE
)
from kernix_g0_first_libc_ifunc102_call_resolver_native_jit_entry_plan import SLOT
from kernix_g0_first_libc_ifunc102_same_guest_return_writer_plan import (
    PLAN,GDB,SOURCE_CALL_RECEIPT,FIRST_WRITER_RECEIPT
)
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset,unique
from kernix_g0_original_libc_relocation_type_transition_gate import decode_original_libc,classify

LOG="original-libc-IFUNC102-same-guest-call-JIT-return-site-write-real-FEX-hw.log"
OUTPUT="original-libc-IFUNC102-same-guest-call-JIT-return-site-write-real-FEX-verified.json"
REAL_NEW=0x8040c74a0


def attest(dist:Path,*,raw_override=None):
    root=dist/"original-source-pinned-root"
    libc=(root/"lib/x86_64-linux-gnu/libc.so.6").read_bytes()
    ldso=(root/"lib64/ld-linux-x86-64.so.2").read_bytes()
    assert len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA
    assert len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
    typed=classify(decode_original_libc(libc))
    assert typed==json.loads((dist/"original-libc-147-rela-jmprel-typed-source-next-stage-plan.json").read_text())
    row=decode_original_libc(libc)[102]
    assert row["table"]=="DT_JMPREL" and row["r_type"]==37 and row["r_sym"]==0
    assert row["r_addend"]==RESOLVER-LIBC_BIAS
    assert int(row["source_guest_target"],16)==TARGET
    assert int(row["original_source_qword"],16)==BEFORE
    assert libc[source_offset(libc,RESOLVER-LIBC_BIAS,4,5):][:4]==bytes.fromhex("f30f1efa")
    assert ldso[source_offset(ldso,CALL-LDSO_BIAS,2,5):][:2]==bytes.fromhex("ffd0")
    assert ldso[source_offset(ldso,CALLER_RETURN-LDSO_BIAS,4,5):][:4]==bytes.fromhex("4883c318")
    assert ldso[source_offset(ldso,STORE-LDSO_BIAS,3,5):][:3]==bytes.fromhex("498906")
    assert source_offset(libc,REAL_NEW-LIBC_BIAS,1,5)>=0

    previous=json.loads((dist/FIRST_WRITER_RECEIPT).read_text())
    assert previous["first_IFUNC_native_hardware_target_write_proven"] is True
    assert previous["seven_actual_native_FEX_log_tamper_controls_rejected"] is True
    assert previous["actual_native_hardware_writer_qword"]==hex(REAL_NEW)
    assert previous["original_IFUNC_resolver_call_return_same_process_proven"] is False
    call=json.loads((dist/SOURCE_CALL_RECEIPT).read_text())
    assert call["same_original_FEX_native_guest_process_call_and_JIT_entry_proven"] is True
    assert call["actual_source_libc_resolver_JIT_entry"]==hex(RESOLVER)
    assert call["native_guest_call_stack_return_slot"]==hex(SLOT)
    assert call["six_genuine_source_call_JIT_hardware_log_tamper_cases_rejected"] is True
    assert call["first_IFUNC_call_entry_return_writer_chain_same_process_proven"] is False
    plan=json.loads((dist/PLAN).read_text())
    assert plan["source_original_libc_sha256"]==LIBC_SHA
    assert plan["source_original_ldso_sha256"]==LDSO_SHA
    assert plan["real_original_linux_arm64_FEX_guest_executed_by_this_plan"] is False
    assert plan["same_guest_IFUNC_call_JIT_return_site_write_proven"] is False
    assert plan["explicit_guest_IFUNC_RET_opcode_proven"] is False
    script=(dist/GDB).read_text()
    assert script.count("awatch -location *(unsigned long long *)0x80300f9b8")==1
    assert script.count("watch -location *(unsigned long long *)$native_state")==1
    assert script.count("watch -location *(unsigned long long *)0x804202d78")==1

    raw=(dist/LOG).read_text(errors="replace") if raw_override is None else raw_override
    markers=[
        "KERNIX_G0_LIBC_IFUNC102_CALL_NATIVE_STACK_ACCESS_ARMED ",
        "KERNIX_G0_LIBC_IFUNC102_EXACT_SOURCE_GNU_CALL_STACK_NATIVE_HW_HIT ",
        "KERNIX_G0_LIBC_IFUNC102_RESOLVER_JIT_ENTRY_NATIVE_HEADER_WATCH_ARMED ",
        "KERNIX_G0_LIBC_IFUNC102_ORIGINAL_GNU_RESOLVER_JIT_ENTRY_NATIVE_HW_PROVEN ",
        "KERNIX_G0_LIBC_IFUNC102_JIT_NATIVE_RESOLVER_ENTRY_BOUNDED_TERMINAL ",
        "KERNIX_G0_IFUNC102_SOURCE_RETURN_SITE_FOLLOWUP_ARMED ",
        "KERNIX_G0_IFUNC102_REAL_ORIGINAL_CALLER_RETURN_SITE_JIT_HW_STOP ",
        "KERNIX_G0_IFUNC102_RETURN_SITE_SOURCE_BOUNDED_TERMINAL ",
        "KERNIX_G0_IFUNC102_POST_REAL_RETURN_SITE_PRE_WRITER_TARGET_SOURCE_INITIAL ",
        "KERNIX_G0_IFUNC102_SAME_PROCESS_NATIVE_WRITER_WATCH_ARMED ",
        "KERNIX_G0_IFUNC102_SAME_PROCESS_NATIVE_HW_WRITER_STOP ",
        "KERNIX_G0_IFUNC102_SAME_PROCESS_NATIVE_HW_WRITER_SOURCE_JIT ",
        "KERNIX_G0_IFUNC102_SAME_GUEST_SOURCE_CHAIN_DIAGNOSTIC_END_SPECIFIC_RET_OPCODE_NOT_TRACED=1"
    ]
    assert all(raw.count(m)==1 for m in markers), (
        "each original hardware stage must occur exactly once",
        [(m,raw.count(m)) for m in markers])
    assert all(raw.index(markers[i])<raw.index(markers[i+1])
               for i in range(len(markers)-1)), "same-process order of FEX witnesses wrong"
    arm=unique(
        r"^KERNIX_G0_LIBC_IFUNC102_CALL_NATIVE_STACK_ACCESS_ARMED "
        r"slot=(0x[0-9a-fA-F]+) source_expected_return=(0x[0-9a-fA-F]+) "
        r"resolver_target=(0x[0-9a-fA-F]+) NO_ENTRY_PROVEN_YET=1$",raw)
    assert tuple(int(x,16) for x in arm)==(SLOT,CALLER_RETURN,RESOLVER)
    access=re.findall(
        r"^Hardware access \(read/write\) watchpoint 2: -location "
        r"\*\(unsigned long long \*\)0x([0-9a-fA-F]+)$",raw,re.M)
    assert len(access)==2 and all(int(x,16)==SLOT for x in access)
    guestcall=unique(
        r"^KERNIX_G0_LIBC_IFUNC102_EXACT_SOURCE_GNU_CALL_STACK_NATIVE_HW_HIT "
        r"target_rax_x4=(0x[0-9a-fA-F]+) guest_rsp_x8=(0x[0-9a-fA-F]+) "
        r"native_pc=(0x[0-9a-fA-F]+) guest_return_slot=(0x[0-9a-fA-F]+) "
        r"guest_return_value=(0x[0-9a-fA-F]+) NOT_YET_SOURCE_ENTRY_ATTESTED=1$",raw)
    target,rsp,pc,slot,ret=[int(x,16) for x in guestcall]
    assert (target,rsp,slot,ret)==(RESOLVER,SLOT,SLOT,CALLER_RETURN)
    assert pc>=0xffff00000000
    entry=unique(
        r"^KERNIX_G0_LIBC_IFUNC102_ORIGINAL_GNU_RESOLVER_JIT_ENTRY_NATIVE_HW_PROVEN "
        r"guest_rip=(0x[0-9a-fA-F]+) host_pc=(0x[0-9a-fA-F]+) "
        r"guest_rsp=(0x[0-9a-fA-F]+) resolver_call_return_unproven=1$",raw)
    assert int(entry[0],16)==RESOLVER and int(entry[1],16)>=0xffff00000000
    assert int(entry[2],16)==SLOT
    assert re.search(r"^0x%x:\s+0xf3\s+0x0f\s+0x1e\s+0xfa"%RESOLVER,raw,re.M)
    header_regs=re.findall(
        r"^Hardware watchpoint 3: -location "
        r"\*\(unsigned long long \*\)\$native_state$",raw,re.M)
    assert len(header_regs)>=2
    b=unique(
        r"^KERNIX_G0_IFUNC102_SOURCE_RETURN_SITE_FOLLOWUP_ARMED "
        r"target=(0x[0-9a-fA-F]+) max_native_jit_headers=(\d+) "
        r"explicit_guest_ret_opcode_not_yet_proven=1$",raw)
    assert int(b[0],16)==CALLER_RETURN and int(b[1])==256
    follow=re.findall(
        r"^KERNIX_G0_IFUNC102_FOLLOWUP_REAL_FEX_JIT_HEADER "
        r"ordinal=(\d+) guest_entry=(0x[0-9a-fA-F]+) size=(0x[0-9a-fA-F]+) "
        r"count=(\d+) native_pc=(0x[0-9a-fA-F]+) "
        r"guest_rsp_x8=(0x[0-9a-fA-F]+) guest_rax_x4=(0x[0-9a-fA-F]+) "
        r"guest_r14_x19=(0x[0-9a-fA-F]+)$",raw,re.M)
    assert 1<=len(follow)<=256
    assert [int(x[0]) for x in follow]==list(range(1,len(follow)+1))
    for f in follow:
        assert 0<int(f[2],16)<=4096 and 0<int(f[3])<=4096
        assert int(f[4],16)>=0xffff00000000
        assert 0x803000000<=int(f[5],16)<0x803010000
    return_events=[r for r in follow if int(r[1],16)==CALLER_RETURN]
    assert len(return_events)==1 and return_events[0]==follow[-1]
    end=unique(
        r"^KERNIX_G0_IFUNC102_REAL_ORIGINAL_CALLER_RETURN_SITE_JIT_HW_STOP "
        r"target=(0x[0-9a-fA-F]+) native_pc=(0x[0-9a-fA-F]+) "
        r"guest_rsp=(0x[0-9a-fA-F]+) guest_rax=(0x[0-9a-fA-F]+) "
        r"guest_r14=(0x[0-9a-fA-F]+) explicit_guest_ret_opcode_not_proven=1$",raw)
    retguest,retpc,retrsp,retrax,retr14=[int(x,16) for x in end]
    assert retguest==CALLER_RETURN and retpc==int(return_events[0][4],16)
    assert (retrsp,retrax,retr14)==(SLOT+8,REAL_NEW,TARGET)
    assert int(return_events[0][5],16)==retrsp
    assert int(return_events[0][6],16)==retrax
    assert int(return_events[0][7],16)==retr14
    assert re.search(r"^0x%x:\s+0x48\s+0x83\s+0xc3\s+0x18"%CALLER_RETURN,raw,re.M)
    assert re.search(r"^0x%x:\s+0x%016x$"%(SLOT,CALLER_RETURN),raw,re.M)
    terminal=unique(
        r"^KERNIX_G0_IFUNC102_RETURN_SITE_SOURCE_BOUNDED_TERMINAL "
        r"stops=(\d+) found=(\d+) native_guest_specific_ret_opcode_not_traced=1$",raw)
    assert tuple(int(x) for x in terminal)==(len(follow),1)
    assert "KERNIX_G0_IFUNC102_RETURN_SITE_MISSING_FAIL_CLOSED" not in raw

    oldmark=unique(
        r"^KERNIX_G0_IFUNC102_POST_REAL_RETURN_SITE_PRE_WRITER_TARGET_SOURCE_INITIAL "
        r"target=(0x[0-9a-fA-F]+) qword_follows=1$",raw)
    assert int(oldmark,16)==TARGET
    assert len(re.findall(r"^0x%x:\s+0x%016x$"%(TARGET,BEFORE),raw,re.M))==1
    watchmark=unique(
        r"^KERNIX_G0_IFUNC102_SAME_PROCESS_NATIVE_WRITER_WATCH_ARMED "
        r"target=(0x[0-9a-fA-F]+) correct_source_GNU_writer=(0x[0-9a-fA-F]+) "
        r"proof_pending=1$",raw)
    assert tuple(int(x,16) for x in watchmark)==(TARGET,STORE)
    wr_regs=re.findall(
        r"^Hardware watchpoint 4: -location "
        r"\*\(unsigned long long \*\)0x([0-9a-fA-F]+)$",raw,re.M)
    assert len(wr_regs)==2 and all(int(x,16)==TARGET for x in wr_regs)
    old=unique(r"^Old value = (0x[0-9a-fA-F]+)$",raw)
    new=unique(r"^New value = (0x[0-9a-fA-F]+)$",raw)
    assert (int(old,16),int(new,16))==(BEFORE,REAL_NEW)
    w=unique(
        r"^KERNIX_G0_IFUNC102_SAME_PROCESS_NATIVE_HW_WRITER_STOP "
        r"pc=(0x[0-9a-fA-F]+) x4_rax=(0x[0-9a-fA-F]+) "
        r"x19_r14=(0x[0-9a-fA-F]+) x8_rsp=(0x[0-9a-fA-F]+) "
        r"x28_state=(0x[0-9a-fA-F]+)$",raw)
    wpc,rax,r14,rsp,state=[int(x,16) for x in w]
    assert wpc>=0xffff00000000 and wpc%4==0
    assert (rax,r14,rsp)==(REAL_NEW,TARGET,SLOT+8)
    assert state>=0xffff00000000
    assert re.search(r"^\s*0x%x:\s+stlr\s+x4,\s*\[x19\]\s*$"%(wpc-4),raw,re.M)
    hdr=unique(
        r"^KERNIX_G0_IFUNC102_SAME_PROCESS_NATIVE_HW_WRITER_SOURCE_JIT "
        r"guest_entry=(0x[0-9a-fA-F]+) guest_size=(0x[0-9a-fA-F]+) "
        r"count=(\d+) native_after_pc=(0x[0-9a-fA-F]+)$",raw)
    guest,size,n,pc=[int(hdr[0],16),int(hdr[1],16),int(hdr[2]),int(hdr[3],16)]
    assert (guest,size,n,pc)==(STORE,3,2,wpc)
    assert re.search(r"^0x%x:\s+0x49\s+0x89\s+0x06"%STORE,raw,re.M)
    assert re.search(r"^0x%x:\s+0x%016x$"%(TARGET,REAL_NEW),raw,re.M)
    assert raw.count("KERNIX_G0_IFUNC102_SAME_GUEST_SOURCE_CHAIN_DIAGNOSTIC_END_SPECIFIC_RET_OPCODE_NOT_TRACED=1")==1
    return {
        "schema":"kernix.g0.first-original-libc-IFUNC102-same-FEX-guest-real-source-call-JIT-caller-write-verified.v1",
        "source_original_libc_sha256":LIBC_SHA,
        "source_original_ldso_sha256":LDSO_SHA,
        "one_real_FEX_guest_process_CALL_to_IFUNC_resolver_JIT_and_return_site_target_store_proven":True,
        "source_guest_IFUNC_index":102,
        "source_original_GNU_loader_CALL_guest_RIP":hex(CALL),
        "source_guest_resolver_entry_RIP":hex(RESOLVER),
        "source_GNU_caller_JIT_return_site_guest_RIP":hex(CALLER_RETURN),
        "live_original_GNU_IFUNC_return_pointer_RAX_at_caller_JIT":hex(retrax),
        "live_guest_stack_RSP_restored":hex(retrsp),
        "source_target_guest_address":hex(TARGET),
        "source_target_initial_qword":hex(oldmark and BEFORE),
        "source_target_after_native_FEX_hardware_store":hex(REAL_NEW),
        "original_x86_GNU_writer_guest_RIP":hex(guest),
        "original_x86_GNU_writer_opcode":"498906",
        "native_ARM64_after_write_PC":hex(wpc),
        "native_ARM64_store_opcode":"stlr x4, [x19]",
        "native_hardware_jit_followup_blocks_to_source_caller":len(follow),
        "explicit_original_guest_IFUNC_RET_opcode_hardware_traced":False,
        "original_IFUNC_resolver_entire_body_semantics_proven":False,
        "other_45_IFUNC_resolvers_proven":False,
        "other_85_RELA_source_writers_proven":False,
        "all_147_original_libc_dynamic_relocations_closed_in_one_guest":False,
        "Android_Bionic_Wine_Proton_games_proven":False
    }

def negative_controls(dist:Path):
    raw=(dist/LOG).read_text(errors="replace")
    bad=[]
    def one(name,pattern,repl):
        altered,n=re.subn(pattern,repl,raw,count=1,flags=re.M)
        assert n==1 and altered!=raw,(name,n)
        bad.append((name,altered))
    one("source_CALL_target_forged",
        r"^(KERNIX_G0_LIBC_IFUNC102_EXACT_SOURCE_GNU_CALL_STACK_NATIVE_HW_HIT target_rax_x4=)0x[0-9a-fA-F]+",
        r"\g<1>0x1")
    one("source_resolver_JIT_entry_forged",
        r"^(KERNIX_G0_LIBC_IFUNC102_ORIGINAL_GNU_RESOLVER_JIT_ENTRY_NATIVE_HW_PROVEN guest_rip=)0x[0-9a-fA-F]+",
        r"\g<1>0x1")
    one("source_caller_RAX_result_forged",
        r"^(KERNIX_G0_IFUNC102_REAL_ORIGINAL_CALLER_RETURN_SITE_JIT_HW_STOP [^\n]+ guest_rax=)0x[0-9a-fA-F]+",
        r"\g<1>0x1")
    one("source_caller_RSP_restoration_forged",
        r"^(KERNIX_G0_IFUNC102_REAL_ORIGINAL_CALLER_RETURN_SITE_JIT_HW_STOP [^\n]+ guest_rsp=)0x[0-9a-fA-F]+",
        r"\g<1>0x1")
    one("target_original_old_word_forged",
        r"^Old value = 0x[0-9a-fA-F]+$","Old value = 0x1")
    one("target_native_new_word_forged",
        r"^New value = 0x[0-9a-fA-F]+$","New value = 0x1")
    one("source_writer_native_x19_forged",
        r"^(KERNIX_G0_IFUNC102_SAME_PROCESS_NATIVE_HW_WRITER_STOP [^\n]+ x19_r14=)0x[0-9a-fA-F]+",
        r"\g<1>0x1")
    one("same_guest_hardware_writer_missing",
        r"^KERNIX_G0_IFUNC102_SAME_PROCESS_NATIVE_HW_WRITER_STOP [^\n]+$",
        "KERNIX_G0_WRITER_NATIVE_STOP_MISSING")
    one("caller_source_return_site_missing",
        r"^KERNIX_G0_IFUNC102_REAL_ORIGINAL_CALLER_RETURN_SITE_JIT_HW_STOP [^\n]+$",
        "KERNIX_G0_CALLER_SOURCE_RETURN_SITE_MISSING")
    pat=r"^\s*0x[0-9a-fA-F]+:\s+stlr\s+x4,\s*\[x19\]\s*$"
    changed,n=re.subn(pat,"0x00000000: ldr x4, [x19]",raw,flags=re.M)
    assert n>=1 and not re.search(pat,changed,re.M)
    bad.append(("replace_all_native_STLR_source_stores",changed))
    assert len(bad)==10
    for name,corrupt in bad:
        try:attest(dist,raw_override=corrupt)
        except AssertionError:continue
        raise AssertionError("FAIL OPEN source IFUNC102 one-FEX-guest hardware proof accepted forged evidence "+name)
    return [name for name,_ in bad]

def main(dist:Path):
    result=attest(dist)
    checks=negative_controls(dist)
    assert len(checks)==10
    result["ten_same_process_native_hardware_log_mutations_rejected"]=True
    result["negative_names"]=checks
    (dist/OUTPUT).write_text(json.dumps(result,indent=2)+"\n")
    print("KERNIX_G0_FIRST_ORIGINAL_LIBC_IFUNC102_SAME_REAL_FEX_GUEST_NATIVE_CALL_JIT_RETURN_SITE_TARGET_WRITE_PASS_SPECIFIC_GUEST_RET_UNTRACED")

if __name__=="__main__":
    assert len(sys.argv)==2
    main(Path(sys.argv[1]))
