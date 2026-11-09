#!/usr/bin/env python3
"""Attest native FEX hardware call stack + ORIGINAL libc IFUNC102 JIT entry.

This stops at the first guest resolver ENDBR64 JIT header. Neither explicit
guest RET, its ABI return value, nor same-process relocation target write
is proven by this gate; those require separate bounded runtime evidence.
"""
import hashlib,json,re,sys
from pathlib import Path

from kernix_g0_first_libc_ifunc102_original_fex_source_watch import (
    LIBC_SHA,LDSO_SHA,LIBC_BIAS,LDSO_BIAS,CALL,CALLER_RETURN,RESOLVER,TARGET
)
from kernix_g0_first_libc_ifunc102_call_resolver_native_jit_entry_plan import PLAN,GDB,SLOT
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset,unique

LOG="original-libc-first-IFUNC102-call-target-JIT-entry-real-FEX.log"
OUT="original-libc-first-IFUNC102-call-target-JIT-entry-real-FEX-verified.json"


def attest(dist:Path,*,raw_override=None):
    root=dist/"original-source-pinned-root"
    libc=(root/"lib/x86_64-linux-gnu/libc.so.6").read_bytes()
    ldso=(root/"lib64/ld-linux-x86-64.so.2").read_bytes()
    assert len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA
    assert len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
    first=json.loads((dist/"original-libc-first-IRELATIVE-102-real-FEX-native-writer-only-proof.json").read_text())
    assert first["first_IFUNC_source_index"]==102
    assert first["actual_native_hardware_writer_qword"]=="0x8040c74a0"
    assert first["first_IFUNC_native_hardware_target_write_proven"] is True
    assert first["seven_actual_native_FEX_log_tamper_controls_rejected"] is True
    assert first["original_IFUNC_resolver_call_return_same_process_proven"] is False
    plan=json.loads((dist/PLAN).read_text())
    assert plan["original_libc_sha256"]==LIBC_SHA
    assert plan["original_ldso_sha256"]==LDSO_SHA
    assert plan["prior_real_FEX_first_IFUNC_native_hardware_writer_proven"] is True
    assert plan["original_GNU_x86_call_guest_RIP"]==hex(CALL)
    assert plan["original_GNU_x86_call_opcode"]=="ffd0"
    assert plan["exact_expected_resolver_guest_RIP"]==hex(RESOLVER)
    assert plan["original_guest_STACK_after_call_return_slot"]==hex(SLOT)
    assert plan["original_guest_return_address_qword"]==hex(CALLER_RETURN)
    assert plan["real_FEX_guest_call_stack_hardware_stop_observed"] is False
    assert plan["real_FEX_guest_resolver_JIT_header_entry_hardware_stop_observed"] is False
    assert ldso[source_offset(ldso,CALL-LDSO_BIAS,2,5):][:2]==bytes.fromhex("ffd0")
    assert libc[source_offset(libc,RESOLVER-LIBC_BIAS,4,5):][:4]==bytes.fromhex("f30f1efa")
    script=(dist/GDB).read_text()
    assert "awatch -location *(unsigned long long *)0x80300f9b8" in script
    assert "watch -location *(unsigned long long *)$native_state" in script
    raw=(dist/LOG).read_text(errors="replace") if raw_override is None else raw_override
    begin=unique(
        r"^KERNIX_G0_LIBC_IFUNC102_CALL_NATIVE_STACK_ACCESS_ARMED "
        r"slot=(0x[0-9a-fA-F]+) source_expected_return=(0x[0-9a-fA-F]+) "
        r"resolver_target=(0x[0-9a-fA-F]+) NO_ENTRY_PROVEN_YET=1$",raw)
    assert tuple(int(x,16) for x in begin)==(SLOT,CALLER_RETURN,RESOLVER)
    access=re.findall(
        r"^Hardware access \(read/write\) watchpoint 2: -location "
        r"\*\(unsigned long long \*\)0x([0-9a-fA-F]+)$",raw,re.M)
    assert len(access)==2 and all(int(x,16)==SLOT for x in access)
    event=unique(
        r"^KERNIX_G0_LIBC_IFUNC102_EXACT_SOURCE_GNU_CALL_STACK_NATIVE_HW_HIT "
        r"target_rax_x4=(0x[0-9a-fA-F]+) guest_rsp_x8=(0x[0-9a-fA-F]+) "
        r"native_pc=(0x[0-9a-fA-F]+) guest_return_slot=(0x[0-9a-fA-F]+) "
        r"guest_return_value=(0x[0-9a-fA-F]+) NOT_YET_SOURCE_ENTRY_ATTESTED=1$",raw)
    target,rsp,pc,slot,value=[int(x,16) for x in event]
    assert (target,rsp,slot,value)==(RESOLVER,SLOT,SLOT,CALLER_RETURN)
    assert pc>=0xffff00000000
    assert re.search(r"^0x%x:\s+0x%016x$"%(SLOT,CALLER_RETURN),raw,re.M)
    entry_arm=unique(
        r"^KERNIX_G0_LIBC_IFUNC102_RESOLVER_JIT_ENTRY_NATIVE_HEADER_WATCH_ARMED "
        r"state=(0x[0-9a-fA-F]+) expected=(0x[0-9a-fA-F]+) max=(\d+)$",raw)
    state,expected,limit=int(entry_arm[0],16),int(entry_arm[1],16),int(entry_arm[2])
    assert state>=0xffff00000000 and expected==RESOLVER and limit==48
    regs=re.findall(
        r"^Hardware watchpoint 3: -location "
        r"\*\(unsigned long long \*\)\$native_state$",raw,re.M)
    assert len(regs)>=2
    items=re.findall(
        r"^KERNIX_G0_LIBC_IFUNC102_JIT_NATIVE_HEADER_STOP "
        r"i=(\d+) guest_entry=(0x[0-9a-fA-F]+) size=(0x[0-9a-fA-F]+) "
        r"host_pc=(0x[0-9a-fA-F]+) x8_rsp=(0x[0-9a-fA-F]+) "
        r"x4_rax=(0x[0-9a-fA-F]+) count=(\d+)$",raw,re.M)
    assert 1<=len(items)<=48
    assert [int(i[0]) for i in items]==list(range(1,len(items)+1))
    for rec in items:
        _,guest,length,host,guest_rsp,rax,count=rec
        assert 0<int(length,16)<=4096
        assert int(host,16)>=0xffff00000000
        assert 0x803000000<=int(guest_rsp,16)<0x803010000
        assert int(count)>=1 and int(count)<=4096
    resolver=[r for r in items if int(r[1],16)==RESOLVER]
    assert len(resolver)==1 and resolver[0]==items[-1]
    hit=unique(
        r"^KERNIX_G0_LIBC_IFUNC102_ORIGINAL_GNU_RESOLVER_JIT_ENTRY_NATIVE_HW_PROVEN "
        r"guest_rip=(0x[0-9a-fA-F]+) host_pc=(0x[0-9a-fA-F]+) "
        r"guest_rsp=(0x[0-9a-fA-F]+) resolver_call_return_unproven=1$",raw)
    assert tuple(int(x,16) for x in hit)==(
        RESOLVER,int(resolver[0][3],16),int(resolver[0][4],16))
    assert int(hit[2],16)==SLOT
    assert re.search(r"^0x%x:\s+0xf3\s+0x0f\s+0x1e\s+0xfa"%RESOLVER,raw,re.M)
    count,found=unique(
        r"^KERNIX_G0_LIBC_IFUNC102_JIT_NATIVE_RESOLVER_ENTRY_BOUNDED_TERMINAL "
        r"stops=(\d+) found=(\d+) guest_return_untraced=1$",raw)
    assert int(count)==len(items) and int(found)==1
    strings=[
        "KERNIX_G0_LIBC_IFUNC102_CALL_NATIVE_STACK_ACCESS_ARMED",
        "KERNIX_G0_LIBC_IFUNC102_EXACT_SOURCE_GNU_CALL_STACK_NATIVE_HW_HIT",
        "KERNIX_G0_LIBC_IFUNC102_RESOLVER_JIT_ENTRY_NATIVE_HEADER_WATCH_ARMED",
        "KERNIX_G0_LIBC_IFUNC102_ORIGINAL_GNU_RESOLVER_JIT_ENTRY_NATIVE_HW_PROVEN",
        "KERNIX_G0_LIBC_IFUNC102_JIT_NATIVE_RESOLVER_ENTRY_BOUNDED_TERMINAL",
    ]
    assert all(raw.index(strings[i])<raw.index(strings[i+1]) for i in range(len(strings)-1))
    return {
        "schema":"kernix.g0.first-IFUNC102-original-FEX-native-CALL-stack-and-JIT-resolver-entry.v1",
        "original_libc_sha256":LIBC_SHA,
        "original_ldso_sha256":LDSO_SHA,
        "same_original_FEX_native_guest_process_call_and_JIT_entry_proven":True,
        "original_GNU_x86_indirect_CALL_guest_RIP":hex(CALL),
        "native_guest_call_target_x4":hex(target),
        "native_guest_call_stack_return_slot":hex(slot),
        "original_guest_return_address_qword":hex(value),
        "actual_source_libc_resolver_JIT_entry":hex(RESOLVER),
        "first_source_JIT_guest_entry_original_ENDBR64_verified":True,
        "native_FEX_JIT_headers_to_resolver_entry":len(items),
        "original_resolver_guest_return_opcode_executed_proven":False,
        "original_IFUNC_caller_return_site_reached":False,
        "first_IFUNC_call_entry_return_writer_chain_same_process_proven":False,
        "first_IFUNC_genuine_hardware_target_store_proven_in_separate_run":True,
        "other_45_IFUNC_resolvers_proven":False,
        "all_147_RELA_JMPREL_closed_in_one_guest":False,
        "Android_Bionic_Wine_Proton_games_proven":False
    }

def negative_controls(dist:Path):
    raw=(dist/LOG).read_text(errors="replace")
    negative=[]
    def one(name,pat,repl):
        altered,n=re.subn(pat,repl,raw,count=1,flags=re.M)
        assert n==1 and altered!=raw,(name,n)
        negative.append((name,altered))
    one("caller_guest_call_target_forged",
        r"^(KERNIX_G0_LIBC_IFUNC102_EXACT_SOURCE_GNU_CALL_STACK_NATIVE_HW_HIT target_rax_x4=)0x[0-9a-fA-F]+",
        r"\g<1>0x1")
    one("caller_stack_rsp_forged",
        r"^(KERNIX_G0_LIBC_IFUNC102_EXACT_SOURCE_GNU_CALL_STACK_NATIVE_HW_HIT [^\n]+ guest_rsp_x8=)0x[0-9a-fA-F]+",
        r"\g<1>0x1")
    one("resolver_JIT_entry_forged",
        r"^(KERNIX_G0_LIBC_IFUNC102_ORIGINAL_GNU_RESOLVER_JIT_ENTRY_NATIVE_HW_PROVEN guest_rip=)0x[0-9a-fA-F]+",
        r"\g<1>0x1")
    one("source_ENDBR_native_dump_forged",
        r"^(0x8040b4f00:\s+)0xf3",r"\g<1>0x00")
    one("resolver_found_claim_forged",
        r"^(KERNIX_G0_LIBC_IFUNC102_JIT_NATIVE_RESOLVER_ENTRY_BOUNDED_TERMINAL stops=\d+ found=)1",
        r"\g<1>0")
    pat=r"^Hardware access \(read/write\) watchpoint 2: -location \*\(unsigned long long \*\)0x[0-9a-fA-F]+$"
    bad,n=re.subn(pat,"Hardware watchpoint removed",raw,flags=re.M)
    assert n==2 and not re.search(pat,bad,re.M)
    negative.append(("both_native_call_stack_watchpoints_removed",bad))
    assert len(negative)==6
    for name,bad in negative:
        try:attest(dist,raw_override=bad)
        except AssertionError:continue
        raise AssertionError("FAIL OPEN IFUNC102 forged native call or JIT source entry "+name)
    return [name for name,_ in negative]


def main(dist:Path):
    proof=attest(dist)
    names=negative_controls(dist)
    assert len(names)==6
    proof["six_genuine_source_call_JIT_hardware_log_tamper_cases_rejected"]=True
    proof["negative_case_names"]=names
    (dist/OUT).write_text(json.dumps(proof,indent=2)+"\n")
    print("KERNIX_G0_LIBC_IFUNC102_TRUE_FEX_ORIGINAL_SOURCE_CALL_AND_RESOLVER_JIT_ENTRY_PASS_RETURN_NOT_PROVEN")


if __name__=="__main__":
    assert len(sys.argv)==2
    main(Path(sys.argv[1]))
