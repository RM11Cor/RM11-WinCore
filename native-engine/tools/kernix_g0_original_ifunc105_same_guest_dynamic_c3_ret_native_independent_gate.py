#!/usr/bin/env python3
"""Independently verify original GNU libc IFUNC105 real FEX ARM64 whole CALL/RET/store.

Only accepts authentic source ELF, previous distinct source HW writer receipt,
one new real FEX process GDB native hardware write/read traps, exact C3 source
JIT and original ld-linux x86 writer. Reject forged authentic native logs.
CALL/RET gate adds NO new distinct writer: source IFUNC105 is already writer #20 of 147.
No Android device, Wine/Proton, Windows game or FPS proof.
"""
from pathlib import Path
import hashlib
import json
import re
import sys
from kernix_g0_original_libc_relocation_type_transition_gate import decode_original_libc, LIBC_SHA, LDSO_SHA
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_original_ifunc105_one_guest_dynamic_ret_hardware_plan import (
    INDEX, RESOLVER, RET_CANDIDATES, SLOT, TARGET, OLD, RESULT, GDB, OUTPUT as SOURCE_PLAN,
    WRITER_PROOF, CALL, CALLER_RETURN, STORE, LIBC_BIAS, LDSO_BIAS
)
from kernix_g0_original_libc_ifunc105_ret_source_disassembly import OUT as CANDIDATES

LOG="original-libc-IFUNC105-one-FEX-CALL-five-source-RET-native-stack-HW-READ-and-GNU-WRITE.log"
EXIT="original-libc-IFUNC105-one-FEX-CALL-five-source-RET-native-stack-HW-READ-and-GNU-WRITE.exit"
OUT="original-libc-IFUNC105-original-one-FEX-CALL-C3-RET-native-stack-read-GNU-writer-INDEPENDENT-PROOF.json"

def unique(pattern, raw):
    matches=re.findall(pattern,raw,re.M)
    assert len(matches)==1,("missing or duplicate authentic FEX native event",pattern,len(matches))
    return matches[0]

def attest(dist:Path, override=None):
    root=dist/"original-source-pinned-root"
    libc=(root/"lib/x86_64-linux-gnu/libc.so.6").read_bytes()
    ldso=(root/"lib64/ld-linux-x86-64.so.2").read_bytes()
    assert len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA
    assert len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
    row=decode_original_libc(libc)[INDEX]
    assert row["index"]==105 and row["r_type"]==37 and row["r_sym"]==0
    assert row["table"]=="DT_JMPREL" and row["table_index"]==19
    assert LIBC_BIAS+row["r_addend"]==RESOLVER==0x8040cc270
    assert int(row["source_guest_target"],16)==TARGET==0x804202d40
    assert int(row["original_source_qword"],16)==OLD==0x28360
    assert libc[source_offset(libc,RESOLVER-LIBC_BIAS,4,5):][:4]==bytes.fromhex("f30f1efa")
    assert RET_CANDIDATES==(0x8040cc2a5,0x8040cc2dd,0x8040cc2ef,0x8040cc55b,0x8040cc63f)
    for candidate in RET_CANDIDATES:
        assert libc[source_offset(libc,candidate-LIBC_BIAS,1,5)]==0xc3
    assert ldso[source_offset(ldso,CALL-LDSO_BIAS,2,5):][:2]==bytes.fromhex("ffd0")
    assert ldso[source_offset(ldso,CALLER_RETURN-LDSO_BIAS,4,5):][:4]==bytes.fromhex("4883c318")
    assert ldso[source_offset(ldso,STORE-LDSO_BIAS,3,5):][:3]==bytes.fromhex("498906")
    plan=json.loads((dist/SOURCE_PLAN).read_text())
    assert plan["source_libc_sha256"]==LIBC_SHA and plan["source_ldso_sha256"]==LDSO_SHA
    assert plan["original_ifunc_index"]==INDEX
    assert plan["original_resolver_guest_RIP"]==hex(RESOLVER)
    assert plan["original_source_RET_guest_RIP_candidates"]==[hex(x) for x in RET_CANDIDATES]
    assert plan["original_source_RET_guest_RIP_selected_at_runtime"] is None
    assert plan["original_source_RET_opcode"]=="c3"
    assert plan["original_guest_return_stack_slot"]==hex(SLOT)
    assert plan["original_guest_return_site"]==hex(CALLER_RETURN)
    assert plan["expected_real_original_resolver_result_from_prior_write_only_hardware_proof"]==hex(RESULT)
    assert plan["original_IFUNC105_target"]==hex(TARGET)
    assert plan["original_IFUNC105_source_old_qword"]==hex(OLD)
    assert plan["source_plan_only_not_runtime_proof"] is True
    assert plan["actual_native_hardware_RET_read_and_same_process_writer_proven"] is False
    assert plan["previous_unique_native_hardware_writers_independently_certified"]==20
    candidates=json.loads((dist/CANDIDATES).read_text())
    assert candidates["original_IFUNC_source_index"]==INDEX
    assert candidates["source_disassembled_RET_candidates"]==[{
        "original_elf_virtual_address":hex(x-LIBC_BIAS),
        "guest_source_RIP":hex(x),
        "original_x86_opcode":"c3",
        "source_ELF_RX_offset":hex(x-LIBC_BIAS),
        "source_disassembler_mnemonic":"ret",
    } for x in RET_CANDIDATES]
    assert candidates["source_disassembly_RET_candidates_are_NOT_native_execution_proof"] is True
    assert candidates["original_source_libc_sha256"]==LIBC_SHA
    proof=json.loads((dist/WRITER_PROOF).read_text())
    assert proof["original_source_ifunc_index"]==INDEX
    assert proof["source_original_resolver_guest_RIP"]==hex(RESOLVER)
    assert proof["original_source_target"]==hex(TARGET)
    assert proof["native_hardware_new_source_target_qword"]==hex(RESULT)
    assert proof["ten_original_native_hardware_log_corruptions_rejected"] is True
    assert proof["new_unique_original_ifunc105_native_hardware_writer_independently_proven"] is True
    assert proof["unique_original_libc_native_hardware_writer_target_count"]==20
    assert proof["original_IFUNC105_resolver_CALL_C3_RET_native_stack_HW_READ_proven"] is False
    script=(dist/GDB).read_text()
    assert script.count("awatch -location *(unsigned long long *)0x80300f9b8")==1
    assert script.count("rwatch -location *(unsigned long long *)0x80300f9b8")==1
    assert script.count("watch -location *(unsigned long long *)0x804202d40")==1
    assert script.count("watch -location *(unsigned long long *)$native_state")==1
    assert "if $entry == 0x8040cc2a5 || $entry == 0x8040cc2dd || $entry == 0x8040cc2ef || $entry == 0x8040cc55b || $entry == 0x8040cc63f" in script
    assert "condition 4 " not in script
    assert (dist/EXIT).read_text().strip()=="0"
    raw=(dist/LOG).read_text(errors="replace") if override is None else override
    assert "Error in sourced command file" not in raw and "No registers." not in raw
    markers=[
        "KERNIX_G0_IFUNC105_ORIGINAL_CALL_STACK_HW_WATCH_ARMED ",
        "KERNIX_G0_IFUNC105_ORIGINAL_CALL_NATIVE_STACK_HW_HIT ",
        "KERNIX_G0_IFUNC105_ORIGINAL_RESOLVER_JIT_ENTRY_NATIVE_HW_STOP ",
        "KERNIX_G0_IFUNC105_RESOLVER_BOUNDED_SCAN_DONE ",
        "KERNIX_G0_IFUNC105_ORIGINAL_C3_RET_JIT_NATIVE_HW_STOP ",
        "KERNIX_G0_IFUNC105_SOURCE_RET_JIT_BOUNDED_DONE ",
        "KERNIX_G0_IFUNC105_C3_RET_ORIGINAL_RETURN_STACK_HW_READ_ARMED ",
        "KERNIX_G0_IFUNC105_REAL_C3_RET_NATIVE_HARDWARE_READ ",
        "KERNIX_G0_IFUNC105_AFTER_HARDWARE_READ_SOURCE_JIT ",
        "KERNIX_G0_IFUNC105_ORIGINAL_CALLER_RESUMED_AFTER_C3_RET ",
        "KERNIX_G0_IFUNC105_POST_C3_RET_SOURCE_TARGET_BEFORE_NATIVE_WRITER ",
        "KERNIX_G0_IFUNC105_SAME_PROCESS_POST_RET_NATIVE_WRITER_HW_HIT ",
        "KERNIX_G0_IFUNC105_SAME_PROCESS_ORIGINAL_GNU_WRITER_NATIVE_JIT ",
        "KERNIX_G0_IFUNC105_ONE_ORIGINAL_FEX_GUEST_CALL_NATIVE_RET_STACK_READ_AND_GNU_STORE_DIAGNOSTIC_COMPLETE_NOT_INDEPENDENTLY_ATTESTED=1"
    ]
    assert all(raw.count(m)==1 for m in markers), [(m,raw.count(m)) for m in markers]
    points=[raw.index(m) for m in markers]
    assert points==sorted(points) and len(set(points))==len(points), "FEX CALL/RET/store events out of order"
    arm=unique(
      r"^KERNIX_G0_IFUNC105_ORIGINAL_CALL_STACK_HW_WATCH_ARMED resolver=(0x[0-9a-f]+) "
      r"slot=(0x[0-9a-f]+) expected_return=(0x[0-9a-f]+)$",raw)
    assert tuple(int(x,16) for x in arm)==(RESOLVER,SLOT,CALLER_RETURN)
    call=unique(
      r"^KERNIX_G0_IFUNC105_ORIGINAL_CALL_NATIVE_STACK_HW_HIT resolver_rax_x4=(0x[0-9a-f]+) "
      r"guest_rsp_x8=(0x[0-9a-f]+) native_after_pc=(0x[0-9a-f]+)$",raw)
    assert (int(call[0],16),int(call[1],16))==(RESOLVER,SLOT)
    assert int(call[2],16)>=0xffff00000000 and int(call[2],16)%4==0
    assert re.search(r"^0x%x:\s+0xff\s+0xd0\b"%CALL,raw,re.M)
    resolver=unique(
      r"^KERNIX_G0_IFUNC105_ORIGINAL_RESOLVER_JIT_ENTRY_NATIVE_HW_STOP "
      r"guest_entry=(0x[0-9a-f]+) native_pc=(0x[0-9a-f]+) guest_rsp=(0x[0-9a-f]+)$",raw)
    assert int(resolver[0],16)==RESOLVER and int(resolver[1],16)>=0xffff00000000
    assert int(resolver[2],16)==SLOT
    assert re.search(r"^0x%x:\s+0xf3\s+0x0f\s+0x1e\s+0xfa"%RESOLVER,raw,re.M)
    ret=unique(
      r"^KERNIX_G0_IFUNC105_ORIGINAL_C3_RET_JIT_NATIVE_HW_STOP guest_ret=(0x[0-9a-f]+) "
      r"size=(0x[0-9a-f]+) native_pc=(0x[0-9a-f]+) "
      r"guest_rsp=(0x[0-9a-f]+) guest_rax=(0x[0-9a-f]+) native_state=(0x[0-9a-f]+)$",raw)
    chosen_ret=int(ret[0],16)
    assert chosen_ret in RET_CANDIDATES,("actual native JIT return not source-derived x86 C3",hex(chosen_ret))
    assert (int(ret[1],16),int(ret[3],16),int(ret[4],16))==(1,SLOT,RESULT)
    assert libc[source_offset(libc,chosen_ret-LIBC_BIAS,1,5)]==0xc3
    read_armed=unique(r"^KERNIX_G0_IFUNC105_C3_RET_ORIGINAL_RETURN_STACK_HW_READ_ARMED "
       r"slot=(0x[0-9a-f]+) source_ret=(0x[0-9a-f]+)$",raw)
    assert tuple(int(x,16) for x in read_armed)==(SLOT,chosen_ret)
    assert int(ret[2],16)>=0xffff00000000 and int(ret[5],16)>=0xffff00000000
    assert re.search(r"^0x%x:\s+0xc3\b"%chosen_ret,raw,re.M)
    assert re.search(r"^0x%x:\s+0x%016x$"%(SLOT,CALLER_RETURN),raw,re.M)
    assert raw.count("Hardware read watchpoint 4: -location *(unsigned long long *)0x80300f9b8")>=2
    read=unique(
      r"^KERNIX_G0_IFUNC105_REAL_C3_RET_NATIVE_HARDWARE_READ "
      r"pc=(0x[0-9a-f]+) guest_rsp=(0x[0-9a-f]+) guest_rax=(0x[0-9a-f]+) state_x28=(0x[0-9a-f]+)$",raw)
    pc_read,rsp_read,rax_read,state_read=(int(x,16) for x in read)
    assert pc_read>=0xffff00000000 and pc_read%4==0
    assert (rsp_read,rax_read,state_read)==(SLOT+8,RESULT,int(ret[5],16))
    jit=unique(
      r"^KERNIX_G0_IFUNC105_AFTER_HARDWARE_READ_SOURCE_JIT guest_entry=(0x[0-9a-f]+) "
      r"source_size=(0x[0-9a-f]+) native_after_pc=(0x[0-9a-f]+)$",raw)
    assert tuple(int(x,16) for x in jit)==(chosen_ret,1,pc_read)
    caller=unique(
      r"^KERNIX_G0_IFUNC105_ORIGINAL_CALLER_RESUMED_AFTER_C3_RET guest_entry=(0x[0-9a-f]+) "
      r"rsp=(0x[0-9a-f]+) rax=(0x[0-9a-f]+) native_pc=(0x[0-9a-f]+) target_r14=(0x[0-9a-f]+)$",raw)
    assert tuple(int(x,16) for x in (caller[0],caller[1],caller[2],caller[4]))==(CALLER_RETURN,SLOT+8,RESULT,TARGET)
    assert int(caller[3],16)>=0xffff00000000
    assert re.search(r"^0x%x:\s+0x48\s+0x83\s+0xc3\s+0x18"%CALLER_RETURN,raw,re.M)
    target_arm=unique(
      r"^KERNIX_G0_IFUNC105_POST_C3_RET_SOURCE_TARGET_BEFORE_NATIVE_WRITER "
      r"target=(0x[0-9a-f]+) old_expected=(0x[0-9a-f]+)$",raw)
    assert tuple(int(x,16) for x in target_arm)==(TARGET,OLD)
    write_segment=raw[raw.index(markers[10]):]
    assert re.search(r"^0x%x:\s+0x%016x$"%(TARGET,OLD),write_segment,re.M)
    assert write_segment.count("Hardware watchpoint 5: -location *(unsigned long long *)0x804202d40")>=2
    assert re.search(r"^Old value = 0x%x$"%OLD,write_segment,re.M)
    assert re.search(r"^New value = 0x%x$"%RESULT,write_segment,re.M)
    writer=unique(
      r"^KERNIX_G0_IFUNC105_SAME_PROCESS_POST_RET_NATIVE_WRITER_HW_HIT "
      r"pc=(0x[0-9a-f]+) rsp=(0x[0-9a-f]+) rax=(0x[0-9a-f]+) r14=(0x[0-9a-f]+)$",raw)
    pc_write,rsp_write,rax_write,r14_write=(int(x,16) for x in writer)
    assert pc_write>=0xffff00000000 and pc_write%4==0
    assert (rsp_write,rax_write,r14_write)==(SLOT+8,RESULT,TARGET)
    assert re.search(r"^\s*0x%x:\s+stlr\s+x4,\s*\[x19\]$"%(pc_write-4),write_segment,re.M)
    assert re.search(r"^0x%x:\s+0x%016x$"%(TARGET,RESULT),write_segment,re.M)
    jit_writer=unique(
      r"^KERNIX_G0_IFUNC105_SAME_PROCESS_ORIGINAL_GNU_WRITER_NATIVE_JIT entry=(0x[0-9a-f]+) "
      r"size=(0x[0-9a-f]+) count=(\d+) native_after_pc=(0x[0-9a-f]+)$",raw)
    assert (int(jit_writer[0],16),int(jit_writer[1],16),int(jit_writer[3],16))==(STORE,3,pc_write)
    assert 1<=int(jit_writer[2])<=16
    original=ldso[source_offset(ldso,STORE-LDSO_BIAS,8,5):][:8]
    assert original[:3]==bytes.fromhex("498906")
    assert re.search(r"^0x%x:\s+0x49\s+0x89\s+0x06"%STORE,raw,re.M)
    assert re.search(r"^0x%x:\s+0x%016x$"%(TARGET,RESULT),raw,re.M)
    return {
       "schema":"kernix.g0.original-libc-IFUNC105-one-genuine-native-FEX-guest-CALL-exact-C3-RET-hardware-stack-READ-then-GNU-writer.v1",
       "source_original_libc_sha256":LIBC_SHA,"source_original_ldso_sha256":LDSO_SHA,
       "original_source_IFUNC_index":INDEX,
       "source_original_resolver_guest_RIP":hex(RESOLVER),
       "source_original_RET_guest_RIP":hex(chosen_ret),
       "source_original_RET_guest_RIP_candidates":[hex(x) for x in RET_CANDIDATES],
       "native_real_original_RET_stack_read_PC":hex(pc_read),
       "original_guest_stack_read_qword_slot":hex(SLOT),
       "original_guest_source_caller_return_RIP":hex(CALLER_RETURN),
       "actual_native_return_rsp_after_read":hex(rsp_read),
       "original_real_IFUNC105_result_pointer":hex(RESULT),
       "source_GNU_original_guest_writer_RIP":hex(STORE),
       "source_original_target":hex(TARGET),
       "source_original_target_before_qword":hex(OLD),
       "source_original_target_after_qword":hex(RESULT),
       "genuine_original_linux_FEX_ARM64_ONE_process_IFUNC105_CALL_resolver_JIT_C3_RET_native_hardware_read_and_writer_proven":True,
       "native_source_original_IFUNC105_distinct_writer_ledger_count":20,
       "new_unique_relocation_count_due_to_RET_proof":0,
       "all_147_original_libc_RELA_JMPREL_writers_one_process_proven":False,
       "Android_Bionic_Wine_Proton_games_proven":False
    }

def negative_controls(dist:Path):
    raw=(dist/LOG).read_text(errors="replace")
    trials=[
      ("change_source_resolver",r"(KERNIX_G0_IFUNC105_ORIGINAL_RESOLVER_JIT_ENTRY_NATIVE_HW_STOP guest_entry=)0x[0-9a-f]+",r"\g<1>0x8040b4f00"),
      ("change_exact_RET_guest_RIP",r"(KERNIX_G0_IFUNC105_ORIGINAL_C3_RET_JIT_NATIVE_HW_STOP guest_ret=)0x[0-9a-f]+",r"\g<1>0x8040b4f27"),
      ("change_original_RET_guest_RSP",r"(KERNIX_G0_IFUNC105_ORIGINAL_C3_RET_JIT_NATIVE_HW_STOP [^\n]+ guest_rsp=)0x[0-9a-f]+",r"\g<1>0x1"),
      ("change_guest_native_READ_RSP",r"(KERNIX_G0_IFUNC105_REAL_C3_RET_NATIVE_HARDWARE_READ [^\n]+ guest_rsp=)0x[0-9a-f]+",r"\g<1>0x1"),
      ("change_native_READ_rax",r"(KERNIX_G0_IFUNC105_REAL_C3_RET_NATIVE_HARDWARE_READ [^\n]+ guest_rax=)0x[0-9a-f]+",r"\g<1>0x1"),
      ("omit_hardware_READ_watchpoint",r"^Hardware read watchpoint 4: -location \*\(unsigned long long \*\)0x80300f9b8$","MISSING_NATIVE_READ"),
      ("change_caller_return_guest_RIP",r"(KERNIX_G0_IFUNC105_ORIGINAL_CALLER_RESUMED_AFTER_C3_RET guest_entry=)0x[0-9a-f]+",r"\g<1>0x1"),
      ("change_GNU_writer_JIT_guest_RIP",r"(KERNIX_G0_IFUNC105_SAME_PROCESS_ORIGINAL_GNU_WRITER_NATIVE_JIT entry=)0x[0-9a-f]+",r"\g<1>0x1"),
      ("omit_source_native_WRITER_STLR",r"^\s*0x[0-9a-f]+:\s+stlr\s+x4,\s*\[x19\]$","0x0: ldr x4, [x19]"),
      ("change_target_new_qword",r"^New value = 0x8041ab0b0$","New value = 0x1"),
    ]
    names=[]
    for name,pattern,replacement in trials:
       altered,n=re.subn(pattern,replacement,raw,flags=re.M)
       assert n>=1 and altered!=raw,(name,n)
       try:attest(dist,override=altered)
       except AssertionError:names.append(name)
       else:raise AssertionError("FAIL-OPEN: forged real original IFUNC105 hardware log accepted: "+name)
    assert len(names)==10
    return names

def main(dist:Path):
    proof=attest(dist)
    controls=negative_controls(dist)
    proof["ten_genuine_native_hardware_log_corruptions_independently_rejected"]=True
    proof["negative_controls"]=controls
    (dist/OUT).write_text(json.dumps(proof,indent=2)+"\n")
    print("KERNIX_G0_IFUNC105_REAL_ORIGINAL_FEX_ARM64_ONE_GUEST_CALL_EXACT_C3_RET_STACK_HW_READ_GNU_SOURCE_STORE_INDEPENDENTLY_ATTESTED_LEDGER_20_147")

if __name__=="__main__":
    assert len(sys.argv)==2
    main(Path(sys.argv[1]))
