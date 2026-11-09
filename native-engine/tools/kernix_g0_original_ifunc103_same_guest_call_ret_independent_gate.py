#!/usr/bin/env python3
"""Fail-closed independent ORIGINAL GNU libc #103 CALL/JIT/C3 RET/stack READ/store.

The prior independently verified *different* native writer #103 is a
prerequisite. No same-process #103 return chain is accepted from source
C3 bytes, copied #102 traces, a printed GDB memory read, or a missing native
hardware READ trap. Real Linux ARM64 FEX only; NEVER Android/game proof.
"""
import hashlib
import json
import re
import sys
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import (
    decode_original_libc, LIBC_SHA, LDSO_SHA
)
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_original_ifunc103_same_guest_call_ret_hardware_plan import (
    INDEX,RESOLVER,RET,SLOT,TARGET,OLD,RESULT,CALL,CALLER_RETURN,STORE,
    LIBC_BIAS,LDSO_BIAS,GDB as SCRIPT,OUTPUT as PLAN,WRITER_PROOF
)
from kernix_g0_original_ifunc103_ret_source_candidate_discovery import OUTPUT as RET_PLAN

LOG="original-libc-IFUNC103-same-process-CALL-RET-native-HW-read-source-writer.log"
EXIT="original-libc-IFUNC103-same-process-CALL-RET-native-HW-read-source-writer.exit"
OUTPUT="original-libc-IFUNC103-original-one-FEX-CALL-JIT-C3-RET-stack-read-and-writer-independent.json"


def unique(pattern,source):
    found=re.findall(pattern,source,re.M)
    assert len(found)==1,("expected exactly one genuine native event",pattern,len(found))
    return found[0]


def sequence(source,markers):
    for marker in markers:
        assert source.count(marker)==1,("missing or duplicate event",marker,source.count(marker))
    offsets=[source.index(marker) for marker in markers]
    assert offsets==sorted(offsets) and len(set(offsets))==len(offsets),"broken original guest native chronological sequence"


def verify(dist:Path, *, raw_override=None):
    root=dist/"original-source-pinned-root"
    libc=(root/"lib/x86_64-linux-gnu/libc.so.6").read_bytes()
    ldso=(root/"lib64/ld-linux-x86-64.so.2").read_bytes()
    assert len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA
    assert len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
    row=decode_original_libc(libc)[INDEX]
    assert row["index"]==INDEX and row["table"]=="DT_JMPREL" and row["table_index"]==17
    assert row["r_type"]==37 and row["r_sym"]==0
    assert LIBC_BIAS+row["r_addend"]==RESOLVER
    assert int(row["source_guest_target"],16)==TARGET
    assert int(row["original_source_qword"],16)==OLD
    assert libc[source_offset(libc,RESOLVER-LIBC_BIAS,4,5):][:4]==bytes.fromhex("f30f1efa")
    assert libc[source_offset(libc,RET-LIBC_BIAS,1,5)]==0xc3
    assert ldso[source_offset(ldso,CALL-LDSO_BIAS,2,5):][:2]==bytes.fromhex("ffd0")
    assert ldso[source_offset(ldso,CALLER_RETURN-LDSO_BIAS,4,5):][:4]==bytes.fromhex("4883c318")
    assert ldso[source_offset(ldso,STORE-LDSO_BIAS,3,5):][:3]==bytes.fromhex("498906")
    candidate=json.loads((dist/RET_PLAN).read_text())
    assert candidate["source_original_libc_sha256"]==LIBC_SHA
    assert candidate["source_original_ldso_sha256"]==LDSO_SHA
    assert candidate["original_resolver_source_RIP"]==hex(RESOLVER)
    assert len(candidate["source_disassembled_ret_candidates"])==1
    assert candidate["source_disassembled_ret_candidates"][0]["guest_source_RIP"]==hex(RET)
    assert candidate["source_disassembly_ret_candidates_are_not_execution_proof"] is True
    assert candidate["native_FEX_original_IFUNC103_return_stack_hardware_read_proven"] is False
    writer=json.loads((dist/WRITER_PROOF).read_text())
    assert writer["source_original_ifunc_index"]==INDEX
    assert writer["source_original_resolver_guest_RIP"]==hex(RESOLVER)
    assert writer["source_original_relocation_guest_target"]==hex(TARGET)
    assert writer["original_target_old_qword"]==hex(OLD)
    assert writer["actual_native_hardware_new_qword"]==hex(RESULT)
    assert writer["nine_source_locked_native_hardware_tamper_controls_rejected"] is True
    assert writer["IFUNC103_distinct_native_hardware_writer_independently_proven"] is True
    assert writer["unique_original_libc_individual_native_writer_receipts"]==18
    assert writer["IFUNC103_resolver_CALL_RET_same_process_proven"] is False
    plan=json.loads((dist/PLAN).read_text())
    assert plan["source_libc_sha256"]==LIBC_SHA and plan["source_ldso_sha256"]==LDSO_SHA
    assert plan["original_ifunc_index"]==INDEX
    assert plan["original_resolver_guest_RIP"]==hex(RESOLVER)
    assert plan["original_source_RET_guest_RIP"]==hex(RET)
    assert plan["original_source_RET_opcode"]=="c3"
    assert plan["original_guest_return_site"]==hex(CALLER_RETURN)
    assert plan["original_guest_return_stack_slot"]==hex(SLOT)
    assert plan["original_IFUNC103_target"]==hex(TARGET)
    assert plan["expected_real_original_resolver_result_from_prior_write_only_hardware_proof"]==hex(RESULT)
    assert plan["previous_unique_native_hardware_writers_independently_certified"]==18
    assert plan["source_plan_only_not_runtime_proof"] is True
    assert plan["actual_native_hardware_RET_read_and_same_process_writer_proven"] is False
    script=(dist/SCRIPT).read_text()
    assert script.count("awatch -location *(unsigned long long *)"+hex(SLOT))==1
    assert script.count("rwatch -location *(unsigned long long *)"+hex(SLOT))==1
    assert script.count("watch -location *(unsigned long long *)"+hex(TARGET))==1
    assert script.count("watch -location *(unsigned long long *)$native_state")==1
    assert "condition 4 " not in script
    assert (dist/EXIT).read_text().strip()=="0"
    raw=(dist/LOG).read_text(errors="replace") if raw_override is None else raw_override
    assert "Error in sourced command file" not in raw and "No registers." not in raw
    markers=[
      "KERNIX_G0_IFUNC103_ORIGINAL_CALL_STACK_HW_WATCH_ARMED ",
      "KERNIX_G0_IFUNC103_ORIGINAL_CALL_NATIVE_STACK_HW_HIT ",
      "KERNIX_G0_IFUNC103_ORIGINAL_RESOLVER_JIT_ENTRY_NATIVE_HW_STOP ",
      "KERNIX_G0_IFUNC103_RESOLVER_BOUNDED_SCAN_DONE ",
      "KERNIX_G0_IFUNC103_ORIGINAL_C3_RET_JIT_NATIVE_HW_STOP ",
      "KERNIX_G0_IFUNC103_SOURCE_RET_JIT_BOUNDED_DONE ",
      "KERNIX_G0_IFUNC103_C3_RET_ORIGINAL_RETURN_STACK_HW_READ_ARMED ",
      "KERNIX_G0_IFUNC103_REAL_C3_RET_NATIVE_HARDWARE_READ ",
      "KERNIX_G0_IFUNC103_AFTER_HARDWARE_READ_SOURCE_JIT ",
      "KERNIX_G0_IFUNC103_ORIGINAL_CALLER_RESUMED_AFTER_C3_RET ",
      "KERNIX_G0_IFUNC103_POST_C3_RET_SOURCE_TARGET_BEFORE_NATIVE_WRITER ",
      "KERNIX_G0_IFUNC103_SAME_PROCESS_POST_RET_NATIVE_WRITER_HW_HIT ",
      "KERNIX_G0_IFUNC103_SAME_PROCESS_ORIGINAL_GNU_WRITER_NATIVE_JIT ",
      "KERNIX_G0_IFUNC103_ONE_ORIGINAL_FEX_GUEST_CALL_NATIVE_RET_STACK_READ_AND_GNU_STORE_DIAGNOSTIC_COMPLETE_NOT_INDEPENDENTLY_ATTESTED=1",
    ]
    sequence(raw,markers)
    # Real traps MUST occur AFTER their own hardware watch armed and BEFORE
    # the semantic label; source GDB printf (or plain x/gx) isn't a trap.
    trap_read="Hardware read watchpoint 4: -location *(unsigned long long *)"+hex(SLOT)
    read_arm=raw.index(markers[6]);read_label=raw.index(markers[7])
    assert raw.count(trap_read)>=2
    assert trap_read in raw[read_arm:read_label]
    trap_write="Hardware watchpoint 5: -location *(unsigned long long *)"+hex(TARGET)
    write_arm=raw.index(markers[10]);write_label=raw.index(markers[11])
    assert raw.count(trap_write)>=2
    assert trap_write in raw[write_arm:write_label]
    call=unique(
      r"^KERNIX_G0_IFUNC103_ORIGINAL_CALL_NATIVE_STACK_HW_HIT resolver_rax_x4=(0x[0-9a-f]+) "
      r"guest_rsp_x8=(0x[0-9a-f]+) native_after_pc=(0x[0-9a-f]+)$",raw)
    assert int(call[0],16)==RESOLVER and int(call[1],16)==SLOT
    assert int(call[2],16)>=0xffff00000000
    assert re.search(r"^0x%x:\s+0x[0-9a-f]{16}$"%SLOT,raw,re.M)
    assert re.search(r"^0x%x:\s+0x000000080100fd5c$"%SLOT,raw,re.M)
    entry=unique(
      r"^KERNIX_G0_IFUNC103_ORIGINAL_RESOLVER_JIT_ENTRY_NATIVE_HW_STOP "
      r"guest_entry=(0x[0-9a-f]+) native_pc=(0x[0-9a-f]+) guest_rsp=(0x[0-9a-f]+)$",raw)
    assert (int(entry[0],16),int(entry[2],16))==(RESOLVER,SLOT)
    assert int(entry[1],16)>=0xffff00000000
    assert re.search(r"^0x%x:\s+0xf3\s+0x0f\s+0x1e\s+0xfa"%RESOLVER,raw,re.M)
    rt=unique(
      r"^KERNIX_G0_IFUNC103_ORIGINAL_C3_RET_JIT_NATIVE_HW_STOP "
      r"guest_ret=(0x[0-9a-f]+) size=(0x[0-9a-f]+) native_pc=(0x[0-9a-f]+) "
      r"guest_rsp=(0x[0-9a-f]+) guest_rax=(0x[0-9a-f]+) native_state=(0x[0-9a-f]+)$",raw)
    assert (int(rt[0],16),int(rt[1],16),int(rt[3],16),int(rt[4],16))==(RET,1,SLOT,RESULT)
    assert int(rt[2],16)>=0xffff00000000 and int(rt[5],16)>=0xffff00000000
    assert re.search(r"^0x%x:\s+0xc3$"%RET,raw,re.M)
    read=unique(
      r"^KERNIX_G0_IFUNC103_REAL_C3_RET_NATIVE_HARDWARE_READ "
      r"pc=(0x[0-9a-f]+) guest_rsp=(0x[0-9a-f]+) "
      r"guest_rax=(0x[0-9a-f]+) state_x28=(0x[0-9a-f]+)$",raw)
    pc,rsp,rax,state=(int(x,16) for x in read)
    assert pc>=0xffff00000000 and pc%4==0
    assert (rsp,rax,state)==(SLOT+8,RESULT,int(rt[5],16))
    hw=unique(
      r"^KERNIX_G0_IFUNC103_AFTER_HARDWARE_READ_SOURCE_JIT "
      r"guest_entry=(0x[0-9a-f]+) source_size=(0x[0-9a-f]+) native_after_pc=(0x[0-9a-f]+)$",raw)
    assert (int(hw[0],16),int(hw[1],16),int(hw[2],16))==(RET,1,pc)
    caller=unique(
      r"^KERNIX_G0_IFUNC103_ORIGINAL_CALLER_RESUMED_AFTER_C3_RET "
      r"guest_entry=(0x[0-9a-f]+) rsp=(0x[0-9a-f]+) rax=(0x[0-9a-f]+) "
      r"native_pc=(0x[0-9a-f]+) target_r14=(0x[0-9a-f]+)$",raw)
    assert tuple(int(v,16) for v in caller[:3])==(CALLER_RETURN,SLOT+8,RESULT)
    assert int(caller[3],16)>=0xffff00000000 and int(caller[4],16)==TARGET
    assert re.search(r"^0x%x:\s+0x48\s+0x83\s+0xc3\s+0x18"%CALLER_RETURN,raw,re.M)
    assert re.search(r"^0x%x:\s+0x00000000000283b0$"%TARGET,raw,re.M)
    # Source target post-native actual store may have subsequent lines;
    # require specific 64-bit hardware memory value in the same native log.
    assert re.search(r"^0x%x:\s+0x00000008040c83a0$"%TARGET,raw,re.M)
    writer=unique(
      r"^KERNIX_G0_IFUNC103_SAME_PROCESS_POST_RET_NATIVE_WRITER_HW_HIT "
      r"pc=(0x[0-9a-f]+) rsp=(0x[0-9a-f]+) rax=(0x[0-9a-f]+) r14=(0x[0-9a-f]+)$",raw)
    writer_pc=int(writer[0],16)
    assert writer_pc>=0xffff00000000 and writer_pc%4==0
    assert tuple(int(v,16) for v in writer[1:])==(SLOT+8,RESULT,TARGET)
    assert re.search(r"^\s*0x%x:\s+stlr\s+x4,\s*\[x19\]\s*$"%(writer_pc-4),raw,re.M)
    jit=unique(
      r"^KERNIX_G0_IFUNC103_SAME_PROCESS_ORIGINAL_GNU_WRITER_NATIVE_JIT "
      r"entry=(0x[0-9a-f]+) size=(0x[0-9a-f]+) count=(\d+) "
      r"native_after_pc=(0x[0-9a-f]+)$",raw)
    assert (int(jit[0],16),int(jit[1],16),int(jit[3],16))==(STORE,3,writer_pc)
    assert 1<=int(jit[2])<=16
    assert re.search(r"^0x%x:\s+0x49\s+0x89\s+0x06"%STORE,raw,re.M)
    return {
      "schema":"kernix.g0.original-libc-IFUNC103-one-real-FEX-ARM64-guest-CALL-JIT-C3-RET-stack-HW-READ-to-GNU-writer.v1",
      "original_source_libc_sha256":LIBC_SHA,"original_source_ldso_sha256":LDSO_SHA,
      "source_ifunc_relocation_index":INDEX,
      "source_original_resolver_entry":hex(RESOLVER),
      "real_original_resolver_JIT_entry_hardware_observed":True,
      "original_source_C3_RET_guest_RIP":hex(RET),
      "native_real_C3_RET_guest_stack_hardware_read_observed":True,
      "original_guest_stack_source_SLOT":hex(SLOT),
      "original_return_to_GNU_caller_RIP":hex(CALLER_RETURN),
      "real_original_resolver_return_value":hex(RESULT),
      "real_native_read_after_PC":hex(pc),
      "real_original_GNU_writer_guest_RIP":hex(STORE),
      "real_original_GNU_writer_target":hex(TARGET),
      "real_native_writer_after_PC":hex(writer_pc),
      "same_process_original_FEX_CALL_resolver_JIT_exact_C3_RET_stack_HW_READ_caller_and_source_writer_proven":True,
      "previous_independent_18_unique_writer_targets_unchanged":18,
      "all_147_original_libc_relocations_proven":False,
      "Android_Bionic_Wine_Proton_games_proven":False,
    }


def negative_controls(dist:Path):
    raw=(dist/LOG).read_text(errors="replace")
    changes=[
        ("call_target_changed",r"(^KERNIX_G0_IFUNC103_ORIGINAL_CALL_NATIVE_STACK_HW_HIT resolver_rax_x4=)0x[0-9a-f]+",r"\g<1>0x8040b4f00"),
        ("resolver_entry_changed",r"(^KERNIX_G0_IFUNC103_ORIGINAL_RESOLVER_JIT_ENTRY_NATIVE_HW_STOP guest_entry=)0x[0-9a-f]+",r"\g<1>0x8040b4f00"),
        ("source_ret_guest_RIP_changed",r"(^KERNIX_G0_IFUNC103_ORIGINAL_C3_RET_JIT_NATIVE_HW_STOP guest_ret=)0x[0-9a-f]+",r"\g<1>0x8040b4f27"),
        ("source_ret_size_changed",r"(^KERNIX_G0_IFUNC103_ORIGINAL_C3_RET_JIT_NATIVE_HW_STOP [^\n]+ size=)0x[0-9a-f]+",r"\g<1>0x2"),
        ("real_ret_read_event_removed",r"^KERNIX_G0_IFUNC103_REAL_C3_RET_NATIVE_HARDWARE_READ [^\n]+$","MISSING_REAL_READ_EVENT"),
        ("real_ret_read_rsp_changed",r"(^KERNIX_G0_IFUNC103_REAL_C3_RET_NATIVE_HARDWARE_READ [^\n]+ guest_rsp=)0x[0-9a-f]+",r"\g<1>0x80300f9b8"),
        ("read_native_header_changed",r"(^KERNIX_G0_IFUNC103_AFTER_HARDWARE_READ_SOURCE_JIT guest_entry=)0x[0-9a-f]+",r"\g<1>0x8040b4f27"),
        ("wrong_guest_caller",r"(^KERNIX_G0_IFUNC103_ORIGINAL_CALLER_RESUMED_AFTER_C3_RET guest_entry=)0x[0-9a-f]+",r"\g<1>0x1"),
        ("wrong_GNU_writer_target_register",r"(^KERNIX_G0_IFUNC103_SAME_PROCESS_POST_RET_NATIVE_WRITER_HW_HIT [^\n]+ r14=)0x[0-9a-f]+",r"\g<1>0x804202d78"),
        ("wrong_GNU_writer_source_JIT",r"(^KERNIX_G0_IFUNC103_SAME_PROCESS_ORIGINAL_GNU_WRITER_NATIVE_JIT entry=)0x[0-9a-f]+",r"\g<1>0x1"),
        ("hardware_read_watch_deleted",r"^Hardware read watchpoint 4: -location \*\(unsigned long long \*\)0x80300f9b8$","MISSING_REAL_RWATCH"),
        ("hardware_writer_watch_deleted",r"^Hardware watchpoint 5: -location \*\(unsigned long long \*\)0x804202d68$","MISSING_REAL_WRITE_WATCH"),
    ]
    names=[]
    for name,pat,replacement in changes:
        mutated,count=re.subn(pat,replacement,raw,flags=re.M)
        assert count>=1 and mutated!=raw,(name,count)
        try:
            verify(dist,raw_override=mutated)
        except AssertionError:
            names.append(name)
        else:
            raise AssertionError("FAIL OPEN: accepted forged native original IFUNC103 evidence: "+name)
    assert len(names)==12
    return names


def main(dist:Path):
    proof=verify(dist)
    cases=negative_controls(dist)
    proof["twelve_actual_native_hardware_evidence_tamper_cases_rejected"]=True
    proof["negative_case_names"]=cases
    (dist/OUTPUT).write_text(json.dumps(proof,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_LIBC_IFUNC103_EXACT_SOURCE_C3_RET_GUEST_STACK_REAL_ARM64_FEX_HW_READ_CALLER_AND_GNU_NATIVE_WRITER_INDEPENDENT_PASS_NO_147_CLOSURE")


if __name__=="__main__":
    assert len(sys.argv)==2
    main(Path(sys.argv[1]))
