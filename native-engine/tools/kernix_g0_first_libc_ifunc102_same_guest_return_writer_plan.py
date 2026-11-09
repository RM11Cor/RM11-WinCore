#!/usr/bin/env python3
"""Source-only native FEX same-process IFUNC102 CALL -> resolver JIT -> caller -> write probe.

A source-only plan can NOT prove any new guest instruction executed. A real
Linux AArch64 FEX run and separate strict hardware log attestation are mandatory.
Do not assert explicit guest RET opcode from caller JIT-header transitions.
"""
import hashlib
import json
from pathlib import Path
import sys

from kernix_g0_first_libc_ifunc102_original_fex_source_watch import (
    LIBC_SHA,LDSO_SHA,LIBC_BIAS,LDSO_BIAS,
    RESOLVER,TARGET,BEFORE,CALL,CALLER_RETURN,STORE
)
from kernix_g0_first_libc_ifunc102_call_resolver_native_jit_entry_plan import (
    PLAN as CALL_PLAN,GDB as CALL_GDB,SLOT
)
from kernix_g0_original_libc_relocation_type_transition_gate import (
    decode_original_libc,classify
)
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset

PLAN="original-libc-IFUNC102-same-guest-call-JIT-return-site-write-source-plan.json"
GDB="original-libc-IFUNC102-same-guest-call-JIT-return-site-write.gdb"
SOURCE_CALL_RECEIPT="original-libc-first-IFUNC102-call-target-JIT-entry-real-FEX-verified.json"
FIRST_WRITER_RECEIPT="original-libc-first-IRELATIVE-102-real-FEX-native-writer-only-proof.json"

def prepare(dist:Path):
    root=dist/"original-source-pinned-root"
    lp=root/"lib/x86_64-linux-gnu/libc.so.6"
    dp=root/"lib64/ld-linux-x86-64.so.2"
    assert lp.is_file() and not lp.is_symlink()
    assert dp.is_file() and not dp.is_symlink()
    libc,ldso=lp.read_bytes(),dp.read_bytes()
    assert len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA
    assert len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
    typed=classify(decode_original_libc(libc))
    assert typed==json.loads((dist/"original-libc-147-rela-jmprel-typed-source-next-stage-plan.json").read_text())
    assert typed["original_source_IRELATIVE_count"]==46
    row=decode_original_libc(libc)[102]
    assert row["table"]=="DT_JMPREL" and row["r_type"]==37 and row["r_sym"]==0
    assert row["r_addend"]==RESOLVER-LIBC_BIAS
    assert int(row["source_guest_target"],16)==TARGET
    assert int(row["original_source_qword"],16)==BEFORE
    assert libc[source_offset(libc,RESOLVER-LIBC_BIAS,4,5):][:4]==bytes.fromhex("f30f1efa")
    assert ldso[source_offset(ldso,CALL-LDSO_BIAS,2,5):][:2]==bytes.fromhex("ffd0")
    assert ldso[source_offset(ldso,CALLER_RETURN-LDSO_BIAS,4,5):][:4]==bytes.fromhex("4883c318")
    assert ldso[source_offset(ldso,STORE-LDSO_BIAS,3,5):][:3]==bytes.fromhex("498906")

    first=json.loads((dist/FIRST_WRITER_RECEIPT).read_text())
    assert first["original_libc_sha256"]==LIBC_SHA
    assert first["original_ldso_sha256"]==LDSO_SHA
    assert first["first_IFUNC_source_index"]==102
    assert first["source_resolver_guest_entry"]==hex(RESOLVER)
    assert first["actual_native_hardware_writer_qword"]=="0x8040c74a0"
    assert first["first_IFUNC_native_hardware_target_write_proven"] is True
    assert first["seven_actual_native_FEX_log_tamper_controls_rejected"] is True
    assert first["original_IFUNC_resolver_call_return_same_process_proven"] is False

    call=json.loads((dist/SOURCE_CALL_RECEIPT).read_text())
    assert call["original_libc_sha256"]==LIBC_SHA
    assert call["original_ldso_sha256"]==LDSO_SHA
    assert call["same_original_FEX_native_guest_process_call_and_JIT_entry_proven"] is True
    assert call["original_GNU_x86_indirect_CALL_guest_RIP"]==hex(CALL)
    assert call["native_guest_call_target_x4"]==hex(RESOLVER)
    assert call["native_guest_call_stack_return_slot"]==hex(SLOT)
    assert call["original_guest_return_address_qword"]==hex(CALLER_RETURN)
    assert call["actual_source_libc_resolver_JIT_entry"]==hex(RESOLVER)
    assert call["first_source_JIT_guest_entry_original_ENDBR64_verified"] is True
    assert call["six_genuine_source_call_JIT_hardware_log_tamper_cases_rejected"] is True
    assert len(call["negative_case_names"])==6
    assert call["original_resolver_guest_return_opcode_executed_proven"] is False
    assert call["first_IFUNC_call_entry_return_writer_chain_same_process_proven"] is False

    prior=json.loads((dist/CALL_PLAN).read_text())
    assert prior["exact_expected_resolver_guest_RIP"]==hex(RESOLVER)
    assert prior["original_guest_return_address_qword"]==hex(CALLER_RETURN)
    assert prior["source_original_guest_target"]==hex(TARGET)
    assert prior["source_original_previous_on_disk_qword"]==hex(BEFORE)
    src=(dist/CALL_GDB).read_text()
    assert src.endswith("\nquit\n") and src.count("\nquit\n")==1
    assert src.count("KERNIX_G0_LIBC_IFUNC102_ORIGINAL_GNU_RESOLVER_JIT_ENTRY_NATIVE_HW_PROVEN")==1
    assert src.count("KERNIX_G0_LIBC_IFUNC102_JIT_NATIVE_RESOLVER_ENTRY_BOUNDED_TERMINAL")==1
    # Continue using the SAME guest process, FEX native state header watch,
    # and original source x86 CALL -> original resolver entry JIT witness.
    # Exact guest RET not inferred from a return-site JIT header alone.
    continuation=r'''set $return_scans=0
set $return_site_found=0
printf "KERNIX_G0_IFUNC102_SOURCE_RETURN_SITE_FOLLOWUP_ARMED target=0x80100fd5c max_native_jit_headers=256 explicit_guest_ret_opcode_not_yet_proven=1\n"
while $return_scans < 256 && $return_site_found == 0
  continue
  set $return_scans=$return_scans+1
  set $header=*(unsigned long long *)$native_state
  if $header != 0
    set $offset=*(unsigned int *)$header
    set $tail=$header+$offset
    set $guest_entry=*(unsigned long long *)($tail+8)
    set $guest_size=*(unsigned long long *)($tail+16)
    set $count=*(unsigned int *)($tail+24)
    printf "KERNIX_G0_IFUNC102_FOLLOWUP_REAL_FEX_JIT_HEADER ordinal=%u guest_entry=0x%lx size=0x%lx count=%u native_pc=0x%lx guest_rsp_x8=0x%lx guest_rax_x4=0x%lx guest_r14_x19=0x%lx\n", $return_scans,$guest_entry,$guest_size,$count,$pc,$x8,$x4,$x19
    if $guest_entry == 0x80100fd5c
      set $return_site_found=1
      printf "KERNIX_G0_IFUNC102_REAL_ORIGINAL_CALLER_RETURN_SITE_JIT_HW_STOP target=0x80100fd5c native_pc=0x%lx guest_rsp=0x%lx guest_rax=0x%lx guest_r14=0x%lx explicit_guest_ret_opcode_not_proven=1\n", $pc,$x8,$x4,$x19
      x/8bx 0x80100fd5c
      x/gx 0x80300f9b8
    end
  end
end
printf "KERNIX_G0_IFUNC102_RETURN_SITE_SOURCE_BOUNDED_TERMINAL stops=%u found=%u native_guest_specific_ret_opcode_not_traced=1\n", $return_scans,$return_site_found
if $return_site_found == 0
  printf "KERNIX_G0_IFUNC102_RETURN_SITE_MISSING_FAIL_CLOSED\n"
  quit 1
end
disable 3
printf "KERNIX_G0_IFUNC102_POST_REAL_RETURN_SITE_PRE_WRITER_TARGET_SOURCE_INITIAL target=0x804202d78 qword_follows=1\n"
x/gx 0x804202d78
watch -location *(unsigned long long *)0x804202d78
condition 4 $pc >= 0xffff00000000 && $x28 == $native_state
printf "KERNIX_G0_IFUNC102_SAME_PROCESS_NATIVE_WRITER_WATCH_ARMED target=0x804202d78 correct_source_GNU_writer=0x80100fd60 proof_pending=1\n"
continue
printf "KERNIX_G0_IFUNC102_SAME_PROCESS_NATIVE_HW_WRITER_STOP pc=0x%lx x4_rax=0x%lx x19_r14=0x%lx x8_rsp=0x%lx x28_state=0x%lx\n", $pc,$x4,$x19,$x8,$x28
x/gx 0x804202d78
x/i $pc-4
set $hdr=*(unsigned long long *)$x28
set $off=*(unsigned int *)$hdr
set $tail=$hdr+$off
set $entry=*(unsigned long long *)($tail+8)
set $size=*(unsigned long long *)($tail+16)
set $count=*(unsigned int *)($tail+24)
printf "KERNIX_G0_IFUNC102_SAME_PROCESS_NATIVE_HW_WRITER_SOURCE_JIT guest_entry=0x%lx guest_size=0x%lx count=%u native_after_pc=0x%lx\n", $entry,$size,$count,$pc
x/8bx $entry
x/gx 0x80300f9b8
printf "KERNIX_G0_IFUNC102_SAME_GUEST_SOURCE_CHAIN_DIAGNOSTIC_END_SPECIFIC_RET_OPCODE_NOT_TRACED=1\n"
quit
'''
    # Derive from previously accepted call->JIT source GDB without changing
    # its genuine source CALL hardware stop, JIT header or range predicates.
    gdb=src[:-len("quit\n")]+continuation
    assert gdb.count("awatch -location *(unsigned long long *)0x80300f9b8")==1
    assert gdb.count("watch -location *(unsigned long long *)$native_state")==1
    assert gdb.count("watch -location *(unsigned long long *)0x804202d78")==1
    assert gdb.count("KERNIX_G0_IFUNC102_SAME_PROCESS_NATIVE_HW_WRITER_SOURCE_JIT")==1
    assert "quit 1" in gdb and not gdb.endswith("quit 1\n")
    assert gdb.endswith("quit\n")
    (dist/GDB).write_text(gdb)
    proof={
        "schema":"kernix.g0.first-original-IFUNC102-source-only-CALL-JIT-return-site-actual-writer-chain.v1",
        "source_original_libc_sha256":LIBC_SHA,
        "source_original_ldso_sha256":LDSO_SHA,
        "prior_first_native_writer_receipt_independent":True,
        "prior_same_guest_original_CALL_and_resolver_JIT_entry_receipt_independent":True,
        "original_resolver_entry_guest_RIP":hex(RESOLVER),
        "original_CALL_guest_RIP":hex(CALL),
        "source_guest_caller_return_site":hex(CALLER_RETURN),
        "original_guest_source_writer_RIP":hex(STORE),
        "original_GNU_source_writer_opcode":"498906",
        "target_original_RW_NX_guest_address":hex(TARGET),
        "original_target_old_qword":hex(BEFORE),
        "real_original_linux_arm64_FEX_guest_executed_by_this_plan":False,
        "same_guest_IFUNC_call_JIT_return_site_write_proven":False,
        "explicit_guest_IFUNC_RET_opcode_proven":False,
        "source_all_46_IFUNC_resolvers_completed":False,
        "all_original_147_relocations_closed_in_one_guest":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    (dist/PLAN).write_text(json.dumps(proof,indent=2)+"\n")
    print("KERNIX_G0_IFUNC102_SINGLE_GUEST_CALL_JIT_RETURN_SITE_WRITER_NATIVE_WATCH_PLAN_SOURCE_ONLY_PASS")


if __name__=="__main__":
    assert len(sys.argv)==2
    prepare(Path(sys.argv[1]))
