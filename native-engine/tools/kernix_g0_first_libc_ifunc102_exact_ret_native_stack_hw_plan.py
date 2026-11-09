#!/usr/bin/env python3
"""Source-only exact GNU libc IFUNC102 guest C3 RET native hardware read plan.

Must combine source-authentic indirect CALL, resolver JIT entry, first RET
JIT block, original guest return-address slot READ, original GNU caller
return site and real IFUNC target WRITE in ONE new Linux ARM64 FEX guest.

Source-only inputs do not constitute runtime evidence.  The actual FEX
hardware read MUST prove it was executed, not merely source ELF x86 C3.
"""
import hashlib
import json
from pathlib import Path
import sys
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import (
    LIBC_SHA,LDSO_SHA,LIBC_BIAS,LDSO_BIAS,RESOLVER,
    TARGET,BEFORE,CALL,CALLER_RETURN,STORE
)
from kernix_g0_first_libc_ifunc102_call_resolver_native_jit_entry_plan import SLOT
from kernix_g0_first_libc_ifunc102_same_guest_return_writer_plan import (
    GDB as PRIOR_GDB,PLAN as PRIOR_PLAN
)
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset

RET=0x8040b4f27
RET_SOURCE_OFFSET=0xb4f27
SOURCE="original-libc-IFUNC102-exact-C3-RET-hardware-stack-read-source-plan.json"
GDB="original-libc-IFUNC102-exact-C3-RET-and-writer-one-FEX-guest.gdb"
CERTIFIED="original-libc-IFUNC102-same-guest-call-JIT-return-site-write-real-FEX-verified.json"


def prepare(dist:Path):
    root=dist/"original-source-pinned-root"
    libc=(root/"lib/x86_64-linux-gnu/libc.so.6").read_bytes()
    ldso=(root/"lib64/ld-linux-x86-64.so.2").read_bytes()
    assert len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA
    assert len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
    off=source_offset(libc,RET-LIBC_BIAS,1,5)
    assert off==RET_SOURCE_OFFSET
    assert libc[off:off+1]==bytes.fromhex("c3")
    # Guest previous instruction: MOV RAX,RDX then RET (48 89 d0 c3).
    assert libc[off-3:off+1]==bytes.fromhex("4889d0c3")
    assert libc[source_offset(libc,RESOLVER-LIBC_BIAS,4,5):][:4]==bytes.fromhex("f30f1efa")
    assert ldso[source_offset(ldso,CALL-LDSO_BIAS,2,5):][:2]==bytes.fromhex("ffd0")
    assert ldso[source_offset(ldso,CALLER_RETURN-LDSO_BIAS,4,5):][:4]==bytes.fromhex("4883c318")
    assert ldso[source_offset(ldso,STORE-LDSO_BIAS,3,5):][:3]==bytes.fromhex("498906")
    old=json.loads((dist/CERTIFIED).read_text())
    assert old["source_original_libc_sha256"]==LIBC_SHA
    assert old["source_original_ldso_sha256"]==LDSO_SHA
    assert old["one_real_FEX_guest_process_CALL_to_IFUNC_resolver_JIT_and_return_site_target_store_proven"] is True
    assert old["source_guest_IFUNC_index"]==102
    assert old["source_guest_resolver_entry_RIP"]==hex(RESOLVER)
    assert old["source_GNU_caller_JIT_return_site_guest_RIP"]==hex(CALLER_RETURN)
    assert old["source_target_guest_address"]==hex(TARGET)
    assert old["source_target_initial_qword"]==hex(BEFORE)
    assert old["source_target_after_native_FEX_hardware_store"]=="0x8040c74a0"
    assert old["native_hardware_jit_followup_blocks_to_source_caller"]==10
    assert old["ten_same_process_native_hardware_log_mutations_rejected"] is True
    assert len(old["negative_names"])==10
    assert old["explicit_original_guest_IFUNC_RET_opcode_hardware_traced"] is False
    prior=json.loads((dist/PRIOR_PLAN).read_text())
    assert prior["same_guest_IFUNC_call_JIT_return_site_write_proven"] is False
    assert prior["original_CALL_guest_RIP"]==hex(CALL)
    assert prior["original_resolver_entry_guest_RIP"]==hex(RESOLVER)
    assert prior["original_guest_source_writer_RIP"]==hex(STORE)
    assert prior["target_original_RW_NX_guest_address"]==hex(TARGET)
    text=(dist/PRIOR_GDB).read_text()
    cut=text.index("set $return_scans=0\n")
    assert cut>0 and text.endswith("\nquit\n")
    before=text[:cut]
    assert before.count("KERNIX_G0_LIBC_IFUNC102_ORIGINAL_GNU_RESOLVER_JIT_ENTRY_NATIVE_HW_PROVEN")==1
    assert before.count("KERNIX_G0_LIBC_IFUNC102_JIT_NATIVE_RESOLVER_ENTRY_BOUNDED_TERMINAL")==1
    # This is NOT executable proof.  It is an exact GDB instruction-level
    # write/read hardware diagnostic prepared for an independent original
    # source/native Linux ARM64 FEX guest run and source attestation.
    end=r'''set $ret_scan=0
set $ret_found=0
printf "KERNIX_G0_IFUNC102_EXACT_SOURCE_RET_SEARCH_HW_ARMED guest_ret=0x8040b4f27 max_native_header_stops=48 not_executed_yet=1\n"
while $ret_scan < 48 && $ret_found == 0
  continue
  set $ret_scan=$ret_scan+1
  set $h=*(unsigned long long *)$native_state
  set $off=*(unsigned int *)$h
  set $tail=$h+$off
  set $entry=*(unsigned long long *)($tail+8)
  set $size=*(unsigned long long *)($tail+16)
  set $cnt=*(unsigned int *)($tail+24)
  printf "KERNIX_G0_IFUNC102_BEFORE_SOURCE_RET_JIT_HW_STOP idx=%u entry=0x%lx size=0x%lx count=%u native_pc=0x%lx guest_rsp_x8=0x%lx guest_rax_x4=0x%lx\n", $ret_scan,$entry,$size,$cnt,$pc,$x8,$x4
  if $entry == 0x8040b4f27
    set $ret_found=1
    printf "KERNIX_G0_IFUNC102_ORIGINAL_C3_RET_JIT_NATIVE_HW_STOP guest_ret=0x8040b4f27 size=0x%lx native_pc=0x%lx guest_rsp=0x%lx guest_rax=0x%lx native_state=0x%lx not_executed_until_stack_read=1\n", $size,$pc,$x8,$x4,$x28
    x/1bx 0x8040b4f27
    x/gx 0x80300f9b8
  end
end
printf "KERNIX_G0_IFUNC102_SOURCE_C3_RET_JIT_BOUNDED_TERMINAL stops=%u found=%u\n", $ret_scan,$ret_found
if $ret_found == 0
  quit 1
end
disable 3
rwatch -location *(unsigned long long *)0x80300f9b8
condition 4 $pc >= 0xffff00000000 && $x28 == $native_state && $x8 == 0x80300f9b8 && $x4 == 0x8040c74a0
printf "KERNIX_G0_IFUNC102_EXACT_C3_RET_GUEST_QWORD_HW_READ_ARMED slot=0x80300f9b8 target_return=0x80100fd5c original_ret_opcode_c3=1\n"
continue
printf "KERNIX_G0_IFUNC102_EXACT_RET_GUEST_QWORD_REAL_NATIVE_HW_READ pc=0x%lx guest_rsp_x8=0x%lx returned_rax_x4=0x%lx native_state_x28=0x%lx\n", $pc,$x8,$x4,$x28
x/14i $pc-28
set $hdr=*(unsigned long long *)$native_state
set $off=*(unsigned int *)$hdr
set $tail=$hdr+$off
set $entry=*(unsigned long long *)($tail+8)
set $length=*(unsigned long long *)($tail+16)
printf "KERNIX_G0_IFUNC102_EXACT_C3_RET_NATIVE_HW_READ_GUEST_JIT entry=0x%lx length=0x%lx pc=0x%lx\n", $entry,$length,$pc
disable 4
enable 3
continue
set $hdr=*(unsigned long long *)$native_state
set $off=*(unsigned int *)$hdr
set $tail=$hdr+$off
set $entry=*(unsigned long long *)($tail+8)
printf "KERNIX_G0_IFUNC102_AFTER_EXACT_RET_CALLER_NATIVE_JIT_HEADER caller_guest_entry=0x%lx guest_rsp=0x%lx guest_rax=0x%lx guest_r14=0x%lx native_pc=0x%lx\n", $entry,$x8,$x4,$x19,$pc
if $entry != 0x80100fd5c
  quit 1
end
disable 3
printf "KERNIX_G0_IFUNC102_AFTER_EXACT_RET_SOURCE_TARGET_OLD_QWORD target=0x804202d78\n"
x/gx 0x804202d78
watch -location *(unsigned long long *)0x804202d78
condition 5 $pc >= 0xffff00000000 && $x28 == $native_state && $x19 == 0x804202d78 && $x4 == 0x8040c74a0
printf "KERNIX_G0_IFUNC102_AFTER_EXACT_C3_RET_NATIVE_WRITE_WATCH_ARMED target=0x804202d78 guest_writer=0x80100fd60\n"
continue
printf "KERNIX_G0_IFUNC102_SAME_PROCESS_AFTER_RET_NATIVE_IFUNC_STORE_STOP pc=0x%lx guest_rsp=0x%lx guest_rax=0x%lx guest_r14=0x%lx\n", $pc,$x8,$x4,$x19
x/i $pc-4
x/gx 0x804202d78
set $hdr=*(unsigned long long *)$native_state
set $off=*(unsigned int *)$hdr
set $tail=$hdr+$off
set $entry=*(unsigned long long *)($tail+8)
set $size=*(unsigned long long *)($tail+16)
set $cnt=*(unsigned int *)($tail+24)
printf "KERNIX_G0_IFUNC102_AFTER_EXACT_RET_GNU_SOURCE_WRITER_NATIVE_JIT entry=0x%lx size=0x%lx count=%u pc=0x%lx\n", $entry,$size,$cnt,$pc
x/8bx $entry
printf "KERNIX_G0_IFUNC102_EXACT_C3_RET_HW_READ_AND_NATIVE_WRITER_CHAIN_DIAGNOSTIC_FINISHED_NOT_YET_VERIFIED=1\n"
quit
'''
    script=before+end
    assert script.count("awatch -location *(unsigned long long *)0x80300f9b8")==1
    assert script.count("watch -location *(unsigned long long *)$native_state")==1
    assert script.count("rwatch -location *(unsigned long long *)0x80300f9b8")==1
    assert script.count("watch -location *(unsigned long long *)0x804202d78")==1
    assert script.count("quit 1")==2
    assert script.endswith("quit\n")
    (dist/GDB).write_text(script)
    receipt={
        "schema":"kernix.g0.first-original-libc-IFUNC102-explicit-C3-RET-native-stack-read-one-process-source-only.v1",
        "original_source_libc_sha256":LIBC_SHA,
        "original_source_gnu_ldso_sha256":LDSO_SHA,
        "previous_original_FEX_same_process_call_JIT_return_site_target_store_certified":True,
        "exact_original_source_guest_RET_RIP":hex(RET),
        "exact_original_source_libc_RET_ELF_RX_file_offset":hex(off),
        "exact_original_guest_RET_x86_opcode":"c3",
        "original_source_guest_return_stack_slot":hex(SLOT),
        "original_source_guest_return_stack_qword":hex(CALLER_RETURN),
        "source_original_resolver_first_guest_RIP":hex(RESOLVER),
        "source_original_target_write_GNU_guest_RIP":hex(STORE),
        "source_original_target_write_initial_qword":hex(BEFORE),
        "source_guest_target":hex(TARGET),
        "native_guest_hardware_read_of_RET_stack_slot_real_executed":False,
        "real_original_FEX_one_process_RET_read_to_target_write_proven":False,
        "all_46_original_libc_IFUNC_resolvers_proven":False,
        "all_147_original_libc_relocations_closed":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    (dist/SOURCE).write_text(json.dumps(receipt,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_LIBC_IFUNC102_EXACT_C3_RET_SOURCE_SHA256_NATIVE_STACK_READ_PLAN_PASS_NOT_EXECUTED")


if __name__=="__main__":
    assert len(sys.argv)==2
    prepare(Path(sys.argv[1]))
