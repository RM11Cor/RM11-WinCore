#!/usr/bin/env python3
"""Plan one unmodified source GNU IFUNC103 CALL/JIT/C3-RET HW read/caller/store.

Source-only plan; the script is NOT a native runtime receipt. Native FEX Linux
ARM64 and a separate strict replay are required to certify the actual chain.
"""
import hashlib,json,sys
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import decode_original_libc, LIBC_SHA, LDSO_SHA
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import GUEST_MAIN,LIBC_BIAS,LDSO_BIAS,CALL,CALLER_RETURN,STORE
from kernix_g0_original_ifunc103_ret_source_candidate_discovery import OUTPUT as RET_PLAN

INDEX=103
RESOLVER=0x8040b4f90
RET=0x8040b4fb4
SLOT=0x80300f9b8
TARGET=0x804202d68
OLD=0x283b0
RESULT=0x8040c83a0
GDB="original-libc-IFUNC103-original-one-FEX-CALL-C3-RET-native-HW-read-and-GNU-writer.gdb"
OUTPUT="original-libc-IFUNC103-original-one-FEX-CALL-C3-RET-native-HW-read-source-plan.json"
WRITER_PROOF="original-libc-IFUNC103-independently-source-verified-real-FEX-native-write-only.json"

def prepare(dist:Path,repo:Path):
    root=dist/"original-source-pinned-root"
    libc=(root/"lib/x86_64-linux-gnu/libc.so.6").read_bytes()
    ldso=(root/"lib64/ld-linux-x86-64.so.2").read_bytes()
    assert len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA
    assert len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
    row=decode_original_libc(libc)[INDEX]
    assert row["index"]==INDEX and row["table"]=="DT_JMPREL" and row["r_type"]==37 and row["r_sym"]==0
    assert row["r_addend"]==RESOLVER-LIBC_BIAS
    assert int(row["source_guest_target"],16)==TARGET and int(row["original_source_qword"],16)==OLD
    ret=json.loads((dist/RET_PLAN).read_text())
    assert ret["original_IFUNC_source_index"]==INDEX
    assert ret["original_resolver_source_RIP"]==hex(RESOLVER)
    assert ret["source_original_libc_sha256"]==LIBC_SHA and ret["source_original_ldso_sha256"]==LDSO_SHA
    assert ret["source_disassembled_ret_candidates"]==[{
        "original_elf_virtual_address":hex(RET-LIBC_BIAS),
        "guest_source_RIP":hex(RET),
        "original_x86_opcode":"c3",
        "source_ELF_RX_offset":hex(RET-LIBC_BIAS),
        "source_disassembler_mnemonic":"ret",
    }]
    assert ret["native_FEX_original_IFUNC103_return_stack_hardware_read_proven"] is False
    assert libc[source_offset(libc,RESOLVER-LIBC_BIAS,4,5):][:4]==bytes.fromhex("f30f1efa")
    assert libc[source_offset(libc,RET-LIBC_BIAS,1,5)]==0xc3
    assert ldso[source_offset(ldso,CALL-LDSO_BIAS,2,5):][:2]==bytes.fromhex("ffd0")
    assert ldso[source_offset(ldso,CALLER_RETURN-LDSO_BIAS,4,5):][:4]==bytes.fromhex("4883c318")
    assert ldso[source_offset(ldso,STORE-LDSO_BIAS,3,5):][:3]==bytes.fromhex("498906")
    old=json.loads((dist/WRITER_PROOF).read_text())
    assert old["source_original_ifunc_index"]==INDEX and old["source_original_resolver_guest_RIP"]==hex(RESOLVER)
    assert old["source_original_relocation_guest_target"]==hex(TARGET)
    assert old["actual_native_hardware_new_qword"]==hex(RESULT)
    assert old["IFUNC103_distinct_native_hardware_writer_independently_proven"] is True
    assert old["nine_source_locked_native_hardware_tamper_controls_rejected"] is True
    assert old["unique_original_libc_individual_native_writer_receipts"]==18
    assert old["IFUNC103_resolver_CALL_RET_same_process_proven"] is False
    source=(repo/GUEST_MAIN).read_text().splitlines()
    bps=[i for i,line in enumerate(source,1) if line.strip()=="ctx->ExecuteThread(thread);"]
    assert len(bps)==1
    bp=bps[0]
    # Genuine source-anchored ARM64 FEX GDB hardware traps; no guest fixture
    # or direct writes. PC/registers are sampled after actual HW events.
    # The native stack-read RSP condition must NOT be applied pre-RET:
    # the x86 C3 RET advances RSP to SLOT+8 during the native load.
    script=f'''set pagination off
set confirm off
set breakpoint pending on
set output-radix 16
handle SIGBUS nostop noprint pass
handle SIGCHLD nostop noprint pass
break {GUEST_MAIN}:{bp}
commands
silent
printf "KERNIX_G0_IFUNC103_ORIGINAL_CALL_STACK_HW_WATCH_ARMED resolver={hex(RESOLVER)} slot={hex(SLOT)} expected_return={hex(CALLER_RETURN)}\\n"
x/gx {hex(SLOT)}
awatch -location *(unsigned long long *){hex(SLOT)}
condition 2 $pc >= 0xffff00000000 && $x28 >= 0xffff00000000 && $x8 == {hex(SLOT)} && $x4 == {hex(RESOLVER)} && *(unsigned long long *){hex(SLOT)} == {hex(CALLER_RETURN)}
continue
end
run
printf "KERNIX_G0_IFUNC103_ORIGINAL_CALL_NATIVE_STACK_HW_HIT resolver_rax_x4=0x%lx guest_rsp_x8=0x%lx native_after_pc=0x%lx\\n", $x4,$x8,$pc
x/i $pc-4
x/gx {hex(SLOT)}
x/8bx {hex(CALL)}
disable 2
set $native_state=$x28
watch -location *(unsigned long long *)$native_state
condition 3 $pc >= 0xffff00000000 && $x28 == $native_state
set $resolver_scans=0
set $resolver_found=0
while $resolver_scans < 64 && $resolver_found == 0
  continue
  set $resolver_scans=$resolver_scans+1
  set $hdr=*(unsigned long long *)$native_state
  if $hdr != 0
    set $off=*(unsigned int *)$hdr
    set $tail=$hdr+$off
    set $entry=*(unsigned long long *)($tail+8)
    set $size=*(unsigned long long *)($tail+16)
    set $cnt=*(unsigned int *)($tail+24)
    printf "KERNIX_G0_IFUNC103_RESOLVER_SEARCH_REAL_JIT idx=%u entry=0x%lx size=0x%lx native_pc=0x%lx count=%u rsp=0x%lx\\n", $resolver_scans,$entry,$size,$pc,$cnt,$x8
    if $entry == {hex(RESOLVER)}
      set $resolver_found=1
      printf "KERNIX_G0_IFUNC103_ORIGINAL_RESOLVER_JIT_ENTRY_NATIVE_HW_STOP guest_entry=0x%lx native_pc=0x%lx guest_rsp=0x%lx\\n", $entry,$pc,$x8
      x/8bx {hex(RESOLVER)}
    end
  end
end
printf "KERNIX_G0_IFUNC103_RESOLVER_BOUNDED_SCAN_DONE stops=%u found=%u\\n", $resolver_scans,$resolver_found
if $resolver_found == 0
  quit 1
end
set $ret_scans=0
set $ret_found=0
while $ret_scans < 96 && $ret_found == 0
  continue
  set $ret_scans=$ret_scans+1
  set $hdr=*(unsigned long long *)$native_state
  if $hdr != 0
    set $off=*(unsigned int *)$hdr
    set $tail=$hdr+$off
    set $entry=*(unsigned long long *)($tail+8)
    set $size=*(unsigned long long *)($tail+16)
    set $cnt=*(unsigned int *)($tail+24)
    printf "KERNIX_G0_IFUNC103_SOURCE_RET_JIT_SEARCH idx=%u entry=0x%lx size=0x%lx native_pc=0x%lx count=%u rsp=0x%lx rax=0x%lx\\n", $ret_scans,$entry,$size,$pc,$cnt,$x8,$x4
    if $entry == {hex(RET)}
      set $ret_found=1
      printf "KERNIX_G0_IFUNC103_ORIGINAL_C3_RET_JIT_NATIVE_HW_STOP guest_ret={hex(RET)} size=0x%lx native_pc=0x%lx guest_rsp=0x%lx guest_rax=0x%lx native_state=0x%lx\\n", $size,$pc,$x8,$x4,$x28
      x/1bx {hex(RET)}
      x/gx {hex(SLOT)}
    end
  end
end
printf "KERNIX_G0_IFUNC103_SOURCE_RET_JIT_BOUNDED_DONE stops=%u found=%u\\n", $ret_scans,$ret_found
if $ret_found == 0
  quit 1
end
if $size != 1 || $x8 != {hex(SLOT)}
  quit 1
end
disable 3
rwatch -location *(unsigned long long *){hex(SLOT)}
printf "KERNIX_G0_IFUNC103_C3_RET_ORIGINAL_RETURN_STACK_HW_READ_ARMED slot={hex(SLOT)} source_ret={hex(RET)}\\n"
continue
printf "KERNIX_G0_IFUNC103_REAL_C3_RET_NATIVE_HARDWARE_READ pc=0x%lx guest_rsp=0x%lx guest_rax=0x%lx state_x28=0x%lx\\n", $pc,$x8,$x4,$x28
x/12i $pc-24
set $hdr=*(unsigned long long *)$native_state
set $off=*(unsigned int *)$hdr
set $tail=$hdr+$off
set $entry=*(unsigned long long *)($tail+8)
set $size=*(unsigned long long *)($tail+16)
printf "KERNIX_G0_IFUNC103_AFTER_HARDWARE_READ_SOURCE_JIT guest_entry=0x%lx source_size=0x%lx native_after_pc=0x%lx\\n", $entry,$size,$pc
if $entry != {hex(RET)} || $size != 1 || $x8 != {hex(SLOT+8)} || $x4 != {hex(RESULT)}
  quit 1
end
disable 4
enable 3
set $caller_scans=0
set $caller_found=0
while $caller_scans < 32 && $caller_found == 0
  continue
  set $caller_scans=$caller_scans+1
  set $hdr=*(unsigned long long *)$native_state
  set $off=*(unsigned int *)$hdr
  set $tail=$hdr+$off
  set $entry=*(unsigned long long *)($tail+8)
  set $size=*(unsigned long long *)($tail+16)
  printf "KERNIX_G0_IFUNC103_POST_RET_SOURCE_JIT idx=%u entry=0x%lx size=0x%lx native_pc=0x%lx rsp=0x%lx rax=0x%lx\\n", $caller_scans,$entry,$size,$pc,$x8,$x4
  if $entry == {hex(CALLER_RETURN)}
    set $caller_found=1
    printf "KERNIX_G0_IFUNC103_ORIGINAL_CALLER_RESUMED_AFTER_C3_RET guest_entry=0x%lx rsp=0x%lx rax=0x%lx native_pc=0x%lx target_r14=0x%lx\\n", $entry,$x8,$x4,$pc,$x19
    x/8bx {hex(CALLER_RETURN)}
  end
end
if $caller_found == 0
  quit 1
end
disable 3
printf "KERNIX_G0_IFUNC103_POST_C3_RET_SOURCE_TARGET_BEFORE_NATIVE_WRITER target={hex(TARGET)} old_expected={hex(OLD)}\\n"
x/gx {hex(TARGET)}
watch -location *(unsigned long long *){hex(TARGET)}
condition 5 $pc >= 0xffff00000000 && $x28 == $native_state && $x19 == {hex(TARGET)} && $x4 == {hex(RESULT)}
continue
printf "KERNIX_G0_IFUNC103_SAME_PROCESS_POST_RET_NATIVE_WRITER_HW_HIT pc=0x%lx rsp=0x%lx rax=0x%lx r14=0x%lx\\n", $pc,$x8,$x4,$x19
x/i $pc-4
x/gx {hex(TARGET)}
set $hdr=*(unsigned long long *)$native_state
set $off=*(unsigned int *)$hdr
set $tail=$hdr+$off
set $entry=*(unsigned long long *)($tail+8)
set $size=*(unsigned long long *)($tail+16)
set $cnt=*(unsigned int *)($tail+24)
printf "KERNIX_G0_IFUNC103_SAME_PROCESS_ORIGINAL_GNU_WRITER_NATIVE_JIT entry=0x%lx size=0x%lx count=%u native_after_pc=0x%lx\\n", $entry,$size,$cnt,$pc
x/8bx $entry
x/8bx {hex(STORE)}
printf "KERNIX_G0_IFUNC103_ONE_ORIGINAL_FEX_GUEST_CALL_NATIVE_RET_STACK_READ_AND_GNU_STORE_DIAGNOSTIC_COMPLETE_NOT_INDEPENDENTLY_ATTESTED=1\\n"
quit
'''
    assert script.count("awatch -location *(unsigned long long *)"+hex(SLOT))==1
    assert script.count("rwatch -location *(unsigned long long *)"+hex(SLOT))==1
    assert script.count("watch -location *(unsigned long long *)$native_state")==1
    assert script.count("watch -location *(unsigned long long *)"+hex(TARGET))==1
    assert "condition 4 " not in script  # do not mask post-RET hardware stack READ
    assert script.count("quit 1")==5
    assert script.endswith("quit\n")
    (dist/GDB).write_text(script)
    receipt={"schema":"kernix.g0.original-libc-IFUNC103-one-guest-source-CALL-resolver-exact-C3-RET-native-stack-read-and-writer-SOURCE-ONLY.v1",
             "source_libc_sha256":LIBC_SHA,"source_ldso_sha256":LDSO_SHA,
             "previous_unique_native_hardware_writers_independently_certified":18,
             "original_ifunc_index":INDEX,
             "original_resolver_guest_RIP":hex(RESOLVER),
             "original_source_RET_guest_RIP":hex(RET),
             "original_source_RET_opcode":"c3",
             "original_caller_RIP":hex(CALL),
             "original_guest_return_site":hex(CALLER_RETURN),
             "original_guest_return_stack_slot":hex(SLOT),
             "original_guest_return_stack_qword":hex(CALLER_RETURN),
             "expected_real_original_resolver_result_from_prior_write_only_hardware_proof":hex(RESULT),
             "original_GNU_writer_RIP":hex(STORE),
             "original_GNU_writer_source_bytes":"498906",
             "original_IFUNC103_target":hex(TARGET),
             "original_IFUNC103_source_old_qword":hex(OLD),
             "source_plan_only_not_runtime_proof":True,
             "actual_native_hardware_RET_read_and_same_process_writer_proven":False,
             "all_147_source_relocations_closed":False,
             "Android_Bionic_Wine_Proton_games_proven":False}
    (dist/OUTPUT).write_text(json.dumps(receipt,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_IFUNC103_ONE_FEX_GUEST_CALL_C3_RET_HW_READ_WRITER_SOURCE_PLAN_ONLY_NOT_RUN")

if __name__=="__main__":
    assert len(sys.argv)==3
    prepare(Path(sys.argv[1]),Path(sys.argv[2]))
