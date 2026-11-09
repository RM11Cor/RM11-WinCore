#!/usr/bin/env python3
"""Source-locked first GNU libc IFUNC 102 actual call-target/JIT entry probe.

A successful source plan is NOT runtime. Actual native ARM64 GDB hardware
stack and JIT-header stops must separately prove source x86 CALL and
first guest resolver JIT entry. Guest RET opcode and full ABI NOT assumed.
"""
import json
from pathlib import Path
import sys
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import (
    LIBC_SHA, LDSO_SHA, LIBC_BIAS, LDSO_BIAS,
    RESOLVER,TARGET,BEFORE,CALL,CALLER_RETURN,STORE,GUEST_MAIN
)
from kernix_g0_original_libc_relocation_type_transition_gate import decode_original_libc, classify
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset

PLAN="original-libc-first-IFUNC102-call-target-JIT-entry-source-plan.json"
GDB="original-libc-first-IFUNC102-call-target-JIT-entry-real-FEX-watch.gdb"
SLOT=0x80300f9b8


def prepare(dist:Path, repo:Path):
    import hashlib
    original=dist/"original-source-pinned-root"
    libc=(original/"lib/x86_64-linux-gnu/libc.so.6").read_bytes()
    ldso=(original/"lib64/ld-linux-x86-64.so.2").read_bytes()
    assert hashlib.sha256(libc).hexdigest()==LIBC_SHA
    assert hashlib.sha256(ldso).hexdigest()==LDSO_SHA
    all_types=classify(decode_original_libc(libc))
    assert all_types==json.loads((dist/"original-libc-147-rela-jmprel-typed-source-next-stage-plan.json").read_text())
    row=decode_original_libc(libc)[102]
    assert row["r_type"]==37 and row["r_sym"]==0 and row["r_addend"]==0xb4f00
    assert int(row["source_guest_target"],16)==TARGET
    assert int(row["original_source_qword"],16)==BEFORE
    first=json.loads(
        (dist/"original-libc-first-IRELATIVE-102-real-FEX-native-writer-only-proof.json").read_text())
    assert first["first_IFUNC_source_index"]==102
    assert first["source_relocation_guest_target"]==hex(TARGET)
    assert first["actual_native_hardware_writer_qword"]=="0x8040c74a0"
    assert first["first_IFUNC_native_hardware_target_write_proven"] is True
    assert first["seven_actual_native_FEX_log_tamper_controls_rejected"] is True
    assert first["original_IFUNC_resolver_JIT_entry_observed"] is False
    assert first["original_IFUNC_resolver_call_return_same_process_proven"] is False
    assert libc[source_offset(libc,RESOLVER-LIBC_BIAS,4,5):][:4]==bytes.fromhex("f30f1efa")
    assert ldso[source_offset(ldso,CALL-LDSO_BIAS,2,5):][:2]==bytes.fromhex("ffd0")
    assert ldso[source_offset(ldso,CALLER_RETURN-LDSO_BIAS,4,5):][:4]==bytes.fromhex("4883c318")
    assert ldso[source_offset(ldso,STORE-LDSO_BIAS,3,5):][:3]==bytes.fromhex("498906")
    lines=(repo/GUEST_MAIN).read_text().splitlines()
    matches=[n for n,x in enumerate(lines,1) if x.strip()=="ctx->ExecuteThread(thread);"]
    assert len(matches)==1
    bp=matches[0]
    gdb=(
        "set pagination off\nset confirm off\n"
        "set breakpoint pending on\nset output-radix 16\n"
        "handle SIGBUS nostop noprint pass\n"
        "handle SIGCHLD nostop noprint pass\n"
        f"break {GUEST_MAIN}:{bp}\n"
        "commands\nsilent\n"
        f'printf "KERNIX_G0_LIBC_IFUNC102_CALL_NATIVE_STACK_ACCESS_ARMED slot={hex(SLOT)} source_expected_return={hex(CALLER_RETURN)} resolver_target={hex(RESOLVER)} NO_ENTRY_PROVEN_YET=1\\n"\n'
        f"x/gx {hex(SLOT)}\n"
        f"awatch -location *(unsigned long long *){hex(SLOT)}\n"
        f"condition 2 $pc >= 0xffff00000000 && $x28 >= 0xffff00000000 && $x8 == {hex(SLOT)} && $x4 == {hex(RESOLVER)} && *(unsigned long long *){hex(SLOT)} == {hex(CALLER_RETURN)}\n"
        "continue\nend\nrun\n"
        f'printf "KERNIX_G0_LIBC_IFUNC102_EXACT_SOURCE_GNU_CALL_STACK_NATIVE_HW_HIT target_rax_x4=0x%lx guest_rsp_x8=0x%lx native_pc=0x%lx guest_return_slot={hex(SLOT)} guest_return_value={hex(CALLER_RETURN)} NOT_YET_SOURCE_ENTRY_ATTESTED=1\\n", $x4, $x8, $pc\n'
        "x/i $pc-4\n"
        f"x/gx {hex(SLOT)}\n"
        f"x/8bx {hex(CALL)}\n"
        "disable 2\n"
        "set $native_state=$x28\n"
        "watch -location *(unsigned long long *)$native_state\n"
        "condition 3 $pc >= 0xffff00000000 && $x28 == $native_state\n"
        f'printf "KERNIX_G0_LIBC_IFUNC102_RESOLVER_JIT_ENTRY_NATIVE_HEADER_WATCH_ARMED state=0x%lx expected={hex(RESOLVER)} max=48\\n", $native_state\n'
        "set $tries=0\nset $found=0\n"
        "while $tries < 48 && $found == 0\n"
        "  continue\n"
        "  set $tries=$tries+1\n"
        "  set $hdr=*(unsigned long long *)$native_state\n"
        "  if $hdr != 0\n"
        "    set $hoff=*(unsigned int *)$hdr\n"
        "    set $tail=$hdr+$hoff\n"
        "    set $entry=*(unsigned long long *)($tail+8)\n"
        "    set $size=*(unsigned long long *)($tail+16)\n"
        "    set $inst_count=*(unsigned int *)($tail+24)\n"
        '    printf "KERNIX_G0_LIBC_IFUNC102_JIT_NATIVE_HEADER_STOP i=%u guest_entry=0x%lx size=0x%lx host_pc=0x%lx x8_rsp=0x%lx x4_rax=0x%lx count=%u\\n", $tries,$entry,$size,$pc,$x8,$x4,$inst_count\n'
        f"    if $entry == {hex(RESOLVER)}\n"
        "      set $found=1\n"
        f'      printf "KERNIX_G0_LIBC_IFUNC102_ORIGINAL_GNU_RESOLVER_JIT_ENTRY_NATIVE_HW_PROVEN guest_rip={hex(RESOLVER)} host_pc=0x%lx guest_rsp=0x%lx resolver_call_return_unproven=1\\n", $pc,$x8\n'
        f"      x/8bx {hex(RESOLVER)}\n"
        "      x/6i $pc-16\n"
        "    end\n"
        "  end\n"
        "end\n"
        'printf "KERNIX_G0_LIBC_IFUNC102_JIT_NATIVE_RESOLVER_ENTRY_BOUNDED_TERMINAL stops=%u found=%u guest_return_untraced=1\\n", $tries,$found\n'
        "quit\n"
    )
    assert gdb.count(f"awatch -location *(unsigned long long *){hex(SLOT)}")==1
    assert gdb.count("watch -location *(unsigned long long *)$native_state")==1
    assert "KERNIX_G0_LIBC_IFUNC102_ORIGINAL_GNU_RESOLVER_JIT_ENTRY_NATIVE_HW_PROVEN" in gdb
    (dist/GDB).write_text(gdb)
    data={
        "schema":"kernix.g0.first-original-libc-IRELATIVE-IFUNC102-CALL-to-resolver-JIT-native-source-watch.v1",
        "original_libc_sha256":LIBC_SHA,
        "original_ldso_sha256":LDSO_SHA,
        "prior_real_FEX_first_IFUNC_native_hardware_writer_proven":True,
        "original_GNU_x86_call_guest_RIP":hex(CALL),
        "original_GNU_x86_call_opcode":"ffd0",
        "exact_expected_resolver_guest_RIP":hex(RESOLVER),
        "original_resolver_entry_opcode":"f30f1efa",
        "original_guest_STACK_after_call_return_slot":hex(SLOT),
        "original_guest_return_address_qword":hex(CALLER_RETURN),
        "source_original_resolver_return_site":hex(CALLER_RETURN),
        "source_original_guest_target":hex(TARGET),
        "source_original_previous_on_disk_qword":hex(BEFORE),
        "source_breakpoint_original_fex_ExecuteThread_line":bp,
        "real_FEX_guest_call_stack_hardware_stop_observed":False,
        "real_FEX_guest_resolver_JIT_header_entry_hardware_stop_observed":False,
        "specific_guest_original_IFUNC_RET_opcode_executed_proven":False,
        "source_same_guest_IFUNC_caller_return_site_proven":False,
        "source_same_guest_IFUNC_target_native_writer_chain_proven":False,
        "all_46_IFUNC_resolver_relocations_closed":False,
        "Android_Bionic_Wine_Proton_games_proven":False
    }
    (dist/PLAN).write_text(json.dumps(data,indent=2)+"\n")
    print("KERNIX_G0_FIRST_LIBC_IFUNC102_CALL_STACK_AND_JIT_ENTRY_SOURCE_PLAN_PASS_NOT_EXECUTED")


if __name__=="__main__":
    assert len(sys.argv)==3
    prepare(Path(sys.argv[1]),Path(sys.argv[2]))
