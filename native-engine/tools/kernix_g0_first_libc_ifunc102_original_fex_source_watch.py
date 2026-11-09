#!/usr/bin/env python3
"""Prepare FIRST original libc IRELATIVE #102 WRITE-only ARM64 FEX watch.

Source-only! Does not prove resolver entry/call, ABI return, loader target
write, full GNU relocations, Android or games. Require independently
attested all-16 ordinary JUMP_SLOT writers before moving to IFUNC.
"""
import hashlib
import json
from pathlib import Path
import sys
from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA, LDSO_SHA, decode_original_libc, classify,
)
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset

OUT_JSON="original-libc-first-IRELATIVE-102-source-only-watch-plan.json"
OUT_GDB="original-libc-first-IRELATIVE-102-write-only-native-fex-watch.gdb"
GUEST_MAIN="native-engine/android-host/tests/kernix_g0_original_fex_full_ptload_source_executable_range_arm64.cpp"
LIBC_BIAS=0x804000000
LDSO_BIAS=0x801000000
INDEX=102
TARGET=0x804202d78
BEFORE=0x283d0
RESOLVER=0x8040b4f00
CALL=0x80100fd5a
CALLER_RETURN=0x80100fd5c
STORE=0x80100fd60
SOURCE_WRITER=bytes.fromhex("498906")


def prepare(dist:Path, repository:Path):
    libp=dist/"original-source-pinned-root/lib/x86_64-linux-gnu/libc.so.6"
    ldp=dist/"original-source-pinned-root/lib64/ld-linux-x86-64.so.2"
    assert libp.is_file() and not libp.is_symlink()
    assert ldp.is_file() and not ldp.is_symlink()
    libc,ldso=libp.read_bytes(),ldp.read_bytes()
    assert len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA
    assert len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
    typed=classify(decode_original_libc(libc))
    assert typed==json.loads((dist/"original-libc-147-rela-jmprel-typed-source-next-stage-plan.json").read_text())
    assert typed["original_source_IRELATIVE_count"]==46
    assert typed["original_other_RELA_count"]==85
    assert typed["last_JUMP_SLOT_live_FEX_hardware_writer_proven"] is False

    source_ifunc=json.loads(
        (dist/"original-libc-46-IFUNC-IRELATIVE-42-unique-resolver-source-only-plan.json").read_text())
    assert source_ifunc["source_original_libc_sha256"]==LIBC_SHA
    assert source_ifunc["source_original_ldso_sha256"]==LDSO_SHA
    assert source_ifunc["original_IFUNC_source_relocation_count"]==46
    assert source_ifunc["original_distinct_resolver_entry_address_count"]==42
    assert source_ifunc["first_initial_IFUNC_candidate_index"]==INDEX
    assert source_ifunc["IFUNC_execution_real_native_FEX_witness_proven"] is False
    row=decode_original_libc(libc)[INDEX]
    assert row["index"]==INDEX and row["table"]=="DT_JMPREL"
    assert row["r_type"]==37 and row["r_sym"]==0
    assert row["r_offset"]=="0x202d78"
    assert row["r_addend"]==0xb4f00
    assert int(row["source_guest_target"],16)==TARGET
    assert int(row["original_source_qword"],16)==BEFORE
    assert TARGET==LIBC_BIAS+int(row["r_offset"],16)
    assert RESOLVER==LIBC_BIAS+row["r_addend"]
    srcrow=source_ifunc["original_IFUNC_source_candidate_resolvers"][1]
    assert srcrow["source_index"]==INDEX
    assert srcrow["original_guest_resolver_entry"]==hex(RESOLVER)
    assert srcrow["original_guest_RW_NX_target"]==hex(TARGET)
    assert srcrow["original_target_source_qword"]==hex(BEFORE)
    assert srcrow["resolver_real_FEX_entry_executed"] is False
    off=source_offset(libc,TARGET-LIBC_BIAS,8,6,nonexec=True)
    assert int.from_bytes(libc[off:off+8],"little")==BEFORE
    rx=source_offset(libc,RESOLVER-LIBC_BIAS,4,5)
    assert libc[rx:rx+4]==bytes.fromhex("f30f1efa"), "source libc IFUNC must start with ENDBR64"
    call_off=source_offset(ldso,CALL-LDSO_BIAS,2,5)
    assert ldso[call_off:call_off+2]==bytes.fromhex("ffd0"), "exact original GNU CALL *%rax"
    caller_off=source_offset(ldso,CALLER_RETURN-LDSO_BIAS,4,5)
    assert ldso[caller_off:caller_off+4]==bytes.fromhex("4883c318")
    wr=source_offset(ldso,STORE-LDSO_BIAS,3,5)
    assert ldso[wr:wr+3]==SOURCE_WRITER, "different GNU IFUNC store opcode from JUMP_SLOT"

    previous=json.loads(
        (dist/"original-libc-last-jumpslot-101-real-fex-hw-verified.json").read_text())
    assert previous["source_original_libc_sha256"]==LIBC_SHA
    assert previous["source_original_gnu_ldso_sha256"]==LDSO_SHA
    assert previous["last_JUMP_SLOT_source_index"]==101
    assert previous["last_JUMP_SLOT_original_qword"]=="0x283c0"
    assert previous["last_JUMP_SLOT_real_native_hardware_after_qword"]=="0x80101adb0"
    assert previous["all_16_JUMP_SLOT_individual_native_hardware_writers_proven_count"]==16
    assert previous["six_actual_native_log_negative_mutations_rejected"] is True
    assert previous["remaining_131_RELA_JMPREL_writers_proven"] is False
    assert previous["all_46_IFUNC_resolvers_proven"] is False

    lines=(repository/GUEST_MAIN).read_text().splitlines()
    boundaries=[i for i,x in enumerate(lines,1) if x.strip()=="++RealOriginalLdsoLibcCloses;"]
    assert len(boundaries)==1
    line=boundaries[0]
    # At source native close(3) the original source value must still be
    # original in GDB. The watch only logs genuine new hardware writes.
    # No manufactured simulated guest instruction or direct memory write.
    gdb=(
        "set pagination off\nset confirm off\n"
        "set breakpoint pending on\nset output-radix 16\n"
        "handle SIGBUS nostop noprint pass\n"
        "handle SIGCHLD nostop noprint pass\n"
        f"break {GUEST_MAIN}:{line}\n"
        "commands\nsilent\n"
        f'printf "KERNIX_G0_FIRST_LIBC_IFUNC_102_SOURCE_WRITE_WATCH_ARMED index=102 target={hex(TARGET)} original={hex(BEFORE)} resolver={hex(RESOLVER)} PROOF_PENDING=1\\n"\n'
        f"x/gx {hex(TARGET)}\n"
        f"watch -location *(unsigned long long *){hex(TARGET)}\n"
        "condition 2 $pc >= 0xffff00000000 && $x28 >= 0xffff00000000\n"
        "continue\nend\nrun\n"
        f'printf "KERNIX_G0_FIRST_LIBC_IFUNC_102_NATIVE_HW_AFTER_WRITE target={hex(TARGET)} pc=0x%lx x4_rax=0x%lx x19_r14=0x%lx x8_rsp=0x%lx x28_state=0x%lx SOURCE_ONLY_CONTEXT_NO_RESOLVER_RET_CLAIM=1\\n", $pc,$x4,$x19,$x8,$x28\n'
        f"x/gx {hex(TARGET)}\n"
        "x/i $pc-4\nx/12i $pc-28\n"
        "set $h=*(unsigned long long *)$x28\n"
        "set $off=*(unsigned int *)$h\n"
        "set $tail=$h+$off\n"
        "set $guest_entry=*(unsigned long long *)($tail+8)\n"
        "set $guest_size=*(unsigned long long *)($tail+16)\n"
        "set $jit_count=*(unsigned int *)($tail+24)\n"
        'printf "KERNIX_G0_FIRST_LIBC_IFUNC_102_NATIVE_FEX_GNU_SOURCE_JIT_ENTRY guest_entry=0x%lx guest_size=0x%lx inst_count=%u host_after_pc=0x%lx\\n", $guest_entry,$guest_size,$jit_count,$pc\n'
        "x/8bx $guest_entry\n"
        f"x/8bx {hex(RESOLVER)}\n"
        f"x/8bx {hex(STORE)}\n"
        "x/gx $x8-8\n"
        'printf "KERNIX_G0_FIRST_LIBC_IFUNC_102_WRITER_DIAGNOSTIC_END_IFUNC_CALL_RETURN_NOT_YET_PROVEN=1\\n"\n'
        "quit\n"
    )
    assert gdb.count("watch -location *(unsigned long long *)0x804202d78")==1
    assert "awatch " not in gdb and "rwatch " not in gdb
    assert "KERNIX_G0_FIRST_LIBC_IFUNC_102_NATIVE_HW_AFTER_WRITE" in gdb
    (dist/OUT_GDB).write_text(gdb)
    obj={
        "schema":"kernix.g0.first-libc-IFUNC-IRELATIVE-102-original-FEX-arm64-write-only-source-plan.v1",
        "source_original_libc_sha256":LIBC_SHA,
        "source_original_ldso_sha256":LDSO_SHA,
        "all_16_previous_JUMP_SLOT_individually_native_FEX_writers_source_proven":True,
        "first_IFUNC_source_index":INDEX,
        "first_IFUNC_relocation_type":"R_X86_64_IRELATIVE",
        "source_relocation_target":hex(TARGET),
        "source_relocation_initial_qword":hex(BEFORE),
        "source_original_IFUNC_resolver_addend":hex(row["r_addend"]),
        "source_guest_resolver_entry":hex(RESOLVER),
        "source_resolver_first_four_x86_bytes":"f30f1efa",
        "source_GNU_loader_x86_CALL_guest_address":hex(CALL),
        "source_GNU_loader_x86_CALL_opcode":"ffd0",
        "source_GNU_loader_caller_return_guest_address":hex(CALLER_RETURN),
        "source_GNU_loader_x86_writer_guest_address":hex(STORE),
        "source_GNU_loader_x86_writer_opcode":SOURCE_WRITER.hex(),
        "first_guest_post_close3_source_breakpoint_line":line,
        "native_watch_mode":"write-only",
        "real_FEX_first_IFUNC_guest_executed":False,
        "real_IFUNC_resolver_entry_JIT_observed":False,
        "original_IFUNC_resolver_return_to_caller_observed":False,
        "real_IFUNC_target_write_observed":False,
        "one_guest_complete_46_IFUNC_relocations_proven":False,
        "remaining_85_RELA_writer_semantics_proven":False,
        "all_original_147_dynamic_relocations_closed":False,
        "Android_Bionic_Wine_Proton_games_proven":False
    }
    (dist/OUT_JSON).write_text(json.dumps(obj,indent=2)+"\n")
    print("KERNIX_G0_FIRST_ORIGINAL_LIBC_IFUNC_102_SOURCE_HW_WATCH_PLAN_PASS_NOT_EXECUTED")


if __name__=="__main__":
    assert len(sys.argv)==3
    prepare(Path(sys.argv[1]),Path(sys.argv[2]))
