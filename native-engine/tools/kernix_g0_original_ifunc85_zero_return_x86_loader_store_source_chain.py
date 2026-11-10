#!/usr/bin/env python3
"""SHA-locked ORIGINAL GNU x86 libc IFUNC85 zero-return resolver source chain only.

This is NOT evidence of real guest execution or of any actual ARM64 FEX memory
write. It establishes x86 resolver/loader bytes for a same-zero STORE gate.
"""
from __future__ import annotations
import hashlib, json, sys
from pathlib import Path

from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA, LDSO_SHA, decode_original_libc, classify,
)
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import (
    CALL, STORE, CALLER_RETURN, LIBC_BIAS, LDSO_BIAS,
)

PREFIX = "original-libc-IFUNC85-zero-return-source-and-GNU-ldso-call-store-NO-NATIVE"


def need(ok: bool, label: str) -> None:
    if not ok:
        raise AssertionError("GNU IFUNC85 zero-return SHA-locked SOURCE CHAIN FAIL: " + label)


def run(triad: Path, previous_proof: Path, out: Path) -> dict:
    p = triad/"lib/x86_64-linux-gnu/libc.so.6"
    q = triad/"lib64/ld-linux-x86-64.so.2"
    need(p.is_file() and q.is_file() and not p.is_symlink() and not q.is_symlink(),
         "real pinned libc and ldso")
    libc, ldso = p.read_bytes(), q.read_bytes()
    need(len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA,
         "original x86 libc SHA and size")
    need(len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA,
         "original x86 ldso SHA and size")
    rows=decode_original_libc(libc)
    need(classify(rows)["original_total_RELA_and_JMPREL"]==147,
         "all 147 original sources")
    r=rows[85]
    need(r["index"]==85 and r["table"]=="DT_RELA" and r["table_index"]==85
         and r["r_type"]==37 and r["r_sym"]==0,
         "original libc IRELATIVE #85 exact table/type")
    need(r["original_source_qword"]=="0x0"
         and r["r_addend"]==0xc8570
         and r["r_offset"]=="0x2014c8",
         "original source zero target and real resolver relocation offsets")
    need(r["source_guest_target"]=="0x8042014c8",
         "correct immutable original relocated guest target")
    need(int.from_bytes(libc[source_offset(libc,0x2014c8,8,6,nonexec=True):
                              source_offset(libc,0x2014c8,8,6,nonexec=True)+8],
                        "little")==0, "true original zero qword in RW non-exec mapping")

    # Exact original x86 machine code bytes, not a guessed IFUNC return value.
    def libc_rx(where:int,expect:str)->str:
        data=bytes.fromhex(expect)
        offset=source_offset(libc,where,len(data),5)
        need(libc[offset:offset+len(data)]==data,
             "libc original resolver bytes "+hex(where))
        return hex(LIBC_BIAS+where)
    entry=libc_rx(0xc8570,"f30f1efa")  # endbr64, immutable resolver start
    xor=libc_rx(0xc860b,"31c0")        # xor eax,eax; zero-return epilogue
    ret=libc_rx(0xc860d,"c3")          # x86 near RET from this resolver

    def ldso_rx(where:int,expect:str)->str:
        data=bytes.fromhex(expect)
        offset=source_offset(ldso,where-LDSO_BIAS,len(data),5)
        need(ldso[offset:offset+len(data)]==data,
             "original GNU x86 loader bytes "+hex(where))
        return hex(where)
    call=ldso_rx(CALL,"ffd0")                # call *%rax
    caller_return=ldso_rx(CALLER_RETURN,"4883c318")  # add $0x18,%rbx
    store=ldso_rx(STORE,"498906")            # mov %rax,(%r14)

    need(previous_proof.is_file() and not previous_proof.is_symlink(),
         "independent 61 original GNU hardware writer prerequisite")
    proof=json.loads(previous_proof.read_text())
    need(proof["original_source_libc_sha256"]==LIBC_SHA
         and proof["original_source_ldso_sha256"]==LDSO_SHA
         and proof["original_source_indices"]==[145,146]
         and proof["unique_original_libc_native_hardware_writer_target_count"]==61
         and proof["prior_independently_certified_native_hardware_target_count"]==59,
         "actual previous two native writer receipts and prior 59")
    need(len(proof["two_independent_native_hardware_writer_receipts"])==2
         and sum(map(len, proof["twenty_native_hardware_tamper_cases_rejected"].values()))==20,
         "previous individual two target receipts with 20 negative cases")
    result={
        "schema":"kernix.g0.original-libc-ifunc85-zero-return-original-gnu-loader-source-only.v1",
        "original_source_libc_sha256":LIBC_SHA,
        "original_source_ldso_sha256":LDSO_SHA,
        "source_index":85,
        "source_table":"DT_RELA",
        "source_table_ordinal":85,
        "source_relocation_type":"R_X86_64_IRELATIVE",
        "original_guest_target":"0x8042014c8",
        "original_target_initial_qword":"0x0",
        "original_guest_resolver":entry,
        "original_x86_resolver_endbr64_opcode":"f30f1efa",
        "original_guest_zero_return_xor_eax_eax":xor,
        "original_x86_zero_return_opcode":"31c0",
        "original_guest_zero_return_ret":ret,
        "original_x86_ret_opcode":"c3",
        "original_x86_GNU_ldso_resolver_call_guest_address":call,
        "original_x86_GNU_ldso_resolver_call_opcode":"ffd0",
        "original_x86_GNU_ldso_caller_step_guest_address":caller_return,
        "original_x86_GNU_ldso_caller_step_opcode":"4883c318",
        "original_x86_GNU_ldso_store_guest_address":store,
        "original_x86_GNU_ldso_store_opcode":"498906",
        "source_zero_return_path_validated_not_real_guest_execution":True,
        "unchanged_zero_memory_cannot_be_reliably_inferred_from_GDB_watch":True,
        "previous_independently_attested_original_writer_count":61,
        "new_real_native_writer_attestations":0,
        "same_guest_actual_call_ret_stack_read_proven":False,
        "source_GNU_loader_STORE_executed_under_ARM64_FEX_proven":False,
        "all_147_same_guest_relocations_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
        "conditional_next_gate":"arm awatch and independently validate actual native store zero vs mere read, source GNU original JIT and chronological sequence"
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/(PREFIX+".json")).write_text(json.dumps(result,indent=2)+"\n")
    print("KERNIX_G0_IFUNC85_ORIGINAL_GNU_X86_RESOLVER_ZERO_EPILOGUE_AND_LDSO_STORE_SOURCE_ONLY_HOLD_61_147")
    return result


if __name__=="__main__":
    need(len(sys.argv)==4,"usage original-triad-root previous-61-independently-attested-proof dist")
    run(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))
