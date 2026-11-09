#!/usr/bin/env python3
"""Find immutable original GNU libc IFUNC102 RET candidate source bytes only.

The source x86 C3 byte is a RET instruction *candidate* not proof that
the genuine FEX source guest executed it. Prove this via native JIT/guest
stack hardware reads and caller-return site in a later runtime gate.
"""
import hashlib,json,sys
from pathlib import Path
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import (
    LIBC_SHA,LDSO_SHA,LIBC_BIAS,LDSO_BIAS,RESOLVER,CALL,CALLER_RETURN,STORE
)
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
OUT="original-libc-IFUNC102-GNU-source-RET-candidate-only.json"

def prepare(dist:Path):
    root=dist/"original-source-pinned-root"
    libc=(root/"lib/x86_64-linux-gnu/libc.so.6").read_bytes()
    ldso=(root/"lib64/ld-linux-x86-64.so.2").read_bytes()
    assert len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA
    assert len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
    def c(addr,n):return libc[source_offset(libc,addr-LIBC_BIAS,n,5):][:n]
    def d(addr,n):return ldso[source_offset(ldso,addr-LDSO_BIAS,n,5):][:n]
    assert c(RESOLVER,4)==bytes.fromhex("f30f1efa")
    assert c(0x8040b4f24,4)==bytes.fromhex("4889d0c3")
    assert c(0x8040b4f27,1)==b"\xc3"
    assert d(CALL,2)==bytes.fromhex("ffd0")
    assert d(CALLER_RETURN,4)==bytes.fromhex("4883c318")
    assert d(STORE,3)==bytes.fromhex("498906")
    prior=json.loads(
        (dist/"original-libc-first-IRELATIVE-102-real-FEX-native-writer-only-proof.json").read_text())
    assert prior["original_libc_sha256"]==LIBC_SHA
    assert prior["original_ldso_sha256"]==LDSO_SHA
    assert prior["first_IFUNC_source_index"]==102
    assert prior["source_resolver_guest_entry"]==hex(RESOLVER)
    assert prior["first_IFUNC_native_hardware_target_write_proven"] is True
    assert prior["actual_native_hardware_writer_qword"]=="0x8040c74a0"
    assert prior["original_guest_IFUNC_resolver_RET_opcode_executed_proven"] is False
    # First IFUNC resolver has an original x86 MOV RDX,RAX / RET sequence
    # at 0xb4f24 and b4f27. A scan cannot prove this branch executed.
    def candidate_ok(opcode,source_return,writer):
        return (opcode==b"\xc3" and
                source_return==bytes.fromhex("4883c318") and
                writer==bytes.fromhex("498906"))
    assert candidate_ok(c(0x8040b4f27,1),d(CALLER_RETURN,4),d(STORE,3))
    assert not candidate_ok(b"\x90",d(CALLER_RETURN,4),d(STORE,3))
    assert not candidate_ok(c(0x8040b4f27,1),b"\x90"*4,d(STORE,3))
    assert not candidate_ok(c(0x8040b4f27,1),d(CALLER_RETURN,4),b"\x4c\x89\x08")
    proof={
        "schema":"kernix.g0.source-original-libc-IFUNC102-x86-RET-instruction-candidate-only.v1",
        "original_source_libc_sha256":LIBC_SHA,
        "original_source_ldso_sha256":LDSO_SHA,
        "original_guest_libc_resolver_entry":hex(RESOLVER),
        "original_source_x86_ret_candidate_guest_RIP":"0x8040b4f27",
        "original_x86_ret_candidate_opcode":"c3",
        "original_preceding_x86_opcode":"4889d0",
        "original_GNU_loader_indirect_call_guest_RIP":hex(CALL),
        "original_GNU_loader_call_return_guest_RIP":hex(CALLER_RETURN),
        "original_GNU_loader_writer_guest_RIP":hex(STORE),
        "original_GNU_loader_writer_opcode":"498906",
        "original_real_native_IFUNC102_target_writer_from_separate_guest_proven":True,
        "source_only_three_false_RET_candidate_mutations_rejected":True,
        "genuine_FEX_GNU_resolver_guest_RET_executed_proven":False,
        "genuine_FEX_caller_return_site_reached_proven":False,
        "same_process_call_entry_RET_and_writer_chain_proven":False,
        "all_46_IFUNC_relocations_closed":False,
        "all_147_RELA_JMPREL_closed_in_one_process":False,
        "Android_Bionic_Wine_Proton_games_proven":False
    }
    (dist/OUT).write_text(json.dumps(proof,indent=2)+"\n")
    print("KERNIX_G0_LIBC_IFUNC102_ORIGINAL_GNU_GUEST_RET_SOURCE_C3_CANDIDATE_PASS_NOT_EXECUTED")

if __name__=="__main__":
    assert len(sys.argv)==2
    prepare(Path(sys.argv[1]))
