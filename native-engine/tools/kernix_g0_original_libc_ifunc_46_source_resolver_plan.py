#!/usr/bin/env python3
"""Source-only original libc IFUNC/IRELATIVE resolver provenance plan.

No IFUNC resolver has been executed here. Each original R_X86_64_IRELATIVE
source addend must locate an executable original GNU libc PT_LOAD, while
its relocation target must be the corresponding file-backed RW+NX PT_LOAD.
Duplicate addends are NOT independently proven calls or relocations.
"""
import hashlib
import json
from collections import Counter
from pathlib import Path
import sys

from kernix_g0_original_libc_relocation_type_transition_gate import (
    decode_original_libc, classify, LIBC_SHA, LDSO_SHA
)
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset

OUTPUT="original-libc-46-IFUNC-IRELATIVE-42-unique-resolver-source-only-plan.json"


def plan(dist:Path):
    source=dist/"original-source-pinned-root/lib/x86_64-linux-gnu/libc.so.6"
    ldso=dist/"original-source-pinned-root/lib64/ld-linux-x86-64.so.2"
    assert source.is_file() and not source.is_symlink()
    assert ldso.is_file() and not ldso.is_symlink()
    libc,loader=source.read_bytes(),ldso.read_bytes()
    assert len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA
    assert len(loader)==235408 and hashlib.sha256(loader).hexdigest()==LDSO_SHA
    rows=decode_original_libc(libc)
    classified=classify(rows)
    assert classified==json.loads((dist/"original-libc-147-rela-jmprel-typed-source-next-stage-plan.json").read_text())
    assert classified["last_JUMP_SLOT_live_FEX_hardware_writer_proven"] is False  # source-only typed classification, not mutable runtime receipt
    assert classified["original_source_IRELATIVE_count"]==46
    assert classified["original_other_RELA_count"]==85
    ifunc=[r for r in rows if r["r_type"]==37]
    assert len(ifunc)==46 and [r["index"] for r in ifunc]==[85]+list(range(102,147))
    assert all(r["r_sym"]==0 and r["r_type"]==37 for r in ifunc)
    assert len({r["r_offset"] for r in ifunc})==46
    results=[]
    for r in ifunc:
        addend=r["r_addend"]
        assert addend>0
        # ELF x86_64 R_X86_64_IRELATIVE: resolver source = libc bias + A.
        # A source program header alone does NOT prove that a resolver was
        # called, returned successfully or had a semantically correct result.
        resolver_offset=source_offset(libc,addend,1,5)
        rw=source_offset(libc,int(r["r_offset"],16),8,6,nonexec=True)
        old=int.from_bytes(libc[rw:rw+8],"little")
        assert old==int(r["original_source_qword"],16)
        assert libc[resolver_offset:resolver_offset+1]!=b""
        results.append({
            "source_index":r["index"],
            "table":r["table"],
            "r_type":"R_X86_64_IRELATIVE",
            "source_addend":hex(addend),
            "original_guest_resolver_entry":hex(0x804000000+addend),
            "resolver_source_ELF_RX_file_offset":hex(resolver_offset),
            "original_guest_RW_NX_target":r["source_guest_target"],
            "original_target_source_qword":r["original_source_qword"],
            "resolver_real_FEX_entry_executed":False,
            "resolver_x86_64_ABI_return_proven":False,
            "native_AArch64_resolver_return_proven":False,
            "actual_guest_GNU_loader_target_write_proven":False,
        })
    assert len({x["original_guest_resolver_entry"] for x in results})==42
    counts=Counter(x["original_guest_resolver_entry"] for x in results)
    duplicates={key:n for key,n in sorted(counts.items()) if n>1}
    assert sorted(duplicates.values())==[2,2,2,2]
    assert sum(duplicates.values())==8
    assert results[0]["source_index"]==85
    assert results[0]["original_guest_resolver_entry"]=="0x8040c8570"
    assert results[0]["original_guest_RW_NX_target"]=="0x8042014c8"
    assert results[0]["original_target_source_qword"]=="0x0"
    assert results[1]["source_index"]==102
    assert results[1]["original_guest_resolver_entry"]=="0x8040b4f00"
    assert results[1]["original_guest_RW_NX_target"]=="0x804202d78"
    assert results[1]["original_target_source_qword"]=="0x283d0"
    # Strict source invariants only: 46 unique relocation TARGETS,
    # 42 distinct resolver entry addresses. Do not de-duplicate calls.
    def valid(a):
        return (len(a)==46 and [x["source_index"] for x in a]==[85]+list(range(102,147))
                and len({x["original_guest_RW_NX_target"] for x in a})==46
                and len({x["original_guest_resolver_entry"] for x in a})==42
                and all(x["r_type"]=="R_X86_64_IRELATIVE" for x in a))
    assert valid(results)
    assert not valid(results[:-1])
    assert not valid(results[::-1])
    assert not valid(results[:1]+[dict(results[1],r_type="R_X86_64_JUMP_SLOT")]+results[2:])
    assert not valid(results[:1]+[dict(results[1],original_guest_RW_NX_target=results[0]["original_guest_RW_NX_target"])]+results[2:])
    assert not valid(results[:1]+[dict(results[1],original_guest_resolver_entry="0x0")]+results[2:])
    receipt={
        "schema":"kernix.g0.46-original-libc-IRELATIVE-IFUNC-source-provenance-only.v1",
        "source_original_libc_sha256":LIBC_SHA,
        "source_original_ldso_sha256":LDSO_SHA,
        "original_IFUNC_source_relocation_count":46,
        "original_distinct_resolver_entry_address_count":42,
        "duplicate_resolver_address_groups":duplicates,
        "duplicate_resolver_addends_do_not_prove_deduplication":True,
        "original_DT_RELA_IFUNC_source_record":85,
        "original_DT_JMPREL_IFUNC_source_records":list(range(102,147)),
        "first_initial_IFUNC_candidate_index":102,
        "original_IFUNC_source_candidate_resolvers":results,
        "five_in_memory_source_type_mutations_rejected":True,
        "IFUNC_execution_real_native_FEX_witness_proven":False,
        "source_resolver_call_return_completed":False,
        "source_46_IFUNC_native_hardware_writer_relocations_closed":False,
        "other_85_RELA_relocations_closed":False,
        "all_147_libc_relocations_closed_in_one_guest":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    (dist/OUTPUT).write_text(json.dumps(receipt,indent=2)+"\n")
    print("KERNIX_G0_SOURCE_ORIGINAL_46_IFUNC_42_UNIQUE_RESOLVER_ENTRIES_PASS_NOT_EXECUTED")


if __name__=="__main__":
    assert len(sys.argv)==2
    plan(Path(sys.argv[1]))
