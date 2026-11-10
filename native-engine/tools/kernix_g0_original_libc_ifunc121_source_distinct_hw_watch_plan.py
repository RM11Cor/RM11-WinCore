#!/usr/bin/env python3
"""General source-locked GNU libc next IFUNC IRELATIVE native writer watch generator.

Derives EACH new original relocation source resolver, alias group, target and
old target value separately from SHA256-pinned GNU libc ELF, NOT from earlier
IFUNC indices or adjacent addresses. All plans are SOURCE ONLY and DO NOT
advance the independent 35/147 genuine native writer ledger.
This tool does not synthesize original GNU guest instructions/stores.
"""
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA, LDSO_SHA, decode_original_libc, classify
)
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import (
    GUEST_MAIN, LIBC_BIAS, LDSO_BIAS, CALL, CALLER_RETURN, STORE
)

PREVIOUS = "original-libc-IFUNC120-original-one-FEX-CALL-C3-RET-native-stack-read-GNU-writer-INDEPENDENT-PROOF.json"
IFUNC_SOURCE = "original-libc-46-IFUNC-IRELATIVE-42-unique-resolver-source-only-plan.json"
TYPED = "original-libc-147-rela-jmprel-typed-source-next-stage-plan.json"

def plan(dist:Path, repository:Path, index:int):
    assert index==121, "this plan certifies ONLY next distinct original libc IFUNC121"
    root=dist/"original-source-pinned-root"
    libp=root/"lib/x86_64-linux-gnu/libc.so.6"
    ldp=root/"lib64/ld-linux-x86-64.so.2"
    assert libp.is_file() and not libp.is_symlink()
    assert ldp.is_file() and not ldp.is_symlink()
    libc,ldso=libp.read_bytes(),ldp.read_bytes()
    assert len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA
    assert len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
    rows=decode_original_libc(libc)
    assert classify(rows)==json.loads((dist/TYPED).read_text())
    ifunc=[r for r in rows if r["r_type"]==37]
    assert len(ifunc)==46 and [r["index"] for r in ifunc]==[85]+list(range(102,147))
    assert len({r["source_guest_target"] for r in ifunc})==46
    aliases=Counter(r["r_addend"] for r in ifunc)
    assert len(aliases)==42 and sorted(v for v in aliases.values() if v>1)==[2,2,2,2]
    inventory=json.loads((dist/IFUNC_SOURCE).read_text())
    assert inventory["source_original_libc_sha256"]==LIBC_SHA
    assert inventory["source_original_ldso_sha256"]==LDSO_SHA
    assert inventory["original_IFUNC_source_relocation_count"]==46
    assert inventory["original_distinct_resolver_entry_address_count"]==42
    assert inventory["IFUNC_execution_real_native_FEX_witness_proven"] is False
    previous=json.loads((dist/PREVIOUS).read_text())
    assert previous["source_original_libc_sha256"]==LIBC_SHA
    assert previous["source_original_ldso_sha256"]==LDSO_SHA
    assert previous["original_source_IFUNC_index"]==120
    assert previous["source_original_resolver_guest_RIP"]=="0x8040b4da0"
    assert previous["source_original_target"]=="0x804202c98"
    assert previous["genuine_original_linux_FEX_ARM64_ONE_process_IFUNC120_CALL_resolver_JIT_C3_RET_native_hardware_read_and_writer_proven"] is True
    assert previous["ten_genuine_native_hardware_log_corruptions_independently_rejected"] is True
    assert previous["new_unique_relocation_count_due_to_RET_proof"]==0
    assert previous["native_source_original_IFUNC120_distinct_writer_ledger_count"]==35
    assert previous["all_147_original_libc_RELA_JMPREL_writers_one_process_proven"] is False
    row=rows[index]
    assert row["index"]==index and row["r_type"]==37 and row["r_sym"]==0
    assert row["table_index"]==35
    if index>=104:
        assert row["table"]=="DT_JMPREL" and row["table_index"]==index-86
    else: assert row["table"]=="DT_RELA" and index==85
    assert row["r_addend"]>0
    resolver=LIBC_BIAS+row["r_addend"]
    target=LIBC_BIAS+int(row["r_offset"],16)
    old=int(row["original_source_qword"],16)
    assert target==int(row["source_guest_target"],16)
    assert target not in {int(r["source_guest_target"],16) for r in rows[:index] if r["r_type"]==37}, "not a distinct original IFUNC source relocation target"
    assert old!=0
    srcres=source_offset(libc,row["r_addend"],8,5)
    srctar=source_offset(libc,int(row["r_offset"],16),8,6,nonexec=True)
    assert libc[srcres:srcres+8]!=b"" and int.from_bytes(libc[srctar:srctar+8],"little")==old
    assert ldso[source_offset(ldso,CALL-LDSO_BIAS,2,5):][:2]==bytes.fromhex("ffd0")
    assert ldso[source_offset(ldso,CALLER_RETURN-LDSO_BIAS,4,5):][:4]==bytes.fromhex("4883c318")
    assert ldso[source_offset(ldso,STORE-LDSO_BIAS,3,5):][:3]==bytes.fromhex("498906")
    raw_inventory=inventory["original_IFUNC_source_candidate_resolvers"]
    matches=[r for r in raw_inventory if r["source_index"]==index]
    assert len(matches)==1
    candidate=matches[0]
    assert candidate["original_guest_resolver_entry"]==hex(resolver)
    assert candidate["original_guest_RW_NX_target"]==hex(target)
    assert candidate["original_target_source_qword"]==hex(old)
    assert candidate["resolver_real_FEX_entry_executed"] is False
    alias_indices=[r["index"] for r in ifunc if r["r_addend"]==row["r_addend"]]
    assert len(alias_indices)==aliases[row["r_addend"]]
    assert index in alias_indices
    source=(repository/GUEST_MAIN).read_text().splitlines()
    markers=[i for i,line in enumerate(source,1) if line.strip()=="++RealOriginalLdsoLibcCloses;"]
    assert len(markers)==1
    marker=markers[0]
    # WRITE-only native hardware trial. A hardware WRITE, even if it later
    # passes, is NOT proof of guest resolver CALL, exact RET or ABI return.
    gdb=(
       "set pagination off\nset confirm off\nset breakpoint pending on\n"
       "set output-radix 16\nhandle SIGBUS nostop noprint pass\n"
       "handle SIGCHLD nostop noprint pass\n"
       f"break {GUEST_MAIN}:{marker}\n"
       "commands\nsilent\n"
       f'printf "KERNIX_G0_GENERIC_IFUNC{index}_ORIGINAL_NATIVE_SOURCE_WRITE_WATCH_ARMED index={index} resolver={hex(resolver)} target={hex(target)} old={hex(old)} NO_NEW_RUNTIME_PROOF=1\\n"\n'
       f"x/gx {hex(target)}\n"
       f"watch -location *(unsigned long long *){hex(target)}\n"
       "condition 2 $pc >= 0xffff00000000 && $x28 >= 0xffff00000000\n"
       "continue\nend\nrun\n"
       f'printf "KERNIX_G0_GENERIC_IFUNC{index}_NATIVE_HW_TARGET_WRITER_OBSERVED target={hex(target)} pc=0x%lx guest_rax_x4=0x%lx guest_r14_x19=0x%lx guest_rsp_x8=0x%lx guest_state_x28=0x%lx SOURCE_WRITER_ONLY=1\\n",$pc,$x4,$x19,$x8,$x28\n'
       f"x/gx {hex(target)}\n"
       "x/i $pc-4\n"
       "set $hdr=*(unsigned long long *)$x28\n"
       "set $off=*(unsigned int *)$hdr\n"
       "set $tail=$hdr+$off\n"
       "set $entry=*(unsigned long long *)($tail+8)\n"
       "set $size=*(unsigned long long *)($tail+16)\n"
       "set $cnt=*(unsigned int *)($tail+24)\n"
       f'printf "KERNIX_G0_GENERIC_IFUNC{index}_NATIVE_SOURCE_WRITER_JIT source_entry=0x%lx source_size=0x%lx native_instruction_count=%u native_after_pc=0x%lx\\n",$entry,$size,$cnt,$pc\n'
       "x/8bx $entry\n"
       f"x/8bx {hex(STORE)}\n"
       f"x/8bx {hex(resolver)}\n"
       f'printf "KERNIX_G0_GENERIC_IFUNC{index}_NATIVE_WRITE_ONLY_DIAGNOSTIC_DONE_NOT_INDEPENDENTLY_ATTESTED=1\\n"\n'
       "quit\n"
    )
    assert gdb.count("watch -location *(unsigned long long *)"+hex(target))==1
    assert "rwatch -location" not in gdb and "awatch -location" not in gdb
    assert "quit 1" not in gdb
    tag=f"original-libc-IFUNC{index}-source-only-distinct-native-write-plan"
    (dist/(tag+".gdb")).write_text(gdb)
    receipt={
        "schema":"kernix.g0.original-libc-ifunc-distinct-rela-source-only-native-writer-watch.v1",
        "original_source_libc_sha256":LIBC_SHA,
        "original_source_ldso_sha256":LDSO_SHA,
        "original_libc_RELA_JMPREL_source_records":147,
        "source_IFUNC_count":46,
        "source_distinct_resolver_count":42,
        "candidate_source_index":index,
        "candidate_original_source_table":row["table"],
        "candidate_original_table_index":row["table_index"],
        "candidate_source_type":"R_X86_64_IRELATIVE",
        "original_guest_resolver_entry":hex(resolver),
        "source_original_resolver_8_bytes":libc[srcres:srcres+8].hex(),
        "original_source_resolver_ELF_RX_offset":hex(srcres),
        "original_guest_target":hex(target),
        "original_target_qword":hex(old),
        "original_target_source_RW_NX_ELF_offset":hex(srctar),
        "original_guest_resolver_source_alias_indices":alias_indices,
        "original_resolver_shared_with_102_through_120":any(rows[i]["r_addend"]==row["r_addend"] for i in range(102,121)),
        "source_original_GNU_ldso_CALL_guest_RIP":hex(CALL),
        "source_original_GNU_ldso_caller_return_RIP":hex(CALLER_RETURN),
        "source_original_GNU_ldso_IFUNC_writer_RIP":hex(STORE),
        "source_original_GNU_ldso_writer_bytes":"498906",
        "verified_previous_unique_native_writer_ledger":35,
        "source_only_watch_plan_not_runtime_proof":True,
        "new_candidate_hardware_writer_genuine_observed":False,
        "new_candidate_resolver_CALL_or_RET_native_observed":False,
        "full_147_source_relocation_closure_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    (dist/(tag+".json")).write_text(json.dumps(receipt,indent=2)+"\n")
    print("KERNIX_G0_GENERIC_NEXT_IFUNC_ORIGINAL_SOURCE_PLAN_ONLY_INDEX",index)
    print("KERNIX_G0_GENERIC_NEXT_IFUNC_ORIGINAL_SOURCE_RESOLVER",hex(resolver))
    print("KERNIX_G0_GENERIC_NEXT_IFUNC_ORIGINAL_SOURCE_TARGET",hex(target))
    print("KERNIX_G0_GENERIC_NEXT_IFUNC_ORIGINAL_SOURCE_OLD_QWORD",hex(old))
    print("KERNIX_G0_GENERIC_NEXT_IFUNC_ORIGINAL_SOURCE_ALIASES",",".join(map(str,alias_indices)))
    print("KERNIX_G0_GENERIC_NEXT_IFUNC_WATCH_ONLY_NO_NEW_NATIVE_WRITER_KEEP_LEDGER_35_147")

if __name__=="__main__":
    assert len(sys.argv)==4
    plan(Path(sys.argv[1]),Path(sys.argv[2]),int(sys.argv[3]))
