#!/usr/bin/env python3
"""Source-only next ORIGINAL GNU libc IFUNC #103 real FEX ARM64 writer watch.

The 17/147 accepted writer ledger counts unique original relocations.
IFUNC #102 real hardware evidence never proves #103. Read only immutable
source ELF and verified previous #102 receipt; no manufactured guest stores.
"""
from pathlib import Path
from collections import Counter
import hashlib
import json
import sys
from kernix_g0_original_libc_relocation_type_transition_gate import (
    decode_original_libc, classify, LIBC_SHA, LDSO_SHA
)
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import (
    GUEST_MAIN, LIBC_BIAS, LDSO_BIAS, CALL, CALLER_RETURN, STORE
)

INDEX = 103
OUT = "original-libc-next-IFUNC103-original-source-only-native-watch-plan.json"
GDB = "original-libc-next-IFUNC103-original-source-native-write-only.gdb"
PRIOR = "original-libc-IFUNC102-exact-C3-RET-real-FEX-native-READ-independent-verified.json"

def build(dist: Path, repository: Path):
    root = dist / "original-source-pinned-root"
    libc_path = root / "lib/x86_64-linux-gnu/libc.so.6"
    ldso_path = root / "lib64/ld-linux-x86-64.so.2"
    assert libc_path.is_file() and not libc_path.is_symlink()
    assert ldso_path.is_file() and not ldso_path.is_symlink()
    libc,ldso=libc_path.read_bytes(),ldso_path.read_bytes()
    assert len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA
    assert len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
    typed=classify(decode_original_libc(libc))
    assert typed==json.loads((dist/"original-libc-147-rela-jmprel-typed-source-next-stage-plan.json").read_text())
    assert typed["original_source_IRELATIVE_count"]==46
    assert typed["original_other_RELA_count"]==85
    rows=decode_original_libc(libc)
    first, nextrow = rows[102], rows[INDEX]
    assert first["index"]==102 and first["r_type"]==37
    assert nextrow["index"]==INDEX and nextrow["table"]=="DT_JMPREL"
    assert nextrow["table_index"]==17 and nextrow["r_type"]==37 and nextrow["r_sym"]==0
    assert int(nextrow["r_offset"],16)==int(first["r_offset"],16)+8
    assert int(nextrow["source_guest_target"],16)!=int(first["source_guest_target"],16)
    source_manifest=json.loads((dist/"original-libc-46-IFUNC-IRELATIVE-42-unique-resolver-source-only-plan.json").read_text())
    assert source_manifest["original_IFUNC_source_relocation_count"]==46
    assert source_manifest["original_distinct_resolver_entry_address_count"]==42
    assert source_manifest["IFUNC_execution_real_native_FEX_witness_proven"] is False
    candidates=source_manifest["original_IFUNC_source_candidate_resolvers"]
    assert len(candidates)==46 and candidates[2]["source_index"]==INDEX
    origin=candidates[2]
    resolver=LIBC_BIAS+nextrow["r_addend"]
    target=LIBC_BIAS+int(nextrow["r_offset"],16)
    initial=int(nextrow["original_source_qword"],16)
    assert initial!=0 and nextrow["r_addend"]>0
    assert origin["original_guest_resolver_entry"]==hex(resolver)
    assert origin["original_guest_RW_NX_target"]==hex(target)
    assert origin["original_target_source_qword"]==hex(initial)
    assert origin["resolver_real_FEX_entry_executed"] is False
    assert int.from_bytes(libc[source_offset(libc,nextrow["r_addend"],8,5):source_offset(libc,nextrow["r_addend"],8,5)+8],"little")>=0
    resolver_off=source_offset(libc,nextrow["r_addend"],8,5)
    target_off=source_offset(libc,int(nextrow["r_offset"],16),8,6,nonexec=True)
    assert int.from_bytes(libc[target_off:target_off+8],"little")==initial
    assert libc[resolver_off:resolver_off+4]==bytes.fromhex("f30f1efa")
    assert ldso[source_offset(ldso,CALL-LDSO_BIAS,2,5):][:2]==bytes.fromhex("ffd0")
    assert ldso[source_offset(ldso,CALLER_RETURN-LDSO_BIAS,4,5):][:4]==bytes.fromhex("4883c318")
    assert ldso[source_offset(ldso,STORE-LDSO_BIAS,3,5):][:3]==bytes.fromhex("498906")
    attest=json.loads((dist/PRIOR).read_text())
    assert attest["one_new_real_linux_ARM64_FEX_guest_observed_source_CALL_resolver_JIT_RET_guest_stack_READ_caller_and_writer"] is True
    assert attest["source_target_relocation"]==first["source_guest_target"]
    assert attest["ten_genuine_native_hardware_log_corruptions_rejected"] is True
    assert attest["all_147_libc_RELA_JMPREL_writers_proven"] is False
    all_ifunc=[r for r in rows if r["r_type"]==37]
    entries=Counter(LIBC_BIAS+r["r_addend"] for r in all_ifunc)
    assert len(all_ifunc)==46 and len(entries)==42 and sorted(v for v in entries.values() if v>1)==[2,2,2,2]
    aliases=[r["index"] for r in all_ifunc if r["r_addend"]==nextrow["r_addend"]]
    assert INDEX in aliases
    lines=(repository/GUEST_MAIN).read_text().splitlines()
    markers=[i for i,line in enumerate(lines,1) if line.strip()=="++RealOriginalLdsoLibcCloses;"]
    assert len(markers)==1
    anchor=markers[0]
    # Only the original FEX x86 Linux guest may perform this write.
    # Watch before libc relocation loop; report the true first native stop.
    gdb=(
       "set pagination off\nset confirm off\nset breakpoint pending on\n"
       "set output-radix 16\nhandle SIGBUS nostop noprint pass\n"
       "handle SIGCHLD nostop noprint pass\n"
       f"break {GUEST_MAIN}:{anchor}\n"
       "commands\nsilent\n"
       f'printf "KERNIX_G0_NEXT_IFUNC103_NATIVE_SOURCE_WATCH_ARMED index=103 target={hex(target)} old={hex(initial)} resolver={hex(resolver)} no_execution_yet=1\\n"\n'
       f"x/gx {hex(target)}\n"
       f"watch -location *(unsigned long long *){hex(target)}\n"
       "condition 2 $pc >= 0xffff00000000 && $x28 >= 0xffff00000000\n"
       "continue\nend\nrun\n"
       f'printf "KERNIX_G0_NEXT_IFUNC103_REAL_NATIVE_HARDWARE_WRITE_STOP target={hex(target)} pc=0x%lx rax_x4=0x%lx r14_x19=0x%lx rsp_x8=0x%lx state_x28=0x%lx\\n", $pc,$x4,$x19,$x8,$x28\n'
       f"x/gx {hex(target)}\n"
       "x/i $pc-4\n"
       "set $hdr=*(unsigned long long *)$x28\n"
       "set $off=*(unsigned int *)$hdr\n"
       "set $tail=$hdr+$off\n"
       "set $entry=*(unsigned long long *)($tail+8)\n"
       "set $size=*(unsigned long long *)($tail+16)\n"
       "set $count=*(unsigned int *)($tail+24)\n"
       'printf "KERNIX_G0_NEXT_IFUNC103_NATIVE_SOURCE_JIT guest_entry=0x%lx guest_size=0x%lx inst_count=%u native_after_pc=0x%lx\\n", $entry,$size,$count,$pc\n'
       "x/8bx $entry\n"
       f"x/8bx {hex(STORE)}\n"
       f"x/8bx {hex(resolver)}\n"
       'printf "KERNIX_G0_NEXT_IFUNC103_WRITER_ONLY_DIAGNOSTIC_DONE_CALL_RET_SEPARATE_GATE=1\\n"\n'
       "quit\n"
    )
    assert gdb.count("watch -location *(unsigned long long *)"+hex(target))==1
    assert "awatch " not in gdb and "rwatch " not in gdb
    assert "KERNIX_G0_NEXT_IFUNC103_REAL_NATIVE_HARDWARE_WRITE_STOP" in gdb
    (dist/GDB).write_text(gdb)
    result={
      "schema":"kernix.g0.original-libc-IFUNC103-unique-source-target-hw-watch-only.v1",
      "original_source_libc_sha256":LIBC_SHA,
      "original_source_ldso_sha256":LDSO_SHA,
      "source_index":INDEX,
      "source_table":nextrow["table"],
      "source_relocation_type":"R_X86_64_IRELATIVE",
      "source_guest_resolver_entry":hex(resolver),
      "resolver_source_ELF_RX_file_offset":hex(resolver_off),
      "resolver_original_x86_entry_8_bytes":libc[resolver_off:resolver_off+8].hex(),
      "source_resolver_alias_indices":aliases,
      "resolver_same_as_102":resolver==LIBC_BIAS+first["r_addend"],
      "source_guest_target":hex(target),
      "original_target_qword":hex(initial),
      "original_IFUNC102_target_distinct":first["source_guest_target"],
      "original_GNU_loader_writer_guest_RIP":hex(STORE),
      "original_GNU_loader_writer_x86_bytes":"498906",
      "target_rw_nx_source_verified":True,
      "resolver_rx_source_verified":True,
      "source_only_diagnostic_not_executed":True,
      "new_original_ifunc103_native_hardware_writer_proven":False,
      "new_original_ifunc103_call_ret_proven":False,
      "unique_native_writer_receipt_count":17,
      "all_147_relocations_closed":False,
      "Android_Bionic_Wine_Proton_games_proven":False
    }
    (dist/OUT).write_text(json.dumps(result,indent=2)+"\n")
    print("KERNIX_G0_NEXT_ORIGINAL_LIBC_IFUNC103_SOURCE_ONLY_VERIFIED_NO_NATIVE_NEW_WRITER")
    print("KERNIX_G0_IFUNC103_EXACT_ORIGINAL_SOURCE_INDEX",INDEX)
    print("KERNIX_G0_IFUNC103_EXACT_ORIGINAL_SOURCE_RESOLVER",hex(resolver))
    print("KERNIX_G0_IFUNC103_EXACT_ORIGINAL_SOURCE_TARGET",hex(target))
    print("KERNIX_G0_IFUNC103_EXACT_ORIGINAL_SOURCE_OLD_QWORD",hex(initial))
    print("KERNIX_G0_IFUNC103_RESOLVER_ALIASES",",".join(map(str,aliases)))

if __name__=="__main__":
    assert len(sys.argv)==3
    build(Path(sys.argv[1]),Path(sys.argv[2]))
