#!/usr/bin/env python3
"""Source-locked next unique libc IFUNC104 target + actual FEX hardware WATCH plan.

No actual native write or source resolver execution; no 19th writer receipt.
Prior 18 independent native writer receipts are mandatory and not recycled.
Never assume adjacent ELF relocation records have adjacent target addresses,
or different records have distinct source resolver entrypoints.
"""
import hashlib,json,sys
from collections import Counter
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import decode_original_libc,classify,LIBC_SHA,LDSO_SHA
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import GUEST_MAIN,LIBC_BIAS,LDSO_BIAS,CALL,CALLER_RETURN,STORE

INDEX=104
OUT="original-libc-IFUNC104-next-source-unique-target-native-HW-WRITE-plan.json"
GDB="original-libc-IFUNC104-next-source-unique-target-native-HW-WRITE.gdb"
PRIOR="original-libc-IFUNC103-original-one-FEX-CALL-JIT-C3-RET-stack-read-and-writer-independent.json"

def build(dist:Path,repo:Path):
    root=dist/"original-source-pinned-root"
    p=root/"lib/x86_64-linux-gnu/libc.so.6"
    ld=root/"lib64/ld-linux-x86-64.so.2"
    assert p.is_file() and not p.is_symlink() and ld.is_file() and not ld.is_symlink()
    libc,ldso=p.read_bytes(),ld.read_bytes()
    assert len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA
    assert len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
    rows=decode_original_libc(libc)
    types=classify(rows)
    assert types["original_source_IRELATIVE_count"]==46
    assert types["original_other_RELA_count"]==85
    assert types["original_DT_JMPREL_type_counts"]=={"R_X86_64_JUMP_SLOT":16,"R_X86_64_IRELATIVE":45}
    row=rows[INDEX]
    assert row["index"]==INDEX and row["table"]=="DT_JMPREL"
    assert row["table_index"]==18 and row["r_type"]==37 and row["r_sym"]==0
    assert row["r_addend"]>0
    resolver=LIBC_BIAS+row["r_addend"]
    target=LIBC_BIAS+int(row["r_offset"],16)
    before=int(row["original_source_qword"],16)
    assert before!=0
    assert len({int(r["source_guest_target"],16) for r in rows})==147
    assert target!=int(rows[102]["source_guest_target"],16)
    assert target!=int(rows[103]["source_guest_target"],16)
    ret_off=source_offset(libc,row["r_addend"],8,5)
    assert libc[ret_off:ret_off+4]==bytes.fromhex("f30f1efa")
    tgt_off=source_offset(libc,int(row["r_offset"],16),8,6,nonexec=True)
    assert int.from_bytes(libc[tgt_off:tgt_off+8],"little")==before
    assert ldso[source_offset(ldso,CALL-LDSO_BIAS,2,5):][:2]==bytes.fromhex("ffd0")
    assert ldso[source_offset(ldso,CALLER_RETURN-LDSO_BIAS,4,5):][:4]==bytes.fromhex("4883c318")
    assert ldso[source_offset(ldso,STORE-LDSO_BIAS,3,5):][:3]==bytes.fromhex("498906")
    original=json.loads((dist/"original-libc-46-IFUNC-IRELATIVE-42-unique-resolver-source-only-plan.json").read_text())
    assert original["source_original_libc_sha256"]==LIBC_SHA
    assert original["source_original_ldso_sha256"]==LDSO_SHA
    candidates=original["original_IFUNC_source_candidate_resolvers"]
    assert len(candidates)==46 and candidates[3]["source_index"]==INDEX
    assert candidates[3]["original_guest_resolver_entry"]==hex(resolver)
    assert candidates[3]["original_guest_RW_NX_target"]==hex(target)
    assert candidates[3]["original_target_source_qword"]==hex(before)
    assert candidates[3]["resolver_real_FEX_entry_executed"] is False
    reslist=[r for r in rows if r["r_type"]==37]
    resolver_count=Counter(r["r_addend"] for r in reslist)
    assert len(reslist)==46 and len(resolver_count)==42 and sorted(x for x in resolver_count.values() if x>1)==[2,2,2,2]
    aliases=[r["index"] for r in reslist if r["r_addend"]==row["r_addend"]]
    assert INDEX in aliases
    previous=json.loads((dist/PRIOR).read_text())
    assert previous["source_ifunc_relocation_index"]==103
    assert previous["same_process_original_FEX_CALL_resolver_JIT_exact_C3_RET_stack_HW_READ_caller_and_source_writer_proven"] is True
    assert previous["twelve_actual_native_hardware_evidence_tamper_cases_rejected"] is True
    assert previous["previous_independent_18_unique_writer_targets_unchanged"]==18
    assert previous["all_147_original_libc_relocations_proven"] is False
    source=(repo/GUEST_MAIN).read_text().splitlines()
    anchors=[i for i,line in enumerate(source,1) if line.strip()=="++RealOriginalLdsoLibcCloses;"]
    assert len(anchors)==1
    bp=anchors[0]
    gdb=f'''set pagination off
set confirm off
set breakpoint pending on
set output-radix 16
handle SIGBUS nostop noprint pass
handle SIGCHLD nostop noprint pass
break {GUEST_MAIN}:{bp}
commands
silent
printf "KERNIX_G0_ORIGINAL_IFUNC104_DISTINCT_NATIVE_HW_WATCH_ARMED index=104 target={hex(target)} original={hex(before)} resolver={hex(resolver)} SOURCE_NOT_EXECUTION\\n"
x/gx {hex(target)}
watch -location *(unsigned long long *){hex(target)}
condition 2 $pc >= 0xffff00000000 && $x28 >= 0xffff00000000
continue
end
run
printf "KERNIX_G0_ORIGINAL_IFUNC104_UNVERIFIED_NATIVE_HW_WRITER_DIAGNOSTIC target={hex(target)} pc=0x%lx x4=0x%lx x19=0x%lx x8=0x%lx x28=0x%lx\\n", $pc,$x4,$x19,$x8,$x28
x/gx {hex(target)}
x/i $pc-4
set $hdr=*(unsigned long long *)$x28
set $off=*(unsigned int *)$hdr
set $tail=$hdr+$off
set $entry=*(unsigned long long *)($tail+8)
set $size=*(unsigned long long *)($tail+16)
set $cnt=*(unsigned int *)($tail+24)
printf "KERNIX_G0_ORIGINAL_IFUNC104_UNVERIFIED_NATIVE_GNU_SOURCE_JIT entry=0x%lx size=0x%lx count=%u pc=0x%lx\\n", $entry,$size,$cnt,$pc
x/8bx $entry
x/8bx {hex(resolver)}
x/8bx {hex(STORE)}
printf "KERNIX_G0_ORIGINAL_IFUNC104_DIAGNOSTIC_ENDED_NEW_WRITER_REQUIRES_SEPARATE_INDEPENDENT_PROOF=1\\n"
quit
'''
    assert gdb.count("watch -location *(unsigned long long *)"+hex(target))==1
    assert "rwatch " not in gdb and "awatch " not in gdb
    (dist/GDB).write_text(gdb)
    data={
      "schema":"kernix.g0.original-libc-IFUNC104-immutable-source-next-unique-writer-HW-watch-only.v1",
      "original_source_libc_sha256":LIBC_SHA,
      "original_source_ldso_sha256":LDSO_SHA,
      "source_ifunc_index":INDEX,
      "source_type":"R_X86_64_IRELATIVE",
      "source_table":"DT_JMPREL",
      "source_table_index":row["table_index"],
      "source_original_resolver_guest_RIP":hex(resolver),
      "source_resolver_original_RX_offset":hex(ret_off),
      "source_resolver_original_bytes":libc[ret_off:ret_off+8].hex(),
      "original_resolver_alias_source_indices":aliases,
      "resolver_matches_103":row["r_addend"]==rows[103]["r_addend"],
      "original_unique_guest_target":hex(target),
      "original_target_source_qword":hex(before),
      "previous_independent_unique_writer_ledger":18,
      "new_ifunc104_native_hardware_writer_proven":False,
      "ifunc104_resolver_actual_guest_call_ret_proven":False,
      "all_original_147_relocations_proven":False,
      "Android_Bionic_Wine_Proton_games_proven":False,
    }
    (dist/OUT).write_text(json.dumps(data,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_IFUNC104_SOURCE_ONLY_DISTINCT_RELOCATION_PASS_NO_NEW_HARDWARE_WRITER")
    print("KERNIX_G0_ORIGINAL_IFUNC104_SOURCE_RESOLVER",hex(resolver))
    print("KERNIX_G0_ORIGINAL_IFUNC104_SOURCE_TARGET",hex(target))
    print("KERNIX_G0_ORIGINAL_IFUNC104_SOURCE_QWORD",hex(before))
    print("KERNIX_G0_ORIGINAL_IFUNC104_RESOLVER_ALIASES",",".join(map(str,aliases)))

if __name__=="__main__":
    assert len(sys.argv)==3
    build(Path(sys.argv[1]),Path(sys.argv[2]))
