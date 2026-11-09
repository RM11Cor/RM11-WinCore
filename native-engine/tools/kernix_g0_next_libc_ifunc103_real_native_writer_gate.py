#!/usr/bin/env python3
"""Strict original GNU x86 libc IFUNC103 real Linux ARM64 FEX WRITE-only gate.

Real source #103 (not #102) target watch + exact original GNU x86 writer JIT
+ native AArch64 STLR and register/old/new proof. This does NOT attest source
resolver CALL, C3 RET, whole IFUNC semantics, or Android game execution.
"""
import hashlib
import json
import re
import sys
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import decode_original_libc, classify, LIBC_SHA, LDSO_SHA
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import LIBC_BIAS, LDSO_BIAS, STORE
from kernix_g0_next_libc_ifunc103_source_native_watch_plan import OUT as PLAN, GDB

INDEX=103
TARGET=0x804202d68
OLD=0x283b0
RESOLVER=0x8040b4f90
LOG="original-libc-next-IFUNC103-native-hardware-write-only-FEX.log"
EXIT="original-libc-next-IFUNC103-native-hardware-write-only-FEX.exit"
PREVIOUS="original-libc-IFUNC102-exact-C3-RET-real-FEX-native-READ-independent-verified.json"
OUTPUT="original-libc-IFUNC103-independently-source-verified-real-FEX-native-write-only.json"

def one(pattern, raw):
    found=re.findall(pattern,raw,re.M)
    assert len(found)==1,("missing/duplicated event",pattern,len(found))
    return found[0]

def attest(dist:Path, *,override=None):
    root=dist/"original-source-pinned-root"
    libc=(root/"lib/x86_64-linux-gnu/libc.so.6").read_bytes()
    ldso=(root/"lib64/ld-linux-x86-64.so.2").read_bytes()
    assert len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA
    assert len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
    row=decode_original_libc(libc)[INDEX]
    assert row["index"]==INDEX and row["table"]=="DT_JMPREL" and row["r_type"]==37
    assert row["r_sym"]==0 and row["table_index"]==17
    assert int(row["source_guest_target"],16)==TARGET
    assert int(row["original_source_qword"],16)==OLD
    assert LIBC_BIAS+row["r_addend"]==RESOLVER
    assert libc[source_offset(libc,RESOLVER-LIBC_BIAS,4,5):][:4]==bytes.fromhex("f30f1efa")
    assert ldso[source_offset(ldso,STORE-LDSO_BIAS,3,5):][:3]==bytes.fromhex("498906")
    assert classify(decode_original_libc(libc))==json.loads(
      (dist/"original-libc-147-rela-jmprel-typed-source-next-stage-plan.json").read_text())
    source=json.loads((dist/PLAN).read_text())
    assert source["source_index"]==INDEX and source["source_table"]=="DT_JMPREL"
    assert source["source_guest_resolver_entry"]==hex(RESOLVER)
    assert source["source_guest_target"]==hex(TARGET)
    assert source["original_target_qword"]==hex(OLD)
    assert source["original_IFUNC102_target_distinct"]=="0x804202d78"
    assert source["new_original_ifunc103_native_hardware_writer_proven"] is False
    assert source["unique_native_writer_receipt_count"]==17
    assert source["source_resolver_alias_indices"]==[103]
    assert source["resolver_same_as_102"] is False
    previous=json.loads((dist/PREVIOUS).read_text())
    assert previous["source_target_relocation"]=="0x804202d78"
    assert previous["one_new_real_linux_ARM64_FEX_guest_observed_source_CALL_resolver_JIT_RET_guest_stack_READ_caller_and_writer"] is True
    assert previous["ten_genuine_native_hardware_log_corruptions_rejected"] is True
    assert previous["all_147_libc_RELA_JMPREL_writers_proven"] is False
    gdb=(dist/GDB).read_text()
    assert gdb.count("watch -location *(unsigned long long *)0x804202d68")==1
    assert "rwatch " not in gdb and "awatch " not in gdb
    assert (dist/EXIT).read_text().strip()=="0"
    raw=(dist/LOG).read_text(errors="replace") if override is None else override
    assert "Error in sourced command file" not in raw
    events=[
        "KERNIX_G0_NEXT_IFUNC103_NATIVE_SOURCE_WATCH_ARMED ",
        "KERNIX_G0_NEXT_IFUNC103_REAL_NATIVE_HARDWARE_WRITE_STOP ",
        "KERNIX_G0_NEXT_IFUNC103_NATIVE_SOURCE_JIT ",
        "KERNIX_G0_NEXT_IFUNC103_WRITER_ONLY_DIAGNOSTIC_DONE_CALL_RET_SEPARATE_GATE=1",
    ]
    assert all(raw.count(x)==1 for x in events)
    assert [raw.index(x) for x in events]==sorted(raw.index(x) for x in events)
    armed=one(
      r"^KERNIX_G0_NEXT_IFUNC103_NATIVE_SOURCE_WATCH_ARMED index=(\d+) "
      r"target=(0x[0-9a-fA-F]+) old=(0x[0-9a-fA-F]+) resolver=(0x[0-9a-fA-F]+) no_execution_yet=1$",raw)
    assert (int(armed[0]),int(armed[1],16),int(armed[2],16),int(armed[3],16))==(INDEX,TARGET,OLD,RESOLVER)
    w=re.findall(r"^Hardware watchpoint 2: -location \*\(unsigned long long \*\)0x([0-9a-fA-F]+)$",raw,re.M)
    assert len(w)==2 and all(int(x,16)==TARGET for x in w)
    before=int(one(r"^Old value = (0x[0-9a-fA-F]+)$",raw),16)
    after=int(one(r"^New value = (0x[0-9a-fA-F]+)$",raw),16)
    assert before==OLD and after>0 and after!=OLD
    assert re.search(r"^0x%x:\s+0x%016x$"%(TARGET,after),raw,re.M)
    stop=one(
      r"^KERNIX_G0_NEXT_IFUNC103_REAL_NATIVE_HARDWARE_WRITE_STOP "
      r"target=(0x[0-9a-fA-F]+) pc=(0x[0-9a-fA-F]+) rax_x4=(0x[0-9a-fA-F]+) "
      r"r14_x19=(0x[0-9a-fA-F]+) rsp_x8=(0x[0-9a-fA-F]+) state_x28=(0x[0-9a-fA-F]+)$",raw)
    target,pc,rax,r14,rsp,state=[int(x,16) for x in stop]
    assert (target,rax,r14)==(TARGET,after,TARGET)
    assert pc>=0xffff00000000 and pc%4==0
    assert 0x803000000<=rsp<0x803010000 and state>=0xffff00000000
    assert re.search(r"^\s*0x%x:\s+stlr\s+x4,\s*\[x19\]\s*$"%(pc-4),raw,re.M)
    h=one(
      r"^KERNIX_G0_NEXT_IFUNC103_NATIVE_SOURCE_JIT guest_entry=(0x[0-9a-fA-F]+) "
      r"guest_size=(0x[0-9a-fA-F]+) inst_count=(\d+) native_after_pc=(0x[0-9a-fA-F]+)$",raw)
    guest,size,count,hostpc=int(h[0],16),int(h[1],16),int(h[2]),int(h[3],16)
    assert (guest,size,count,hostpc)==(STORE,3,2,pc)
    bytestrings=re.findall(r"^0x%x:\s+((?:0x[0-9a-fA-F]{2}\s+){7}0x[0-9a-fA-F]{2})\s*$"%STORE,raw,re.M)
    assert len(bytestrings)==2 and len(set(bytestrings))==1
    original_bytes=bytes(int(x,16) for x in re.findall(r"0x[0-9a-fA-F]{2}",bytestrings[0]))
    assert original_bytes==ldso[
      source_offset(ldso,STORE-LDSO_BIAS,8,5):
      source_offset(ldso,STORE-LDSO_BIAS,8,5)+8]
    assert original_bytes[:3]==bytes.fromhex("498906")
    assert re.search(r"^0x%x:\s+0xf3\s+0x0f\s+0x1e\s+0xfa"%RESOLVER,raw,re.M)
    locations=[]
    for label,data,bias in (("libc",libc,LIBC_BIAS),("ld-linux",ldso,LDSO_BIAS)):
        try:source_offset(data,after-bias,1,5)
        except AssertionError:continue
        locations.append(label)
    assert locations==["libc"],"returned target is not pinned original libc RX"
    assert raw.index("KERNIX_G0_NEXT_IFUNC103_NATIVE_SOURCE_WATCH_ARMED")<raw.index("Old value = ")<raw.index(
        "New value = ")<raw.index("KERNIX_G0_NEXT_IFUNC103_REAL_NATIVE_HARDWARE_WRITE_STOP")<raw.index("KERNIX_G0_NEXT_IFUNC103_NATIVE_SOURCE_JIT")
    return {
      "schema":"kernix.g0.original-libc-IFUNC103-real-ARM64-FEX-native-source-writer-only.v1",
      "original_source_libc_sha256":LIBC_SHA,
      "original_source_ldso_sha256":LDSO_SHA,
      "source_original_ifunc_index":INDEX,
      "source_original_resolver_guest_RIP":hex(RESOLVER),
      "source_original_relocation_guest_target":hex(TARGET),
      "original_target_old_qword":hex(OLD),
      "actual_native_hardware_new_qword":hex(after),
      "source_original_GNU_x86_writer_guest_RIP":hex(STORE),
      "source_original_GNU_x86_writer_bytes":"498906",
      "real_FEX_native_AArch64_store_instruction":"stlr x4, [x19]",
      "real_native_hardware_after_store_PC":hex(pc),
      "original_libc_RX_result_pointer":True,
      "previous_IFUNC102_independent_receipt_verified":True,
      "IFUNC103_distinct_native_hardware_writer_independently_proven":True,
      "unique_original_libc_individual_native_writer_receipts":18,
      "IFUNC103_resolver_CALL_RET_same_process_proven":False,
      "remaining_44_IFUNC_individual_native_writers_proven":False,
      "other_85_RELA_writers_proven":False,
      "all_147_original_libc_relocations_closed_in_one_process":False,
      "Android_Bionic_Wine_Proton_games_proven":False
    }


def negatives(dist:Path):
    raw=(dist/LOG).read_text(errors="replace")
    mutants=[
      ("old_qword_wrong",r"^Old value = 0x[0-9a-fA-F]+$","Old value = 0x1"),
      ("new_qword_wrong",r"^New value = 0x[0-9a-fA-F]+$","New value = 0x1"),
      ("source_target_forged",r"^(KERNIX_G0_NEXT_IFUNC103_NATIVE_SOURCE_WATCH_ARMED index=103 target=)0x[0-9a-fA-F]+",r"\g<1>0x804202d78"),
      ("native_RAX_forged",r"^(KERNIX_G0_NEXT_IFUNC103_REAL_NATIVE_HARDWARE_WRITE_STOP [^\n]+ rax_x4=)0x[0-9a-fA-F]+",r"\g<1>0x1"),
      ("native_R14_forged",r"^(KERNIX_G0_NEXT_IFUNC103_REAL_NATIVE_HARDWARE_WRITE_STOP [^\n]+ r14_x19=)0x[0-9a-fA-F]+",r"\g<1>0x804202d78"),
      ("native_JIT_guest_writer_forged",r"^(KERNIX_G0_NEXT_IFUNC103_NATIVE_SOURCE_JIT guest_entry=)0x[0-9a-fA-F]+",r"\g<1>0x1"),
      ("source_resolver_forged",r"^(KERNIX_G0_NEXT_IFUNC103_NATIVE_SOURCE_WATCH_ARMED [^\n]+ resolver=)0x[0-9a-fA-F]+",r"\g<1>0x8040b4f00"),
      ("delete_both_hardware_watchpoints",r"^Hardware watchpoint 2: -location \*\(unsigned long long \*\)0x804202d68$","MISSING_HARDWARE_WATCH"),
      ("change_native_store_opcode",r"^\s*0x[0-9a-fA-F]+:\s+stlr\s+x4,\s*\[x19\]\s*$","0x0: ldr x4, [x19]"),
    ]
    checked=[]
    for name,pat,replacement in mutants:
        modified,n=re.subn(pat,replacement,raw,count=0,flags=re.M)
        assert n>=1 and modified!=raw,(name,n)
        try:
            attest(dist,override=modified)
        except AssertionError:
            checked.append(name)
        else:raise AssertionError("FAIL OPEN accepted modified original native IFUNC103 log: "+name)
    assert len(checked)==9
    return checked


def main(dist:Path):
    proof=attest(dist)
    names=negatives(dist)
    proof["nine_source_locked_native_hardware_tamper_controls_rejected"]=True
    proof["negative_names"]=names
    (dist/OUTPUT).write_text(json.dumps(proof,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_IFUNC103_INDEPENDENT_TRUE_FEX_ARM64_HARDWARE_WRITER_PROVEN_ONLY_NO_CALL_RET_OR_ANDROID")


if __name__=="__main__":
    assert len(sys.argv)==2
    main(Path(sys.argv[1]))
