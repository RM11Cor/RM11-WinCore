#!/usr/bin/env python3
"""Certify ONLY a new original GNU libc IFUNC105 real native FEX ARM64 writer.

Requires immutable original GNU ELF, independent prior complete #104 hardware
CALL/RET/write receipt, exact preflight + native-source GDB bytes, and actual
native HW write to #105's unique ELF source target. Ten forged-live-log cases
must be rejected. No original #105 CALL/RET or Android/Windows-game proof.
"""
import hashlib,json,re,sys
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import decode_original_libc, LIBC_SHA, LDSO_SHA
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_original_libc_ifunc105_source_distinct_hw_watch_plan import (
    PREVIOUS,LIBC_BIAS,LDSO_BIAS,STORE
)

INDEX=105
RESOLVER=0x8040cc270
TARGET=0x804202d40
OLD=0x28360
PLAN="original-libc-IFUNC105-source-only-distinct-native-write-plan.json"
GDB="original-libc-IFUNC105-source-only-distinct-native-write-plan.gdb"
LOG="original-libc-IFUNC105-real-FEX-native-HW-WRITE-only.log"
EXIT="original-libc-IFUNC105-real-FEX-native-HW-WRITE-only.exit"
OUTPUT="original-libc-IFUNC105-real-FEX-ARM64-original-GNU-native-writer-independently-verified.json"

def one(pattern,raw):
    matches=re.findall(pattern,raw,re.M)
    assert len(matches)==1,("missing or ambiguous true native source event",pattern,len(matches))
    return matches[0]

def attest(dist:Path,override=None):
    root=dist/"original-source-pinned-root"
    libc=(root/"lib/x86_64-linux-gnu/libc.so.6").read_bytes()
    ldso=(root/"lib64/ld-linux-x86-64.so.2").read_bytes()
    assert len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA
    assert len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
    row=decode_original_libc(libc)[INDEX]
    assert row["index"]==INDEX and row["table"]=="DT_JMPREL"
    assert row["table_index"]==19 and row["r_type"]==37 and row["r_sym"]==0
    assert LIBC_BIAS+row["r_addend"]==RESOLVER
    assert int(row["source_guest_target"],16)==TARGET
    assert int(row["original_source_qword"],16)==OLD
    assert ldso[source_offset(ldso,STORE-LDSO_BIAS,3,5):][:3]==bytes.fromhex("498906")
    plan=json.loads((dist/PLAN).read_text())
    assert plan["original_source_libc_sha256"]==LIBC_SHA
    assert plan["original_source_ldso_sha256"]==LDSO_SHA
    assert plan["candidate_source_index"]==INDEX
    assert plan["candidate_original_source_table"]=="DT_JMPREL"
    assert plan["candidate_original_table_index"]==19
    assert plan["candidate_source_type"]=="R_X86_64_IRELATIVE"
    assert plan["original_guest_resolver_entry"]==hex(RESOLVER)
    assert plan["original_guest_target"]==hex(TARGET)
    assert plan["original_target_qword"]==hex(OLD)
    assert plan["original_guest_resolver_source_alias_indices"]==[INDEX]
    assert plan["verified_previous_unique_native_writer_ledger"]==19
    assert plan["source_only_watch_plan_not_runtime_proof"] is True
    assert plan["new_candidate_hardware_writer_genuine_observed"] is False
    assert plan["new_candidate_resolver_CALL_or_RET_native_observed"] is False
    assert plan["full_147_source_relocation_closure_proven"] is False
    assert plan["Android_Bionic_Wine_Proton_games_proven"] is False
    old=json.loads((dist/PREVIOUS).read_text())
    assert old["source_original_libc_sha256"]==LIBC_SHA
    assert old["source_original_ldso_sha256"]==LDSO_SHA
    assert old["original_source_IFUNC_index"]==104
    assert old["source_original_RET_guest_RIP"]=="0x8040b309c"
    assert old["source_original_target"]=="0x804202d50"
    assert old["genuine_original_linux_FEX_ARM64_ONE_process_IFUNC104_CALL_resolver_JIT_C3_RET_native_hardware_read_and_writer_proven"] is True
    assert old["ten_genuine_native_hardware_log_corruptions_independently_rejected"] is True
    assert old["native_source_original_IFUNC104_distinct_writer_ledger_count"]==19
    assert old["all_147_original_libc_RELA_JMPREL_writers_one_process_proven"] is False
    g=(dist/GDB).read_text()
    assert g.count("watch -location *(unsigned long long *)"+hex(TARGET))==1
    assert "rwatch " not in g and "awatch " not in g
    assert (dist/EXIT).read_text().strip()=="0"
    raw=(dist/LOG).read_text(errors="replace") if override is None else override
    assert "Error in sourced command file" not in raw and "No registers." not in raw
    markers=[
      "KERNIX_G0_GENERIC_IFUNC105_ORIGINAL_NATIVE_SOURCE_WRITE_WATCH_ARMED ",
      "KERNIX_G0_GENERIC_IFUNC105_NATIVE_HW_TARGET_WRITER_OBSERVED ",
      "KERNIX_G0_GENERIC_IFUNC105_NATIVE_SOURCE_WRITER_JIT ",
      "KERNIX_G0_GENERIC_IFUNC105_NATIVE_WRITE_ONLY_DIAGNOSTIC_DONE_NOT_INDEPENDENTLY_ATTESTED=1",
    ]
    assert all(raw.count(m)==1 for m in markers)
    indices=[raw.index(m) for m in markers]
    assert indices==sorted(indices) and len(set(indices))==len(indices)
    armed=one(
      r"^KERNIX_G0_GENERIC_IFUNC105_ORIGINAL_NATIVE_SOURCE_WRITE_WATCH_ARMED index=(\d+) "
      r"resolver=(0x[0-9a-fA-F]+) target=(0x[0-9a-fA-F]+) "
      r"old=(0x[0-9a-fA-F]+) NO_NEW_RUNTIME_PROOF=1$",raw)
    assert (int(armed[0]),int(armed[1],16),int(armed[2],16),int(armed[3],16))==(INDEX,RESOLVER,TARGET,OLD)
    watch=re.findall(r"^Hardware watchpoint 2: -location \*\(unsigned long long \*\)0x([0-9a-fA-F]+)$",raw,re.M)
    assert len(watch)==2 and all(int(x,16)==TARGET for x in watch)
    before=int(one(r"^Old value = (0x[0-9a-fA-F]+)$",raw),16)
    after=int(one(r"^New value = (0x[0-9a-fA-F]+)$",raw),16)
    assert before==OLD and after!=OLD and after!=0
    assert re.search(r"^0x%x:\s+0x%016x$"%(TARGET,after),raw,re.M)
    stop=one(
      r"^KERNIX_G0_GENERIC_IFUNC105_NATIVE_HW_TARGET_WRITER_OBSERVED "
      r"target=(0x[0-9a-fA-F]+) pc=(0x[0-9a-fA-F]+) "
      r"guest_rax_x4=(0x[0-9a-fA-F]+) guest_r14_x19=(0x[0-9a-fA-F]+) "
      r"guest_rsp_x8=(0x[0-9a-fA-F]+) guest_state_x28=(0x[0-9a-fA-F]+) "
      r"SOURCE_WRITER_ONLY=1$",raw)
    target,pc,rax,r14,rsp,state=(int(x,16) for x in stop)
    assert (target,rax,r14)==(TARGET,after,TARGET)
    assert pc>=0xffff00000000 and pc%4==0
    assert 0x803000000<=rsp<0x803010000 and state>=0xffff00000000
    assert re.search(r"^\s*0x%x:\s+stlr\s+x4,\s*\[x19\]\s*$"%(pc-4),raw,re.M)
    jit=one(
      r"^KERNIX_G0_GENERIC_IFUNC105_NATIVE_SOURCE_WRITER_JIT "
      r"source_entry=(0x[0-9a-fA-F]+) source_size=(0x[0-9a-fA-F]+) "
      r"native_instruction_count=(\d+) native_after_pc=(0x[0-9a-fA-F]+)$",raw)
    guest,size,count,hostpc=(int(x,16) if i!=2 else int(x) for i,x in enumerate(jit))
    assert (guest,size,count,hostpc)==(STORE,3,2,pc)
    originals=re.findall(
      r"^0x%x:\s+((?:0x[0-9a-fA-F]{2}\s+){7}0x[0-9a-fA-F]{2})\s*$"%STORE,raw,re.M)
    assert len(originals)==2 and len(set(originals))==1
    actual_source=bytes(int(x,16) for x in re.findall(r"0x[0-9a-fA-F]{2}",originals[0]))
    assert actual_source==ldso[source_offset(ldso,STORE-LDSO_BIAS,8,5):][:8]
    assert actual_source[:3]==bytes.fromhex("498906")
    source_resolver_print=libc[source_offset(libc,RESOLVER-LIBC_BIAS,8,5):][:8]
    assert len(source_resolver_print)==8
    assert re.search(r"^0x%x:\s+"%RESOLVER,raw,re.M)
    # Native GNU IFUNC resolver output must resolve to immutable original libc executable code.
    locations=[]
    for label,original,bias in (("libc",libc,LIBC_BIAS),("ldso",ldso,LDSO_BIAS)):
      try:source_offset(original,after-bias,1,5)
      except AssertionError:continue
      locations.append(label)
    assert locations==["libc"],("source IFUNC105 resolver returned non-original libc RX",hex(after))
    assert raw.index(markers[0])<raw.index("Old value = ")<raw.index("New value = ")<raw.index(markers[1])<raw.index(markers[2])
    return {
       "schema":"kernix.g0.original-libc-IFUNC105-real-AArch64-FEX-original-native-HW-writer-only-independent.v1",
       "source_original_libc_sha256":LIBC_SHA,
       "source_original_ldso_sha256":LDSO_SHA,
       "original_IFUNC_source_index":INDEX,
       "source_original_resolver_guest_RIP":hex(RESOLVER),
       "source_original_relocation_target":hex(TARGET),
       "original_target_before":hex(OLD),
       "actual_original_native_writer_new_qword":hex(after),
       "source_original_GNU_x86_writer_guest_RIP":hex(STORE),
       "original_guest_GNU_writer_bytes":"498906",
       "actual_source_FEX_ARM64_writer_after_PC":hex(pc),
       "actual_source_FEX_ARM64_writer_opcode":"stlr x4, [x19]",
       "new_source_IFUNC105_distinct_original_libc_FEX_ARM64_hardware_writer_independently_verified":True,
       "previous_IFUNC104_full_native_CALL_RET_hardware_read_and_writer_verified":True,
       "unique_original_libc_per_target_native_writer_count":20,
       "source_original_IFUNC105_same_guest_CALL_RET_stack_read_proven":False,
       "remaining_original_IFUNC_source_writers_unverified":42,
       "remaining_other_non_IFUNC_RELA_native_writers_unverified":85,
       "all_147_original_libc_RELA_JMPREL_writers_in_one_process_proven":False,
       "Android_Bionic_Wine_Proton_games_proven":False
    }

def falsify(dist:Path):
    raw=(dist/LOG).read_text(errors="replace")
    checks=[
      ("switch_source_index",r"(^KERNIX_G0_GENERIC_IFUNC105_ORIGINAL_NATIVE_SOURCE_WRITE_WATCH_ARMED index=)105",r"\g<1>104"),
      ("switch_guest_target",r"(^KERNIX_G0_GENERIC_IFUNC105_ORIGINAL_NATIVE_SOURCE_WRITE_WATCH_ARMED [^\n]+ target=)0x[0-9a-fA-F]+",r"\g<1>0x804202d50"),
      ("switch_source_resolver",r"(^KERNIX_G0_GENERIC_IFUNC105_ORIGINAL_NATIVE_SOURCE_WRITE_WATCH_ARMED [^\n]+ resolver=)0x[0-9a-fA-F]+",r"\g<1>0x8040b3050"),
      ("mutate_previous_old",r"^Old value = 0x[0-9a-fA-F]+$","Old value = 0x1"),
      ("mutate_actual_new",r"^New value = 0x[0-9a-fA-F]+$","New value = 0x1"),
      ("wrong_native_target_x19",r"(^KERNIX_G0_GENERIC_IFUNC105_NATIVE_HW_TARGET_WRITER_OBSERVED [^\n]+ guest_r14_x19=)0x[0-9a-fA-F]+",r"\g<1>0x804202d50"),
      ("wrong_native_result_x4",r"(^KERNIX_G0_GENERIC_IFUNC105_NATIVE_HW_TARGET_WRITER_OBSERVED [^\n]+ guest_rax_x4=)0x[0-9a-fA-F]+",r"\g<1>0x1"),
      ("wrong_source_GNU_writer_jit",r"(^KERNIX_G0_GENERIC_IFUNC105_NATIVE_SOURCE_WRITER_JIT source_entry=)0x[0-9a-fA-F]+",r"\g<1>0x1"),
      ("remove_native_watchpoint",r"^Hardware watchpoint 2: -location \*\(unsigned long long \*\)0x804202d40$","NO_REAL_NATIVE_WATCH"),
      ("remove_stlr_arm64_opcode",r"^\s*0x[0-9a-fA-F]+:\s+stlr\s+x4,\s*\[x19\]\s*$","0x0: ldr x4, [x19]"),
    ]
    checked=[]
    for name,pattern,repl in checks:
       mutant,count=re.subn(pattern,repl,raw,flags=re.M)
       assert count>=1 and mutant!=raw,(name,count)
       try:attest(dist,override=mutant)
       except AssertionError:checked.append(name)
       else:raise AssertionError("FAIL OPEN: false original IFUNC105 hardware evidence accepted "+name)
    assert len(checked)==10
    return checked

def main(dist:Path):
    obj=attest(dist)
    negative=falsify(dist)
    obj["ten_forged_actual_native_hardware_trace_controls_rejected"]=True
    obj["negative_case_names"]=negative
    (dist/OUTPUT).write_text(json.dumps(obj,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_LIBC_IFUNC105_SEPARATE_NATIVE_ARM64_FEX_SOURCE_GNU_HARDWARE_WRITER_INDEPENDENTLY_CERTIFIED_20_147_NO_CALL_RET_OR_ANDROID")

if __name__=="__main__":
    assert len(sys.argv)==2
    main(Path(sys.argv[1]))
