#!/usr/bin/env python3
"""Fail-closed actual original GNU libc IFUNC104 native HW WRITE-only witness.

Require original SHA256 GNU guest libc/ldso, prior #103 independently verified
complete same-guest CALL/RET stack READ/STORE (18 unique writers), source-only
independent #104 plan and a genuinely NEW original AArch64 FEX hardware WRITE
watchpoint on #104's own source target. Reject 10 forged live logs.
No #104 resolver CALL/RET; no full libc reloc closure or Android/game claim.
"""
import hashlib,json,re,sys
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import decode_original_libc,LIBC_SHA,LDSO_SHA
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_original_ifunc104_next_unique_source_watch import (
    INDEX,OUT as SOURCE_PLAN,GDB,PRIOR,LIBC_BIAS,LDSO_BIAS,STORE
)
TARGET=0x804202d50
RESOLVER=0x8040b3050
OLD=0x28380
LOG="original-libc-IFUNC104-next-real-FEX-native-HW-WRITE.log"
EXIT="original-libc-IFUNC104-next-real-FEX-native-HW-WRITE.exit"
OUTPUT="original-libc-IFUNC104-original-GNU-real-FEX-ARM64-native-hardware-writer-INDEPENDENT-proof.json"

def unique(p,raw):
    hits=re.findall(p,raw,re.M)
    assert len(hits)==1,("missing/duplicate real native event",p,len(hits))
    return hits[0]

def attest(dist:Path,raw_override=None):
    root=dist/"original-source-pinned-root"
    libc=(root/"lib/x86_64-linux-gnu/libc.so.6").read_bytes()
    ldso=(root/"lib64/ld-linux-x86-64.so.2").read_bytes()
    assert len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA
    assert len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
    row=decode_original_libc(libc)[INDEX]
    assert row["index"]==104 and row["r_type"]==37 and row["r_sym"]==0
    assert row["table"]=="DT_JMPREL" and row["table_index"]==18
    assert LIBC_BIAS+row["r_addend"]==RESOLVER
    assert int(row["source_guest_target"],16)==TARGET and int(row["original_source_qword"],16)==OLD
    assert libc[source_offset(libc,RESOLVER-LIBC_BIAS,4,5):][:4]==bytes.fromhex("f30f1efa")
    assert ldso[source_offset(ldso,STORE-LDSO_BIAS,3,5):][:3]==bytes.fromhex("498906")
    p=json.loads((dist/SOURCE_PLAN).read_text())
    assert p["original_source_libc_sha256"]==LIBC_SHA
    assert p["original_source_ldso_sha256"]==LDSO_SHA
    assert p["source_ifunc_index"]==INDEX and p["source_type"]=="R_X86_64_IRELATIVE"
    assert p["source_original_resolver_guest_RIP"]==hex(RESOLVER)
    assert p["original_unique_guest_target"]==hex(TARGET)
    assert p["original_target_source_qword"]==hex(OLD)
    assert p["original_resolver_alias_source_indices"]==[104]
    assert p["previous_independent_unique_writer_ledger"]==18
    assert p["new_ifunc104_native_hardware_writer_proven"] is False
    assert p["ifunc104_resolver_actual_guest_call_ret_proven"] is False
    gdb=(dist/GDB).read_text()
    assert gdb.count("watch -location *(unsigned long long *)0x804202d50")==1
    assert "rwatch " not in gdb and "awatch " not in gdb
    previous=json.loads((dist/PRIOR).read_text())
    assert previous["source_ifunc_relocation_index"]==103
    assert previous["same_process_original_FEX_CALL_resolver_JIT_exact_C3_RET_stack_HW_READ_caller_and_source_writer_proven"] is True
    assert previous["twelve_actual_native_hardware_evidence_tamper_cases_rejected"] is True
    assert previous["previous_independent_18_unique_writer_targets_unchanged"]==18
    assert previous["all_147_original_libc_relocations_proven"] is False
    assert (dist/EXIT).read_text().strip()=="0"
    raw=(dist/LOG).read_text(errors="replace") if raw_override is None else raw_override
    assert "Error in sourced command file" not in raw and "No registers." not in raw
    markers=[
      "KERNIX_G0_ORIGINAL_IFUNC104_DISTINCT_NATIVE_HW_WATCH_ARMED ",
      "KERNIX_G0_ORIGINAL_IFUNC104_UNVERIFIED_NATIVE_HW_WRITER_DIAGNOSTIC ",
      "KERNIX_G0_ORIGINAL_IFUNC104_UNVERIFIED_NATIVE_GNU_SOURCE_JIT ",
      "KERNIX_G0_ORIGINAL_IFUNC104_DIAGNOSTIC_ENDED_NEW_WRITER_REQUIRES_SEPARATE_INDEPENDENT_PROOF=1",
    ]
    assert all(raw.count(m)==1 for m in markers)
    ps=[raw.index(m) for m in markers]
    assert ps==sorted(ps) and len(set(ps))==len(ps)
    armed=unique(
      r"^KERNIX_G0_ORIGINAL_IFUNC104_DISTINCT_NATIVE_HW_WATCH_ARMED "
      r"index=(\d+) target=(0x[0-9a-fA-F]+) original=(0x[0-9a-fA-F]+) "
      r"resolver=(0x[0-9a-fA-F]+) SOURCE_NOT_EXECUTION$",raw)
    assert (int(armed[0]),int(armed[1],16),int(armed[2],16),int(armed[3],16))==(
       INDEX,TARGET,OLD,RESOLVER)
    hw=re.findall(r"^Hardware watchpoint 2: -location \*\(unsigned long long \*\)0x([0-9a-fA-F]+)$",raw,re.M)
    assert len(hw)==2 and all(int(x,16)==TARGET for x in hw)
    old=int(unique(r"^Old value = (0x[0-9a-fA-F]+)$",raw),16)
    new=int(unique(r"^New value = (0x[0-9a-fA-F]+)$",raw),16)
    assert old==OLD and new!=OLD and new!=0
    assert re.search(r"^0x%x:\s+0x%016x$"%(TARGET,new),raw,re.M)
    stop=unique(
      r"^KERNIX_G0_ORIGINAL_IFUNC104_UNVERIFIED_NATIVE_HW_WRITER_DIAGNOSTIC "
      r"target=(0x[0-9a-fA-F]+) pc=(0x[0-9a-fA-F]+) "
      r"x4=(0x[0-9a-fA-F]+) x19=(0x[0-9a-fA-F]+) "
      r"x8=(0x[0-9a-fA-F]+) x28=(0x[0-9a-fA-F]+)$",raw)
    target,pc,rax,r14,rsp,state=(int(x,16) for x in stop)
    assert (target,rax,r14)==(TARGET,new,TARGET)
    assert pc>=0xffff00000000 and pc%4==0
    assert 0x803000000<=rsp<0x803010000 and state>=0xffff00000000
    assert re.search(r"^\s*0x%x:\s+stlr\s+x4,\s*\[x19\]\s*$"%(pc-4),raw,re.M)
    jit=unique(
      r"^KERNIX_G0_ORIGINAL_IFUNC104_UNVERIFIED_NATIVE_GNU_SOURCE_JIT "
      r"entry=(0x[0-9a-fA-F]+) size=(0x[0-9a-fA-F]+) count=(\d+) pc=(0x[0-9a-fA-F]+)$",raw)
    entry,size,count,hostpc=int(jit[0],16),int(jit[1],16),int(jit[2]),int(jit[3],16)
    assert (entry,size,count,hostpc)==(STORE,3,2,pc)
    byteprints=re.findall(
      r"^0x%x:\s+((?:0x[0-9a-fA-F]{2}\s+){7}0x[0-9a-fA-F]{2})\s*$"%STORE,raw,re.M)
    assert len(byteprints)==2 and len(set(byteprints))==1
    source_bytes=bytes(int(x,16) for x in re.findall(r"0x[0-9a-fA-F]{2}",byteprints[0]))
    assert source_bytes[:3]==bytes.fromhex("498906")
    assert source_bytes==ldso[source_offset(ldso,STORE-LDSO_BIAS,8,5):][:8]
    assert re.search(r"^0x%x:\s+0xf3\s+0x0f\s+0x1e\s+0xfa"%RESOLVER,raw,re.M)
    locations=[]
    for label,source,bias in (("libc",libc,LIBC_BIAS),("ldso",ldso,LDSO_BIAS)):
      try:source_offset(source,new-bias,1,5)
      except AssertionError:continue
      locations.append(label)
    assert locations==["libc"],("original #104 resulting pointer not original SHA-pinned libc RX",locations,hex(new))
    assert raw.index(markers[0])<raw.index("Old value = ")<raw.index("New value = ")<raw.index(markers[1])<raw.index(markers[2])
    return {
      "schema":"kernix.g0.original-libc-ifunc104-distinct-real-linux-AArch64-FEX-hardware-writer-only-independent.v1",
      "original_source_libc_sha256":LIBC_SHA,
      "original_source_ldso_sha256":LDSO_SHA,
      "source_ifunc_relocation_index":INDEX,
      "source_guest_resolver_entry":hex(RESOLVER),
      "source_guest_target":hex(TARGET),
      "original_target_before":hex(OLD),
      "actual_native_hw_after":hex(new),
      "original_x86_GNU_source_writer_RIP":hex(STORE),
      "original_x86_GNU_source_writer_bytes":"498906",
      "native_FEX_AArch64_writer_after_PC":hex(pc),
      "native_FEX_AArch64_actual_opcode":"stlr x4, [x19]",
      "source_result_pointer_in_original_libc_RX":True,
      "previous_IFUNC103_CALL_RET_native_writer_independently_verified":True,
      "IFUNC104_DISTINCT_SOURCE_NATIVE_HARDWARE_WRITER_INDEPENDENTLY_PROVEN":True,
      "unique_individual_original_libc_NATIVE_WRITER_ledger":19,
      "IFUNC104_original_source_guest_CALL_RET_executed_proven":False,
      "remaining_original_IFUNC_individual_writer_count_without_proof":43,
      "remaining_original_non_IFUNC_RELA_without_native_proof":85,
      "all_147_original_libc_relocations_proven":False,
      "Android_Bionic_Wine_Proton_games_proven":False,
    }

def falsify(dist:Path):
    raw=(dist/LOG).read_text(errors="replace")
    controls=[
      ("source_104_to_103_target",r"(KERNIX_G0_ORIGINAL_IFUNC104_DISTINCT_NATIVE_HW_WATCH_ARMED index=104 target=)0x[0-9a-fA-F]+",r"\g<1>0x804202d68"),
      ("source_104_to_103_resolver",r"(KERNIX_G0_ORIGINAL_IFUNC104_DISTINCT_NATIVE_HW_WATCH_ARMED [^\n]+ resolver=)0x[0-9a-fA-F]+",r"\g<1>0x8040b4f90"),
      ("old_native_qword_wrong",r"^Old value = 0x[0-9a-fA-F]+$","Old value = 0x1"),
      ("new_native_qword_wrong",r"^New value = 0x[0-9a-fA-F]+$","New value = 0x1"),
      ("actual_GNU_target_register_wrong",r"(KERNIX_G0_ORIGINAL_IFUNC104_UNVERIFIED_NATIVE_HW_WRITER_DIAGNOSTIC [^\n]+ x19=)0x[0-9a-fA-F]+",r"\g<1>0x804202d68"),
      ("actual_GNU_value_register_wrong",r"(KERNIX_G0_ORIGINAL_IFUNC104_UNVERIFIED_NATIVE_HW_WRITER_DIAGNOSTIC [^\n]+ x4=)0x[0-9a-fA-F]+",r"\g<1>0x1"),
      ("real_source_GNU_JIT_wrong",r"(KERNIX_G0_ORIGINAL_IFUNC104_UNVERIFIED_NATIVE_GNU_SOURCE_JIT entry=)0x[0-9a-fA-F]+",r"\g<1>0x1"),
      ("hardware_watchpoint_missing",r"^Hardware watchpoint 2: -location \*\(unsigned long long \*\)0x804202d50$","MISSING_REAL_WATCH"),
      ("native_STLR_removed",r"^\s*0x[0-9a-fA-F]+:\s+stlr\s+x4,\s*\[x19\]\s*$","0x0: ldr x4, [x19]"),
      ("runtime_writer_event_removed",r"^KERNIX_G0_ORIGINAL_IFUNC104_UNVERIFIED_NATIVE_HW_WRITER_DIAGNOSTIC [^\n]+$","NO_WRITER_EVENT"),
    ]
    rejected=[]
    for name,pattern,replace in controls:
      mutant,count=re.subn(pattern,replace,raw,flags=re.M)
      assert count>=1 and mutant!=raw,(name,count)
      try:attest(dist,raw_override=mutant)
      except AssertionError:rejected.append(name)
      else:raise AssertionError("FAIL-OPEN wrong original GNU native hardware IFUNC104 log "+name)
    assert len(rejected)==10
    return rejected

def main(dist:Path):
    receipt=attest(dist)
    negative=falsify(dist)
    receipt["ten_source_native_evidence_tamper_controls_rejected"]=True
    receipt["negative_names"]=negative
    (dist/OUTPUT).write_text(json.dumps(receipt,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_LIBC_IFUNC104_DISTINCT_SOURCE_GNU_NATIVE_FEX_ARM64_HARDWARE_WRITER_INDEPENDENT_PASS_LEDGER19_NO_CALL_RET_OR_ANDROID")

if __name__=="__main__":
    assert len(sys.argv)==2
    main(Path(sys.argv[1]))
