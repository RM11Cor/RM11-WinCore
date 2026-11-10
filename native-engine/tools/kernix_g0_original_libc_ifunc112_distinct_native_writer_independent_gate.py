#!/usr/bin/env python3
"""Fail closed on authentic original GNU libc IFUNC112 ARM64 FEX HW writer only.

Independent source ELF SHA, original distinct index/target/resolver, prior
source-locked 21st writer proof, genuine AArch64 native hardware WATCH and
x86 GNU writer JIT provenance are mandatory. No CALL/RET or Android proof.
"""
import hashlib,json,re,sys
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import (
    decode_original_libc, classify, LIBC_SHA, LDSO_SHA
)
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_original_libc_ifunc112_source_distinct_hw_watch_plan import (
    PREVIOUS,IFUNC_SOURCE,TYPED,LIBC_BIAS,LDSO_BIAS,STORE
)

INDEX=112
RESOLVER=0x8040b15d0
TARGET=0x804202cf0
OLD=0x282c0
TAG="original-libc-IFUNC112-source-only-distinct-native-write-plan"
LOG="original-libc-IFUNC112-real-FEX-native-HW-WRITE-only.log"
EXIT="original-libc-IFUNC112-real-FEX-native-HW-WRITE-only.exit"
OUTPUT="original-libc-IFUNC112-source-locked-distinct-real-FEX-ARM64-native-HW-WRITE-INDEPENDENT-PROOF.json"

def single(p,raw):
    values=re.findall(p,raw,re.M)
    assert len(values)==1,("expected exactly one original native event",p,len(values))
    return values[0]

def attest(dist:Path,raw_override=None):
    root=dist/"original-source-pinned-root"
    lib=(root/"lib/x86_64-linux-gnu/libc.so.6").read_bytes()
    ld=(root/"lib64/ld-linux-x86-64.so.2").read_bytes()
    assert len(lib)==2118168 and hashlib.sha256(lib).hexdigest()==LIBC_SHA
    assert len(ld)==235408 and hashlib.sha256(ld).hexdigest()==LDSO_SHA
    rows=decode_original_libc(lib)
    assert classify(rows)==json.loads((dist/TYPED).read_text())
    assert len(rows)==147
    r=rows[INDEX]
    assert r["index"]==INDEX and r["table"]=="DT_JMPREL" and r["table_index"]==26
    assert r["r_type"]==37 and r["r_sym"]==0
    assert LIBC_BIAS+r["r_addend"]==RESOLVER
    assert int(r["source_guest_target"],16)==TARGET
    assert int(r["original_source_qword"],16)==OLD
    assert lib[source_offset(lib,RESOLVER-LIBC_BIAS,4,5):][:4]==bytes.fromhex("f30f1efa")
    assert ld[source_offset(ld,STORE-LDSO_BIAS,3,5):][:3]==bytes.fromhex("498906")
    inventory=json.loads((dist/IFUNC_SOURCE).read_text())
    assert inventory["original_IFUNC_source_relocation_count"]==46
    assert inventory["original_distinct_resolver_entry_address_count"]==42
    ifunc=[q for q in rows if q["r_type"]==37]
    aliases=[q["index"] for q in ifunc if q["r_addend"]==r["r_addend"]]
    assert len(ifunc)==46 and aliases==[112]
    prior=json.loads((dist/PREVIOUS).read_text())
    assert prior["source_original_libc_sha256"]==LIBC_SHA
    assert prior["source_original_ldso_sha256"]==LDSO_SHA
    assert prior["original_source_IFUNC_index"]==111
    assert prior["source_original_target"]=="0x804202cf8"
    assert prior["genuine_original_linux_FEX_ARM64_ONE_process_IFUNC111_CALL_resolver_JIT_C3_RET_native_hardware_read_and_writer_proven"] is True
    assert prior["ten_genuine_native_hardware_log_corruptions_independently_rejected"] is True
    assert prior["native_source_original_IFUNC111_distinct_writer_ledger_count"]==26
    assert prior["new_unique_relocation_count_due_to_RET_proof"]==0
    assert prior["all_147_original_libc_RELA_JMPREL_writers_one_process_proven"] is False
    plan=json.loads((dist/(TAG+".json")).read_text())
    assert plan["original_source_libc_sha256"]==LIBC_SHA
    assert plan["original_source_ldso_sha256"]==LDSO_SHA
    assert plan["candidate_source_index"]==INDEX
    assert plan["candidate_source_type"]=="R_X86_64_IRELATIVE"
    assert plan["candidate_original_source_table"]=="DT_JMPREL"
    assert plan["candidate_original_table_index"]==26
    assert plan["original_guest_resolver_entry"]==hex(RESOLVER)
    assert plan["original_guest_target"]==hex(TARGET)
    assert plan["original_target_qword"]==hex(OLD)
    assert plan["original_guest_resolver_source_alias_indices"]==[112]
    assert plan["verified_previous_unique_native_writer_ledger"]==26
    assert plan["source_only_watch_plan_not_runtime_proof"] is True
    assert plan["new_candidate_hardware_writer_genuine_observed"] is False
    assert plan["new_candidate_resolver_CALL_or_RET_native_observed"] is False
    gdb=(dist/(TAG+".gdb")).read_text()
    assert gdb.count("watch -location *(unsigned long long *)0x804202cf0")==1
    assert "rwatch -location" not in gdb and "awatch -location" not in gdb
    assert gdb.count("KERNIX_G0_GENERIC_IFUNC112_NATIVE_HW_TARGET_WRITER_OBSERVED")==1
    assert (dist/EXIT).read_text().strip()=="0"
    raw=(dist/LOG).read_text(errors="replace") if raw_override is None else raw_override
    assert "Error in sourced command file" not in raw and "No registers." not in raw
    markers=[
      "KERNIX_G0_GENERIC_IFUNC112_ORIGINAL_NATIVE_SOURCE_WRITE_WATCH_ARMED ",
      "KERNIX_G0_GENERIC_IFUNC112_NATIVE_HW_TARGET_WRITER_OBSERVED ",
      "KERNIX_G0_GENERIC_IFUNC112_NATIVE_SOURCE_WRITER_JIT ",
      "KERNIX_G0_GENERIC_IFUNC112_NATIVE_WRITE_ONLY_DIAGNOSTIC_DONE_NOT_INDEPENDENTLY_ATTESTED=1"
    ]
    assert all(raw.count(m)==1 for m in markers),[(m,raw.count(m)) for m in markers]
    order=[raw.index(m) for m in markers]
    assert order==sorted(order) and len(set(order))==len(order)
    armed=single(
      r"^KERNIX_G0_GENERIC_IFUNC112_ORIGINAL_NATIVE_SOURCE_WRITE_WATCH_ARMED index=(\d+) "
      r"resolver=(0x[0-9a-fA-F]+) target=(0x[0-9a-fA-F]+) old=(0x[0-9a-fA-F]+) NO_NEW_RUNTIME_PROOF=1$",raw)
    assert (int(armed[0]),int(armed[1],16),int(armed[2],16),int(armed[3],16))==(INDEX,RESOLVER,TARGET,OLD)
    native_watch=re.findall(
      r"^Hardware watchpoint 2: -location \*\(unsigned long long \*\)0x([0-9a-fA-F]+)$",raw,re.M)
    assert len(native_watch)==2 and all(int(v,16)==TARGET for v in native_watch)
    old=int(single(r"^Old value = (0x[0-9a-fA-F]+)$",raw),16)
    new=int(single(r"^New value = (0x[0-9a-fA-F]+)$",raw),16)
    assert old==OLD and new not in (0,OLD)
    assert re.search(r"^0x%x:\s+0x%016x$"%(TARGET,new),raw,re.M)
    v=single(
      r"^KERNIX_G0_GENERIC_IFUNC112_NATIVE_HW_TARGET_WRITER_OBSERVED "
      r"target=(0x[0-9a-fA-F]+) pc=(0x[0-9a-fA-F]+) "
      r"guest_rax_x4=(0x[0-9a-fA-F]+) guest_r14_x19=(0x[0-9a-fA-F]+) "
      r"guest_rsp_x8=(0x[0-9a-fA-F]+) guest_state_x28=(0x[0-9a-fA-F]+) SOURCE_WRITER_ONLY=1$",raw)
    target,pc,rax,r14,rsp,state=[int(q,16) for q in v]
    assert (target,rax,r14)==(TARGET,new,TARGET)
    assert pc>=0xffff00000000 and pc%4==0
    assert 0x803000000<=rsp<0x803010000 and state>=0xffff00000000
    assert re.search(r"^\s*0x%x:\s+stlr\s+x4,\s*\[x19\]\s*$"%(pc-4),raw,re.M)
    w=single(
      r"^KERNIX_G0_GENERIC_IFUNC112_NATIVE_SOURCE_WRITER_JIT "
      r"source_entry=(0x[0-9a-fA-F]+) source_size=(0x[0-9a-fA-F]+) "
      r"native_instruction_count=(\d+) native_after_pc=(0x[0-9a-fA-F]+)$",raw)
    guest,size,count,host=[int(w[0],16),int(w[1],16),int(w[2]),int(w[3],16)]
    assert (guest,size,count,host)==(STORE,3,2,pc)
    srcbyte=ld[source_offset(ld,STORE-LDSO_BIAS,8,5):][:8]
    assert srcbyte[:3]==bytes.fromhex("498906")
    byteprints=re.findall(
      r"^0x%x:\s+((?:0x[0-9a-fA-F]{2}\s+){7}0x[0-9a-fA-F]{2})\s*$"%STORE,raw,re.M)
    assert len(byteprints)==2 and len(set(byteprints))==1
    observed=bytes(int(q,16) for q in re.findall(r"0x[0-9a-fA-F]{2}",byteprints[0]))
    assert observed==srcbyte
    assert re.search(r"^0x%x:\s+0xf3\s+0x0f\s+0x1e\s+0xfa"%RESOLVER,raw,re.M)
    matches=[]
    for label,blob,bias in (("original-libc",lib,LIBC_BIAS),("original-ldso",ld,LDSO_BIAS)):
      try: source_offset(blob,new-bias,1,5)
      except AssertionError: continue
      matches.append(label)
    assert matches==["original-libc"],("new source IFUNC result must be original libc RX",matches,hex(new))
    assert raw.index(markers[0])<raw.index("Old value = ")<raw.index("New value = ")<raw.index(markers[1])<raw.index(markers[2])
    return {
       "schema":"kernix.g0.original-libc-ifunc112-source-locked-real-fex-arm64-native-writer-only-independent.v1",
       "original_source_libc_sha256":LIBC_SHA,
       "original_source_ldso_sha256":LDSO_SHA,
       "original_source_ifunc_index":INDEX,
       "source_original_resolver_guest_RIP":hex(RESOLVER),
       "original_source_target":hex(TARGET),
       "source_original_target_old_qword":hex(OLD),
       "native_hardware_new_source_target_qword":hex(new),
       "genuine_original_x86_GNU_writer_guest_RIP":hex(STORE),
       "genuine_original_x86_GNU_writer_bytes":"498906",
       "real_FEX_native_AArch64_hw_after_store_pc":hex(pc),
       "real_FEX_native_AArch64_store_instruction":"stlr x4, [x19]",
       "new_source_resolver_result_original_libc_RX":True,
       "previous_IFUNC111_FULL_CALL_RET_source_native_independent_proof_present":True,
       "new_unique_original_ifunc112_native_hardware_writer_independently_proven":True,
       "unique_original_libc_native_hardware_writer_target_count":27,
       "original_IFUNC112_resolver_CALL_C3_RET_native_stack_HW_READ_proven":False,
       "remaining_original_libc_IFUNC_hardware_writers_unproven":35,
       "remaining_original_libc_other_RELA_native_writer_unproven":85,
       "all_147_original_libc_RELA_JMPREL_writers_same_process_proven":False,
       "Android_Bionic_Wine_Proton_games_proven":False,
    }

def negatives(dist:Path):
    original=(dist/LOG).read_text(errors="replace")
    changes=[
      ("source_index_forged",r"(KERNIX_G0_GENERIC_IFUNC112_ORIGINAL_NATIVE_SOURCE_WRITE_WATCH_ARMED index=)112",r"\g<1>111"),
      ("source_resolver_forged",r"(KERNIX_G0_GENERIC_IFUNC112_ORIGINAL_NATIVE_SOURCE_WRITE_WATCH_ARMED [^\n]+ resolver=)0x[0-9a-fA-F]+",r"\g<1>0x8040cc270"),
      ("source_target_forged",r"(KERNIX_G0_GENERIC_IFUNC112_ORIGINAL_NATIVE_SOURCE_WRITE_WATCH_ARMED [^\n]+ target=)0x[0-9a-fA-F]+",r"\g<1>0x804202cf8"),
      ("old_hardware_qword_changed",r"^Old value = 0x[0-9a-fA-F]+$","Old value = 0x1"),
      ("new_hardware_qword_changed",r"^New value = 0x[0-9a-fA-F]+$","New value = 0x1"),
      ("native_rax_changed",r"(KERNIX_G0_GENERIC_IFUNC112_NATIVE_HW_TARGET_WRITER_OBSERVED [^\n]+ guest_rax_x4=)0x[0-9a-fA-F]+",r"\g<1>0x1"),
      ("native_target_register_changed",r"(KERNIX_G0_GENERIC_IFUNC112_NATIVE_HW_TARGET_WRITER_OBSERVED [^\n]+ guest_r14_x19=)0x[0-9a-fA-F]+",r"\g<1>0x804202cf8"),
      ("source_gnu_writer_JIT_changed",r"(KERNIX_G0_GENERIC_IFUNC112_NATIVE_SOURCE_WRITER_JIT source_entry=)0x[0-9a-fA-F]+",r"\g<1>0x1"),
      ("hardware_watch_missing",r"^Hardware watchpoint 2: -location \*\(unsigned long long \*\)0x804202cf0$","NO_HARDWARE_WATCH"),
      ("real_native_store_opcode_removed",r"^\s*0x[0-9a-fA-F]+:\s+stlr\s+x4,\s*\[x19\]\s*$","0x0: ldr x4, [x19]"),
    ]
    rejected=[]
    for name,pattern,replacement in changes:
      forged,count=re.subn(pattern,replacement,original,flags=re.M)
      assert count>=1 and forged!=original,(name,count)
      try:attest(dist,raw_override=forged)
      except AssertionError:rejected.append(name)
      else:raise AssertionError("FAIL OPEN: accepted fabricated original IFUNC112 FEX HW source evidence: "+name)
    assert len(rejected)==10
    return rejected

def main(dist:Path):
    proof=attest(dist)
    controls=negatives(dist)
    proof["ten_original_native_hardware_log_corruptions_rejected"]=True
    proof["negative_case_names"]=controls
    (dist/OUTPUT).write_text(json.dumps(proof,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_LIBC_IFUNC112_DISTINCT_GNU_FEX_ARM64_REAL_SOURCE_HARDWARE_WRITER_INDEPENDENT_PASS_NEW_27_OF_147_NO_CALL_RET_OR_ANDROID")

if __name__=="__main__":
    assert len(sys.argv)==2
    main(Path(sys.argv[1]))
