#!/usr/bin/env python3
"""Original SHA-locked GNU IFUNC85 zero-to-zero STLR independent hardware proof.

A GDB awatch access alone is NEVER a writer. Require real AArch64 STLR x4,[x19],
x4=zero, x19=the original DT_RELA qword, the same guest JIT x86 GNU STORE bytes,
source resolver xor-eax/ret bytes, and reject forged actual run records.
"""
from __future__ import annotations
import hashlib, json, re, sys
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA,LDSO_SHA,decode_original_libc,classify,
)
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset

TARGET="0x8042014c8"
STORE="0x80100fd60"
RESOLVER="0x8040c8570"
ZERO_RET="0x8040c860b"
SOURCE="original-libc-IFUNC85-DT_RELA-zero-source-only-NO-NATIVE-PROOF"
CHAIN="original-libc-IFUNC85-zero-return-source-and-GNU-ldso-call-store-NO-NATIVE.json"
WATCH="original-libc-IFUNC85-DT_RELA-zero-REAL-ARM64-FEX-RAW-DIAGNOSTIC"
ACCESS="original-libc-IFUNC85-DT_RELA-zero-REAL-ARM64-FEX-RAW-ACCESS"
PRIOR="original-libc-IFUNC145-146-two-independent-native-hardware-writer-batch-PROOF.json"
OUT="original-libc-IFUNC85-DT_RELA-zero-to-zero-STLR-one-independent-native-hardware-WRITER-PROOF.json"


def need(ok: bool,why: str)->None:
    if not ok:
        raise AssertionError("IFUNC85 ORIGINAL GNU ZERO VALUE NATIVE WRITER FAIL-CLOSED: "+why)


def loadjson(p:Path)->dict:
    need(p.is_file() and not p.is_symlink(), "normal source JSON "+p.name)
    d=json.loads(p.read_text())
    need(isinstance(d,dict), "JSON object "+p.name)
    return d


def loadtext(p:Path)->str:
    need(p.is_file() and not p.is_symlink(), "normal raw file "+p.name)
    data=p.read_bytes()
    need(250<len(data)<500000, "bounded native raw log "+p.name)
    return data.decode("utf-8",errors="replace")


def authenticated_sources(triad:Path,source:Path,chain:Path,prior:Path,native:Path)->tuple[dict,str]:
    libcpath=triad/"lib/x86_64-linux-gnu/libc.so.6"
    ldsopath=triad/"lib64/ld-linux-x86-64.so.2"
    need(libcpath.is_file() and ldsopath.is_file(), "original GNU ELF source existence")
    libc,ldso=libcpath.read_bytes(),ldsopath.read_bytes()
    need(len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA,
         "exact original x86 libc SHA256")
    need(len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA,
         "exact original x86 ldso SHA256")
    rows=decode_original_libc(libc)
    need(classify(rows)["original_total_RELA_and_JMPREL"]==147,"147 real original ELF source rows")
    r=rows[85]
    need((r["index"],r["table"],r["table_index"],r["r_type"],r["r_sym"])==
         (85,"DT_RELA",85,37,0),"only original DT_RELA index85 R_X86_64_IRELATIVE")
    need(r["source_guest_target"]==TARGET and r["r_offset"]=="0x2014c8"
         and r["r_addend"]==0xc8570 and r["original_source_qword"]=="0x0",
         "original source index85 qword zero resolver/target")
    off=source_offset(libc,0x2014c8,8,6,nonexec=True)
    need(libc[off:off+8]==bytes(8),"real original source zero qword")
    for at,expect in ((0xc8570,"f30f1efa"),(0xc860b,"31c0"),(0xc860d,"c3")):
        raw=bytes.fromhex(expect)
        off=source_offset(libc,at,len(raw),5)
        need(libc[off:off+len(raw)]==raw,"original IFUNC85 resolver/zero-return instruction")
    for guest,expect in ((0x80100fd5a,"ffd0"),(0x80100fd5c,"4883c318"),(0x80100fd60,"498906")):
        raw=bytes.fromhex(expect)
        off=source_offset(ldso,guest-0x801000000,len(raw),5)
        need(ldso[off:off+len(raw)]==raw,"original GNU loader CALL/RET-next/STORE opcode")
    src=loadjson(source/(SOURCE+".json"))
    need(src["original_relocation_index"]==85 and src["original_table"]=="DT_RELA"
         and src["original_guest_target"]==TARGET
         and src["original_guest_resolver"]==RESOLVER
         and src["original_unmodified_target_qword"]=="0x0"
         and src["previously_independently_certified_native_writers"]==61
         and src["new_native_writer_attestations"]==0
         and src["source_only_not_native_hardware_proof"] is True,
         "source-plan specific 85, untouched zero and prior61")
    need(src["original_source_libc_sha256"]==LIBC_SHA
         and src["original_source_ldso_sha256"]==LDSO_SHA,
         "source plan exact ELF SHA parity")
    ch=loadjson(chain/CHAIN)
    need(ch["original_source_libc_sha256"]==LIBC_SHA
         and ch["original_source_ldso_sha256"]==LDSO_SHA,
         "zero-return independently SHA-pinned GNU source proof")
    need(ch["source_index"]==85 and ch["source_table"]=="DT_RELA"
         and ch["original_guest_target"]==TARGET
         and ch["original_guest_resolver"]==RESOLVER
         and ch["original_target_initial_qword"]=="0x0",
         "original source resolver index85 immutable target")
    need(ch["original_x86_zero_return_opcode"]=="31c0"
         and ch["original_x86_ret_opcode"]=="c3"
         and ch["original_x86_GNU_ldso_store_guest_address"]==STORE
         and ch["original_x86_GNU_ldso_store_opcode"]=="498906"
         and ch["original_x86_GNU_ldso_resolver_call_opcode"]=="ffd0",
         "exact original source GNU zero-return and x86 loader STORE instructions")
    need(ch["previous_independently_attested_original_writer_count"]==61
         and ch["new_real_native_writer_attestations"]==0
         and ch["source_GNU_loader_STORE_executed_under_ARM64_FEX_proven"] is False,
         "source chain alone contributed zero native hardware proof")
    p=loadjson(prior/PRIOR)
    need(p["original_source_libc_sha256"]==LIBC_SHA
         and p["original_source_ldso_sha256"]==LDSO_SHA
         and p["original_source_indices"]==[145,146]
         and p["prior_independently_certified_native_hardware_target_count"]==59
         and p["unique_original_libc_native_hardware_writer_target_count"]==61,
         "previous 61 individual real hardware native writer evidence")
    need(len(p["two_independent_native_hardware_writer_receipts"])==2
         and all(x["native_source_hardware_write_independently_attested"] is True
                 for x in p["two_independent_native_hardware_writer_receipts"])
         and sum(map(len,p["twenty_native_hardware_tamper_cases_rejected"].values()))==20,
         "prior 2 original independent native writes 20 forgery controls")
    need(p["all_147_original_libc_RELA_JMPREL_writers_same_process_proven"] is False,
         "never claim original full guest closure")
    gdb=(source/(SOURCE+".gdb")).read_text()
    need(gdb.startswith("set pagination off\nset confirm off\n")
         and gdb.count(f"watch -location *(unsigned long long *){TARGET}")==1
         and "awatch -location" not in gdb,
         "exact untouched source GDB write-only plan")
    need((native/(SOURCE+".gdb")).read_text()==gdb,
         "native archive copied same source plan unchanged")
    need((native/(SOURCE+".json")).read_bytes()==(source/(SOURCE+".json")).read_bytes(),
         "native copied SHA source-only zero target plan exactly")
    need((native/CHAIN).read_bytes()==(chain/CHAIN).read_bytes(),
         "native copied same independent original zero-return/source-store plan")
    return r,gdb


def inspect_raw(log:str)->dict:
    arm=re.search(r"^KERNIX_G0_IFUNC85_DT_RELA_CANDIDATE_PREWATCH target="+
                  re.escape(TARGET)+r" original_zero=1 NOT_NATIVE_PROOF=1$",log,re.MULTILINE)
    need(bool(arm),"live ARM64 genuine original GNU source qword watch was armed")
    access_label="Hardware access (read/write) watchpoint 2: -location *(unsigned long long *)"+TARGET
    first=log.find(access_label)
    need(first>arm.end(),"real AArch64 GDB access watch armed after zero marker")
    zero_text=TARGET+":\t0x0000000000000000"
    z0=log.find(zero_text,arm.end())
    need(arm.end()<z0<first, "native original qword 0 at awatch arm before guest code")
    second=log.find(access_label,first+len(access_label))
    need(second>first and log.count(access_label)==2,
         "second real hardware access event, not only an armed declaration")
    observed=re.search(r"^Value = 0$",log[second:],re.MULTILINE)
    need(bool(observed),"read-or-write hardware trap with still-zero original target")
    m=re.search(r"^KERNIX_G0_IFUNC85_DT_RELA_RAW_UNVERIFIED_ACCESS target="+
                re.escape(TARGET)+
                r" pc=(0x[0-9a-f]+) guest_x4=(0x[0-9a-f]+) x19=(0x[0-9a-f]+) x28=(0x[0-9a-f]+) RAW_NOT_INDEPENDENT=1$",
                log,re.MULTILINE)
    need(bool(m) and m.start()>second,
         "source PC and register snapshot physically after ARM64 hardware access trap")
    pc,x4,x19,x28=(int(s,16) for s in m.groups())
    need(pc>0xffff00000000 and x28>0xffff00000000,
         "real FEX ARM64 JIT native PC and header register")
    need(x4==0 and x19==int(TARGET,16),
         "ARM64 STLR source value zero and physical destination exact original GNU target")
    need(log.find(zero_text,m.end())>m.end(),
         "target is still 0 immediately following actual hardware store")
    stlr=re.search(r"^\s*(0x[0-9a-f]+):\s+stlr\s+x4,\s*\[x19\]\s*$",
                   log[m.end():],re.MULTILINE)
    need(bool(stlr) and int(stlr.group(1),16)==pc-4,
         "native AArch64 actual ZERO STORE opcode stlr x4,[x19] at watch trap PC-4")
    jit=re.search(r"^KERNIX_G0_IFUNC85_DTRELA_SOURCE_GNU_JIT guest_entry=(0x[0-9a-f]+) "
                  r"source_size=(0x[0-9a-f]+) native_count=([0-9]+)$",
                  log[m.end():],re.MULTILINE)
    need(bool(jit),"same FEX guest source JIT header from native x28")
    need(jit.group(1)==STORE and jit.group(2)=="0x3" and jit.group(3)=="2",
         "source JIT guest RIP directly equals original GNU x86 STORE of source size3")
    source_bytes=re.findall(r"^0x80100fd60:\s+0x49\s+0x89\s+0x06$",log,re.MULTILINE)
    need(len(source_bytes)>=2,"JIT guest STORE bytes and direct original GNU source opcode both 49 89 06")
    resolver_ret=re.findall(r"^0x8040c860b:\s+0x31\s+0xc0\s+0xc3$",log,re.MULTILINE)
    need(len(resolver_ret)==1,"same native process mapped original GNU resolver xor-eax RET zero epilogue")
    footer="KERNIX_G0_IFUNC85_DT_RELA_NO_NATIVE_ATTESTATION=1"
    need(log.count(footer)==1 and log.find(footer)>m.end(),
         "raw source diagnostic footer after actual native hardware trace")
    return {
       "original_source_index":85,"original_table":"DT_RELA",
       "original_source_target":TARGET,
       "native_store_pc":hex(pc),"native_source_x4_zero":True,
       "native_write_destination_x19":TARGET,"native_jit_header_x28":hex(x28),
       "native_ARM64_stlr_zero_to_same_zero_independently_verified":True,
       "original_x86_GNU_guest_JIT_STORE_RIP":STORE,
       "same_guest_source_x86_STORE_size":3,"same_guest_source_x86_STORE_native_count":2,
       "original_source_store_opcode_hex":"498906",
       "original_source_resolver_zero_return_xor_eax_ret_hex":"31c0c3",
       "source_was_zero_before_arm_and_after_store":True,
       "GDB_awatch_first_declaration_and_second_physical_event_verified":True,
       "native_guest_CALL_C3_RET_stack_hardware_READ_proven":False,
       "whole_original_147_in_one_guest_proven":False,
    }


def negative_controls(raw:str)->list[str]:
    # Every forged transcript MUST fail real STORE/source-JIT verifier, not mere
    # access-watch marker classification.
    m=re.search(r"RAW_UNVERIFIED_ACCESS target="+re.escape(TARGET)+
                r" pc=(0x[0-9a-f]+) guest_x4=(0x[0-9a-f]+) x19="+
                re.escape(TARGET)+r" x28=(0x[0-9a-f]+)",raw)
    need(bool(m),"real raw register marker available for negative-case generator")
    pc=m.group(1)
    mods=[
      ("wrong_GNU_target",TARGET,"0x804200000"),
      ("missing_zero_arm"," original_zero=1 NOT_NATIVE_PROOF=1"," original_zero=0 NOT_NATIVE_PROOF=1"),
      ("bad_native_pc","pc="+pc,"pc=0x1"),
      ("nonzero_stored_x4","guest_x4=0x0","guest_x4=0x1"),
      ("bad_target_register","x19="+TARGET,"x19=0x1"),
      ("bad_native_header","x28="+m.group(3),"x28=0x1"),
      ("non_writer_ldr","stlr\tx4, [x19]","ldr\tx4, [x19]"),
      ("bad_GNU_source_JIT_RIP","guest_entry="+STORE,"guest_entry=0x801000000"),
      ("bad_GNU_source_size","source_size=0x3","source_size=0x4"),
      ("bad_original_STORE_bytes","0x80100fd60:\t0x49\t0x89\t0x06",
       "0x80100fd60:\t0x00\t0x89\t0x06"),
      ("bad_resolver_ret","0x8040c860b:\t0x31\t0xc0\t0xc3",
       "0x8040c860b:\t0x31\t0xc1\t0xc3"),
      ("remove_access_event","Value = 0","Value = 1"),
    ]
    rejected=[]
    for name,old,new in mods:
        need(old in raw, "negative mutation source exists: "+name)
        fake=raw.replace(old,new,1)
        need(fake!=raw, "negative mutation changed source: "+name)
        try:
            inspect_raw(fake)
        except AssertionError:
            rejected.append(name)
        else:
            raise AssertionError("FORGED ORIGINAL IFUNC85 NATIVE ZERO STORE ACCEPTED: "+name)
    need(len(rejected)==12,"all twelve source/hardware falsifications rejected")
    return rejected


def run(triad:Path,source:Path,chain:Path,native:Path,prior:Path,out:Path)->dict:
    _,orig_gdb=authenticated_sources(triad,source,chain,prior,native)
    stem=native/ACCESS
    need(stem.with_suffix(".log").is_file() and stem.with_suffix(".exit").is_file(),
         "real ARM64 native GDB access logs and process exit")
    raw=loadtext(stem.with_suffix(".log"))
    accessplan=(native/(ACCESS+".gdb")).read_text()
    need(accessplan.startswith(orig_gdb.split("watch -location")[0]),
         "original GDB source prefix matches native awatch guest stage")
    need(accessplan.count("awatch -location *(unsigned long long *)"+TARGET)==1,
         "one exact original GNU target hardware access watchpoint")
    need(accessplan.count("watch -location *(unsigned long long *)"+TARGET)==1,
         "the only occurrence of watch is inside exact awatch, never duplicate")
    need("KERNIX_G0_IFUNC85_DTRELA_SOURCE_GNU_JIT" in accessplan
         and "guest_x4=" in accessplan
         and "x/3bx 0x80100fd60" in accessplan,
         "native diagnostic added same-guest JIT and source resolver bytes")
    diag=loadjson(native/(ACCESS+".json"))
    need(diag["original_source_index"]==85 and diag["original_table"]=="DT_RELA"
         and diag["original_source_target"]==TARGET,
         "raw summary original native source target")
    need(diag["log_sha256"]==hashlib.sha256(raw.encode()).hexdigest(),
         "independent original ARM64 native raw log SHA256")
    need(diag["candidate_gdb_exit_code"]==0
         and int(stem.with_suffix(".exit").read_text())==0,
         "actual FEX GDB exited at zero native store watch event")
    need(diag["original_qword_zero_at_access_watch_arm_observed"] is True
         and diag["native_arm64_hardware_access_watch_trapped"] is True
         and diag["native_hardware_write_independently_attested"] is False
         and diag["original_GNU_native_writer_ledger_unchanged"]==61,
         "raw status never self-claims independent writer proof")
    need(diag["native_x4_zero_and_x19_exact_original_target_raw_candidate"] is True
         and diag["same_guest_original_x86_GNU_STORE_source_JIT_header_observed"] is True
         and diag["two_original_target_zero_qword_samples_arm_and_post_trap"] is True,
         "raw diagnostic contains candidate register/store/JIT markers")
    receipt=inspect_raw(raw)
    denied=negative_controls(raw)
    oldlog=loadtext(native/(WATCH+".log"))
    old=loadjson(native/(WATCH+".json"))
    need(old["original_source_index"]==85
         and old["old_native_writer_ledger_still_valid_count"]==61
         and old["native_hardware_write_independently_attested"] is False,
         "old value-change GDB watch was not a writer witness")
    need(old["candidate_raw_hardware_log_sha256"]==hashlib.sha256(oldlog.encode()).hexdigest(),
         "old watch comparison authentic byte hash")
    need(old["candidate_after_arm_raw_watch_hit_marker_seen"] is False,
         "unchanged 0-to-0 GDB watch does not falsely count writer")
    need("Hardware watchpoint 2: -location *(unsigned long long *)"+TARGET in oldlog,
         "old regular hardware watch really was armed")
    receipt["genuine_native_access_raw_log_sha256"]=hashlib.sha256(raw.encode()).hexdigest()
    receipt["source_x86_GNU_libc_sha256"]=LIBC_SHA
    receipt["source_x86_GNU_ldso_sha256"]=LDSO_SHA
    proof={
        "schema":"kernix.g0.original-gnu-libc-ifunc85-zero-to-zero-stlr-one-independent-FEX-AArch64-hardware-writer.v1",
        "original_source_libc_sha256":LIBC_SHA,
        "original_source_ldso_sha256":LDSO_SHA,
        "original_source_indices":[85],
        "prior_independently_certified_native_hardware_target_count":61,
        "new_distinct_original_GNU_native_hardware_writer_targets":1,
        "unique_original_libc_native_hardware_writer_target_count":62,
        "one_independent_native_hardware_zero_to_zero_writer_receipt":receipt,
        "twelve_native_hardware_tamper_cases_rejected":denied,
        "same_x86_guest_zero_value_real_native_STORE_proven":True,
        "original_IFUNC85_CALL_C3_RET_native_stack_HW_READ_proven":False,
        "all_147_original_libc_RELA_JMPREL_writers_same_process_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    need(len(denied)==12 and proof["unique_original_libc_native_hardware_writer_target_count"]==62,
         "precisely one actual original zero-to-zero hardware writer proof")
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(proof,indent=2)+"\n")
    return proof


if __name__=="__main__":
    need(len(sys.argv)==7,
         "usage triad-root source-watch-dir source-zero-chain-dir genuine-native-raw-dir prior61-proof-dir out.json")
    data=run(*map(Path,sys.argv[1:]))
    print("KERNIX_G0_ORIGINAL_IFUNC85_GENUINE_ZERO_TO_ZERO_ARM64_FEX_HARDWARE_WRITER_INDEPENDENT_62_OF_147",
          data["unique_original_libc_native_hardware_writer_target_count"])
