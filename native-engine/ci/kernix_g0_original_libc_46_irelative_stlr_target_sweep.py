#!/usr/bin/env python3
"""Audit all 46 native FEX JIT STLR trap destinations against *original libc* ELF64 R_X86_64_IRELATIVE.

This is source-authentic runtime evidence from a bounded Linux ARM64 diagnostic
process. It is NOT original GNU ldso self-IRELATIVE completion, an all-ELF RELRO
seal, a production Android emulator test, or a per-game memory-root-cause fix.
"""
from __future__ import annotations
import copy
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

LIBC_SHA = "7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906"
LDSO_SHA = "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"
FEX_SHA = "02e24ca5c01ed0c864466ed573db347336f70170"
TRAP_SCHEMA = "kernix.g0.original-ldso-irelative-source-emitted-FEX-ARM64-code-execution-witness.v1"
BASE = 0x804000000
LDSO_ZERO_SLOT = 0x801036360
LIBC_ZERO_SLOT = 0x8042014c8

class Reject(ValueError):
    pass

def require(value: bool, message: str) -> None:
    if not value:
        raise Reject(message)

def original_irelative_slots(libc: bytes) -> tuple[list[int], int]:
    require(len(libc) == 2118168 and hashlib.sha256(libc).hexdigest() == LIBC_SHA,
            "source libc SHA or size mismatch")
    require(libc[:6] == b"\x7fELF\x02\x01", "not little-endian ELF64")
    require(struct.unpack_from("<H", libc, 18)[0] == 62, "not original x86_64 ELF")
    phoff=struct.unpack_from("<Q", libc, 32)[0]
    phsize,phnum=struct.unpack_from("<HH", libc, 54)
    require(phsize==56 and 0<phnum<=64 and phoff+phsize*phnum<=len(libc),
            "invalid original ELF PT_LOAD headers")
    ph=[struct.unpack_from("<IIQQQQQQ",libc,phoff+56*i) for i in range(phnum)]
    def va_to_file(va:int,n:int)->int:
        owner=[v for v in ph if v[0]==1 and v[3]<=va and va+n<=v[3]+v[5]
               and v[2]+v[5]<=len(libc)]
        require(len(owner)==1,"source dynamic relocation not uniquely inside original file-backed PT_LOAD")
        return owner[0][2]+va-owner[0][3]
    dynamic=[v for v in ph if v[0]==2]
    require(len(dynamic)==1, "source ELF PT_DYNAMIC not unique")
    dyn=dynamic[0]
    require(dyn[2]+dyn[5]<=len(libc) and dyn[5]%16==0, "source PT_DYNAMIC invalid")
    tags={}
    for i in range(dyn[5]//16):
        tag,val=struct.unpack_from("<qQ",libc,dyn[2]+16*i)
        if tag==0:break
        require(tag not in (7,8,9,2,20,23) or tag not in tags,
                "duplicate original libc relocation dynamic tag")
        tags[tag]=val
    # The pinned original libc contains *two* independent RELA relocation
    # tables: DT_RELA (86) plus DT_JMPREL (61). Source inventory in
    # kernix_g0_original_libc_147_rela_jmprel_two_boundary_readonly.h
    # enumerates both in that order; 46 IRELATIVE records are the sum.
    # Omitting DT_JMPREL would silently miss genuine source IFUNC rows.
    require(all(k in tags for k in (7,8,9,2,20,23)), "source libc RELA + JMPREL metadata incomplete")
    require(tags[9]==24 and tags[20]==7, "pinned original DT_RELAENT or DT_PLTREL mismatch")
    require(tags[8]==86*24 and tags[2]==61*24,
            "source original 86 DT_RELA and 61 DT_JMPREL record sizes changed")
    tables=[(tags[7],tags[8],0,"DT_RELA"),
            (tags[23],tags[2],86,"DT_JMPREL")]
    require(tags[7]+tags[8]<=tags[23] or tags[23]+tags[2]<=tags[7],
            "source RELA and JMPREL tables unexpectedly overlap")
    entries=[]
    for va,size,base_index,label in tables:
        start=va_to_file(va,size)
        for i in range(size//24):
            offset,info,addend=struct.unpack_from("<QQq",libc,start+i*24)
            if info & 0xffffffff == 37:
                require(info>>32==0 and offset%8==0,
                        "source IRELATIVE not symbol-free or 8-byte aligned in "+label)
                entries.append((base_index+i,BASE+offset,addend))
    require(len(entries)==46,"source libc IRELATIVE count no longer 46")
    require(len({x[1] for x in entries})==46,"duplicate source libc IRELATIVE targets")
    zero=[v for v in entries if v[1]==LIBC_ZERO_SLOT]
    require(len(zero)==1 and zero[0][0]==85 and zero[0][2]==0xc8570,
            "source libc zero IFUNC #85 location or resolver changed")
    return [v[1] for v in entries],zero[0][0]

def classify(w:dict, provenance:dict, libc:bytes)->dict:
    targets,zero_index=original_irelative_slots(libc)
    require(isinstance(w,dict) and w.get("schema")==TRAP_SCHEMA,"not actual source FEX JIT GDB evidence")
    require(isinstance(provenance,dict) and provenance.get("original_fex_commit")==FEX_SHA,
            "original FEX source pin missing")
    require(provenance.get("original_jit_sha_verified_before_diagnostic_instrumentation") is True,
            "source JIT not pinned before CI-only marker")
    require(provenance.get("diagnostic_only_noop_abi_emission_marker_added") is True,
            "missing CI-only original JIT emission marker")
    require(provenance.get("production_FEX_original_source_unchanged") is True,
            "production FEX source mutated")
    require(w.get("source_fex_commit")==FEX_SHA and w.get("source_original_ldso_sha256")==LDSO_SHA,
            "wrong original FEX or GNU loader")
    require(w.get("source_writer_guest_rip")=="0x80100fd60"
            and w.get("source_writer_x86_bytes")=="498906","not original GNU ldso x86 zero writer")
    require(w.get("compiler_native_preprologue_guest_entry_target_proven") is True
            and w.get("source_pinned_FEX_noop_abi_marker_reached_after_code_emission") is True,
            "source-authorized native writer not compiled and emitted")
    require(w.get("native_emitted_code_size")==68,"unexpected original emitted native JIT block size")
    require(w.get("same_emitted_native_STLR_repeat_witness_unfiltered") is True,
            "test did not keep same original writer native hardware breakpoint")
    require(w.get("native_exited") is True and w.get("native_exit_code")==117,
            "diagnostic did not reach intentionally unsupported original mprotect boundary")
    require(w.get("original_guest_mprotect10_unsupported") is True and w.get("debugger_error") is None,
            "unexpected source guest execution errors")
    for k in ("guest_original_irelative_zero_store_executed_proven",
              "guest_original_ldso_irelative_zero_store_executed_proven",
              "guest_original_irelative_resolver_executed_proven",
              "all_three_ELF_relocations_closed","main_PT_GNU_RELRO_sealed",
              "Android_Bionic_or_Wine_game_proven"):
        require(w.get(k) is False,"false original loader, RELRO or Android proof: "+k)
    require(w.get("writer_native_STLR_repeated_execution_count")==46
            and w.get("original_libc_index85_zero_target_store_trap_count")==1
            and w.get("original_ldso_zero_target_store_trap_count")==0,
            "runtime native STLR count or module classification drift")
    emitted=w.get("native_emitted_store_execution_traps")
    require(isinstance(emitted,list) and len(emitted)==47,"expected one native block entry and all 46 native STLR traps")
    require(emitted[0].get("at_emitted_guest_JIT_entry") is True
            and emitted[0].get("at_source_guest_JIT_emitted_STLR") is False,
            "source code block entry not hardware trapped")
    stlr=emitted[1:]
    native_store={v.get("native_store_candidate_pc") for v in w.get("native_emitted_store_candidate_addresses",[])
                  if v.get("insn")=="stlr" and v.get("operands")=="x4, [x19]"}
    require(len(native_store)==1,"unverified native STLR instruction")
    for row in stlr:
        require(row.get("at_source_guest_JIT_emitted_STLR") is True
                and row.get("at_emitted_guest_JIT_entry") is False
                and row.get("native_code_pc") in native_store
                and row.get("original_guest_RIP_source_witness")=="0x80100fd60",
                "native FEX STLR hardware breakpoint absent or source guest RIP wrong")
        require(re.fullmatch(r"0x[0-9a-f]+",str(row.get("target_register",""))),
                "native destination register not collected")
    seen=[int(row["target_register"],16) for row in stlr]
    require(len(seen)==len(set(seen))==46, "duplicate or omitted native FEX original-libc relocation targets")
    require(set(seen)==set(targets),"original FEX native STLR destinations do not match source ELF64 libc R_X86_64_IRELATIVE addresses")
    require(w.get("original_source_STLR_trap_target_addresses")==[hex(x) for x in seen],
            "emitted native JIT event list contradicts separately collected destination register list")
    zero=[row for row in stlr if int(row["target_register"],16)==LIBC_ZERO_SLOT]
    require(len(zero)==1 and zero[0].get("source_register")=="0x0"
            and zero[0].get("target_value_before_store")=="0x0"
            and zero[0].get("native_zero_slot_after_store")=="0x0"
            and zero[0].get("original_guest_module")=="libc.so.6"
            and zero[0].get("original_guest_libc_source_index")==zero_index
            and zero[0].get("source_triad_glibc_index85_zero_to_zero_store_executed") is True,
            "real libc index85 zero-to-zero native step missing")
    require(w.get("guest_original_libc_irelative_index85_zero_to_zero_store_proven") is True
            and w.get("source_original_libc_irelative_index85_target_guest")==hex(LIBC_ZERO_SLOT),
            "glibc index85 real guest zero store identity changed")
    return {
        "schema":"kernix.g0.original-libc-46-ifunc-all-FEX-native-STLR-source-destination-reconciliation.v1",
        "original_libc_sha256":LIBC_SHA,
        "original_ldso_sha256":LDSO_SHA,
        "original_FEX_source_commit":FEX_SHA,
        "source_IRELATIVE_relocations":46,
        "source_IRELATIVE_source_symbol_free_type":37,
        "one_source_original_libc_zero_IFUNC_relocation_index":85,
        "same_diagnostic_FEX_process_native_STLR_execute_traps":len(stlr),
        "exact_source_ELF_relocation_address_set_matches_native_STLR_registers":True,
        "one_real_libc_index85_zero_to_zero_single_step_proven":True,
        "different_original_ldso_irelative_target":hex(LDSO_ZERO_SLOT),
        "original_ldso_irelative_target_among_observed_46_native_STLR_targets":False,
        "original_ldso_irelative_target_guest_store_proven":False,
        "original_ldso_irelative_resolver_guest_execution_proven":False,
        "all_46_correct_IFUNC_return_values_or_individual_store_after_values_proven":False,
        "original_three_ELF_relocation_closure_proven":False,
        "original_main_RELRO_sealed":False,
        "Android_Bionic_Wine_or_games_proven":False,
        "memory_first_failure_root_causes_for_pc_games_proven":False,
    }

def mutations(w:dict,p:dict,libc:bytes)->list[str]:
    cases=[
        ("zero actual STLR traps",lambda x:x.update(writer_native_STLR_repeated_execution_count=0)),
        ("forged GNU ldso write",lambda x:x.update(guest_original_ldso_irelative_zero_store_executed_proven=True)),
        ("forged GNU ldso resolver",lambda x:x.update(guest_original_irelative_resolver_executed_proven=True)),
        ("forged PT_GNU_RELRO",lambda x:x.update(main_PT_GNU_RELRO_sealed=True)),
        ("forged game launch",lambda x:x.update(Android_Bionic_or_Wine_game_proven=True)),
        ("forged 46 target count",lambda x:x.update(original_libc_index85_zero_target_store_trap_count=46)),
        ("forged native first STLR target",lambda x:x["native_emitted_store_execution_traps"][1].update(target_register=hex(LDSO_ZERO_SLOT))),
        ("duplicate source relocation address",lambda x:x["original_source_STLR_trap_target_addresses"].__setitem__(0,x["original_source_STLR_trap_target_addresses"][1])),
        ("native execution boundary removed",lambda x:x.update(native_exited=False)),
        ("unproven native last store",lambda x:x["native_emitted_store_execution_traps"][-1].update(at_source_guest_JIT_emitted_STLR=False)),
        ("original source GNU opcode mismatch",lambda x:x.update(source_writer_x86_bytes="498907")),
    ]
    names=[]
    for label,fn in cases:
        copy_=copy.deepcopy(w)
        fn(copy_)
        try:
            classify(copy_,p,libc)
        except Reject:
            names.append(label)
        else:
            raise Reject("adversarial mutation accepted: "+label)
    provenance=copy.deepcopy(p)
    provenance["diagnostic_only_noop_abi_emission_marker_added"]=False
    try:
        classify(w,provenance,libc)
    except Reject:
        names.append("false CI-only instrumentation provenance")
    else:
        raise Reject("false CI instrumentation provenance accepted")
    require(len(names)==12,"negative control count drift")
    return names

def main(args:list[str])->int:
    if len(args)!=5 or args[1] not in ("validate","selftest"):
        print("Usage: sweep.py validate|selftest EVIDENCE_JSON PROVENANCE_JSON ORIGINAL_LIBC_SO",file=sys.stderr)
        return 2
    w=json.loads(Path(args[2]).read_text())
    p=json.loads(Path(args[3]).read_text())
    libc=Path(args[4]).read_bytes()
    report=classify(w,p,libc)
    print(json.dumps(report,indent=2,sort_keys=True))
    if args[1]=="selftest":
        for i,k in enumerate(mutations(w,p,libc),1):
            print("KERNIX_G0_FEX_LIBC46_ORIGINAL_ELF_STLR_DESTINATION_MUTATION_%02d_REJECTED %s"%(i,k))
    print("KERNIX_G0_ORIGINAL_LIBC46_ELF_SOURCE_IFUNC_TARGETS_MATCH_EVERY_NATIVE_FEX_STLR_TRAP_GNU_LDSO_RELRO_GAMES_STILL_UNPROVEN")
    return 0

if __name__=="__main__":
    try:
        raise SystemExit(main(sys.argv))
    except (Reject,ValueError,KeyError,TypeError,struct.error) as exc:
        print("KERNIX_G0_ORIGINAL_LIBC46_SOURCE_RECONCILIATION_FAIL_CLOSED: "+str(exc),file=sys.stderr)
        raise SystemExit(1)
