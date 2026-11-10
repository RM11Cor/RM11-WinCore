#!/usr/bin/env python3
"""Source-locked original GNU libc R_X86_64_64 DT_RELA #0 _res native writer.

Two real Linux AArch64 FEX guest processes, first raw watch and separate
native JIT source watch. This independently proves ONE target qword write,
not comprehensive GNU symbol interposition/version semantics, full loader,
one 147-relocation guest process, Android, Wine or games.
"""
from __future__ import annotations
import hashlib,json,re,sys
from pathlib import Path
from kernix_g0_original_rela0_res_fex_jit_independent_raw_forensics import (
    immutable_source,raw_files,candidate,live_jit_original_bytes,need,TARGET,CANDIDATE,
)

OUT="original-libc-DT-RELA0-R_X86_64_64-_res-real-FEX-ARM64-NATIVE-WRITER-INDEPENDENT-PROOF.json"
GUEST_JIT_ENTRY=0x80100fb8b
X86_GNU_STORE="4c8908" # GNU ld-linux-x86-64 original x86 'mov %r9,(%rax)'
HW="stlr x13, [x4]"

def verified_guest_source_writer(trace:str,libc:bytes,ldso:bytes)->dict:
    receipt=candidate(trace)
    src=live_jit_original_bytes(
        trace,int(receipt["jit_source_guest_entry"],16),
        receipt["jit_source_size"],libc,ldso)
    need(receipt["jit_source_guest_entry"]==hex(GUEST_JIT_ENTRY)
         and receipt["jit_source_size"]==3
         and receipt["jit_native_count"]==2,
         "exact old GNU ldso 3-byte MOV source maps to native two-insn AArch64 JIT")
    need(src["original_gnu_source_binary"]=="original-GNU-ld-linux-x86-64"
         and src["original_sha_pinned_JIT_guest_entry"]==hex(GUEST_JIT_ENTRY)
         and src["source_instruction_length"]==3
         and src["original_x86_source_instruction_hex"]==X86_GNU_STORE
         and src["actual_live_GDB_guest_JIT_byte_prefix_hex"][:6]==X86_GNU_STORE
         and src["original_guest_x86_code_bytes_SHA_verified"] is True,
         "x86 GNU ldso source 4C 89 08 MOV r9 -> qword [rax], not guessed opcode")
    # 4C = REX.W|REX.R, 89 = MOV r/m64,r64, 08 = ModRM
    # 00 mod (memory destination), 001 reg + REX.R => r9, 000 rm => rax.
    bs=bytes.fromhex(src["original_x86_source_instruction_hex"])
    need(bs==b"\x4c\x89\x08" and (bs[2]>>6)==0,
         "actual source instruction is x86 64-bit memory store, not a load")
    need(receipt["native_stlr_pc"].startswith("0xffff"),
         "actual AArch64 executable native store PC")
    need(receipt["native_stored_value"]==CANDIDATE
         and receipt["original_guest_target"]==TARGET
         and receipt["native_store_reg"]=="x13"
         and receipt["native_target_reg"]=="x4",
         "AArch64 x13 symbol value physically written to x4 original guest relocation")
    return {
        "original_source_index":0,
        "original_table":"DT_RELA",
        "original_relocation_type":"R_X86_64_64",
        "original_symbol_name":"_res",
        "original_symbol_index":2726,
        "original_guest_target":TARGET,
        "original_old_qword":"0x0",
        "observed_new_qword":CANDIDATE,
        "source_defined_GNU_BSS_symbol_address":CANDIDATE,
        "original_GNU_x86_loader_store_guest_entry":hex(GUEST_JIT_ENTRY),
        "original_GNU_x86_loader_store_opcode":X86_GNU_STORE,
        "original_GNU_x86_loader_decoded_instruction":"mov qword ptr [rax], r9",
        "real_native_AArch64_store":HW,
        "real_native_AArch64_store_pc":receipt["native_stlr_pc"],
        "real_native_store_source_reg":"x13",
        "real_native_store_target_reg":"x4",
        "real_guest_source_JIT_native_count":2,
        "native_source_hardware_write_independently_attested":True,
        "original_GNU_symbol_interposition_versioning_all_lookups_proven":False,
        "one_guest_all_147_relocation_closure_proven":False,
    }

def negative_controls(trace:str,libc:bytes,ldso:bytes)->list[str]:
    first_qword=TARGET+":\t0x0000000000000000"
    newqword=TARGET+":\t0x000000080420b680"
    hit=re.search(r"^KERNIX_G0_RELA0_RES_JIT_RAW_WATCH target="+TARGET+
                  r" pc=(0x[0-9a-f]+) x4=",trace,re.M)
    need(hit is not None,"negative-control input actual native hardware PC")
    pchit=hit.group(1)
    changes={
        "fake_source_arm":(
            "candidate="+CANDIDATE+" NO_NATIVE_PROOF=1",
            "candidate=0x1 NO_NATIVE_PROOF=1"),
        "wrong_pre_arm_value":(first_qword,TARGET+":\t0x0000000000000001"),
        "missing_hw_event":(
            "Hardware watchpoint 2: -location *(unsigned long long *)"+TARGET,
            "Hardware watchpoint 2: NO_REAL_HARDWARE_WRITE"),
        "wrong_symbol_value":(
            "New value = "+str(int(CANDIDATE,16)),
            "New value = 1"),
        "wrong_original_target":(
            "KERNIX_G0_RELA0_RES_JIT_RAW_WATCH target="+TARGET,
            "KERNIX_G0_RELA0_RES_JIT_RAW_WATCH target=0x1"),
        "fake_native_pc":(" pc="+pchit+" x4="," pc=0x1 x4="),
        "load_instead_of_native_store":("stlr\tx13, [x4]","ldar\tx13, [x4]"),
        "wrong_target_register":(
            "KERNIX_G0_RELA0_NATIVE_REGS x4="+TARGET,
            "KERNIX_G0_RELA0_NATIVE_REGS x4=0x1"),
        "wrong_value_register":(
            " x13="+CANDIDATE+" x28=",
            " x13=0x1 x28="),
        "wrong_original_jit_entry":(
            "FEX_ORIGINAL_SOURCE_JIT guest_entry="+hex(GUEST_JIT_ENTRY),
            "FEX_ORIGINAL_SOURCE_JIT guest_entry=0x1"),
        "wrong_source_code_size":(" source_size=0x3 native_count=",
                                  " source_size=0x4 native_count="),
        "wrong_native_jit_count":(" native_count=2"," native_count=1"),
        "tampered_original_guest_opcode":(
            hex(GUEST_JIT_ENTRY)+":\t0x4c\t0x89\t0x08",
            hex(GUEST_JIT_ENTRY)+":\t0x4c\t0x90\t0x08"),
        "missing_raw_footer":(
            "KERNIX_G0_RELA0_RES_SOURCE_ONLY_NO_NATIVE_ATTESTATION=1",
            "KERNIX_G0_RELA0_RES_SOURCE_ONLY_NO_NATIVE_ATTESTATION=0"),
    }
    need(len(changes)==14,"exact fourteen negative controls")
    rejected=[]
    for label,(old,new) in changes.items():
        need(old in trace and old!=new,"actual real native log mutation premise "+label)
        counterfeit=trace.replace(old,new,1)
        need(counterfeit!=trace,"mutation byte change "+label)
        try: verified_guest_source_writer(counterfeit,libc,ldso)
        except AssertionError: rejected.append(label)
        else: raise AssertionError("FAIL OPEN ACCEPTED FORGED ORIGINAL GNU NATIVE LOG "+label)
    need(len(rejected)==14,"all fourteen original native FEX writer mutations rejected")
    return rejected

def run(triad:Path,src:Path,native:Path,prior:Path,out:Path)->dict:
    gdb,plan,libc,ldso=immutable_source(triad,src,prior)
    first,second,rawmeta,jitmeta=raw_files(native,gdb)
    need(first.count("Hardware watchpoint 2: -location *(unsigned long long *)"+TARGET)==2
         and "Old value = 0" in first
         and "New value = "+str(int(CANDIDATE,16)) in first
         and "stlr\tx13, [x4]" in first,
         "first genuine independent original GNU source qword FEX hardware watch witness")
    cert=verified_guest_source_writer(second,libc,ldso)
    rejected=negative_controls(second,libc,ldso)
    proof={
        "schema":"kernix.g0.original-gnu-rela0-symbolic-64-native-fex-independent-one-writer.v1",
        "original_source_libc_sha256":hashlib.sha256(libc).hexdigest(),
        "original_source_ldso_sha256":hashlib.sha256(ldso).hexdigest(),
        "original_source_indices":[0],
        "prior_independently_certified_native_hardware_target_count":62,
        "new_distinct_original_GNU_native_hardware_writer_targets":1,
        "unique_original_libc_native_hardware_writer_target_count":63,
        "one_original_RELA0_R_X86_64_64_res_native_writer_receipt":cert,
        "fourteen_native_hardware_and_original_JIT_forged_witnesses_rejected":rejected,
        "original_native_first_raw_log_sha256":rawmeta["raw_native_log_sha256"],
        "original_native_second_jit_raw_log_sha256":jitmeta["raw_log_sha256"],
        "two_separate_FEX_guest_processes_hardware_write_observed":True,
        "one_single_FEX_guest_process_for_all_63_writers_proven":False,
        "original_full_symbol_preemption_lookup_and_version_semantics_proven":False,
        "original_DT_RELA0_CALL_RET_stack_HARDWARE_READ_proven":False,
        "all_147_original_libc_RELA_JMPREL_writers_same_process_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    need(len(rejected)==14 and cert["native_source_hardware_write_independently_attested"] is True,
         "only one real original GNU hardware writer and fourteen rejected forgeries")
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(proof,indent=2)+"\n")
    print("KERNIX_G0_REAL_ORIGINAL_GNU_RELA0_RES_ONE_INDEPENDENT_ARM64_FEX_NATIVE_WRITER_63_OF_147_NOT_COMPLETE_LOADER",len(rejected))
    return proof

if __name__=="__main__":
    need(len(sys.argv)==6,"usage triad-root original-source native-raw previous62-ledger new-proven-one-rela0-json")
    run(*map(Path,sys.argv[1:]))
