#!/usr/bin/env python3
"""Fail-closed original main ELF RELRO 8 target native x86 vs FEX ARM64 read-only differential.

The native x86 reference includes eight real pre-mprotect qwords. The
independent FEX source GDB job log reports five symbolic values, one PLT
value, and an AGGREGATE pair of RELATIVE expected matches. Never upgrade
this to all 8 source-writer PCs, actual FEX guest mprotect support, or RELRO.
"""
from __future__ import annotations
import copy
import hashlib
import json
import re
import sys
from pathlib import Path

SOURCE_SCHEMA="kernix.g0.source-original-main-8-relro-targets.v1"
NATIVE_SCHEMA="kernix.g0.native-x86-original-main-eight-relro-targets-before-real-mprotect.v1"
LDSO_SHA="cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"
MAIN_SHA="9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412"
FEX_MAIN_BASE=0x800000000
FEX_LIBC_BASE=0x804000000
NAMED_OFFSETS={
 "__libc_start_main":0x3fd8,"_ITM_deregisterTMCloneTable":0x3fe0,
 "__gmon_start__":0x3fe8,"_ITM_registerTMCloneTable":0x3ff0,
 "__cxa_finalize":0x3ff8,"puts":0x3fd0
}
STRONG_VA={"__libc_start_main":0x2a200,"__cxa_finalize":0x472a0,"puts":0x87bc0}
WEAK={"_ITM_deregisterTMCloneTable","__gmon_start__","_ITM_registerTMCloneTable"}

class Refuse(ValueError):pass
def demand(test,msg):
    if not test:raise Refuse(msg)

def capture_markers(log):
    symbol_re=re.compile(
      r"KERNIX_G0_MAIN_RELRO_SOURCE_DYNSYM_SYMBOL index=(\d+) elf_sym=(\d+) binding=(\d+) "
      r"type=6 defined=0 target=([0-9a-f]+) live=([0-9a-f]+) name=([A-Za-z_][A-Za-z_0-9]+) ")
    found={}
    for ix,sym,binding,target,live,name in symbol_re.findall(log):
        item={"index":int(ix),"symbol_index":int(sym),"binding":int(binding),
              "target":int(target,16),"live":int(live,16),"name":name}
        old=found.get(name)
        demand(old is None or old==item,"contradictory true FEX symbolic slot evidence")
        found[name]=item
    demand(set(found)==set(NAMED_OFFSETS)-{"puts"},"FEX five immutable symbolic slot captures incomplete")
    demand(len({v["target"] for v in found.values()})==5,"duplicate FEX observed GOT target")
    for name,item in found.items():
        demand(item["target"]==FEX_MAIN_BASE+NAMED_OFFSETS[name],"FEX source GOT target mismatched")
        demand(item["binding"]==(1 if name=="__libc_start_main" else 2),
               "FEX original symbol binding changed")
        demand(item["live"]==(FEX_LIBC_BASE+STRONG_VA[name] if name in STRONG_VA else 0),
               "source-locked FEX final GLOB_DAT value changed")
    candidates=re.findall(
      r"KERNIX_G0_MAIN_RELRO_DYNAMIC_TARGETS_READONLY_AUDIT "
      r"source_main_rela=(\d+) source_main_plt_rela=(\d+) "
      r"rela_targets_in_main_relro=(\d+) relative_targets=(\d+) "
      r"relative_expected_matches=(\d+) relative_expected_mismatches=(\d+) "
      r"symbolic_targets=(\d+) irelative_targets=(\d+)",log)
    demand(len(candidates)>=1 and all(c==("8","1","7","2","2","0","5","0") for c in candidates),
           "FEX real original main seven RELA plus one JMPREL source inventory or relative summary changed")
    plut=re.findall(
      r"KERNIX_G0_MAIN_PLT_THREE_PHASE_GUEST_EXEC_READONLY symbol=puts "
      r"target=([0-9a-f]+) before_fex=([0-9a-f]+) "
      r"at_libc_relro=([0-9a-f]+) at_main_relro=([0-9a-f]+) "
      r"pre_to_libc_changed=(\d+) libc_to_main_changed=(\d+) "
      r"source_guest_owned=(\d+) main_relro_still_rw=(\d+) "
      r"original_ldso_write_rip_not_traced=(\d+) original_relocation_closure_unproven=(\d+)",log)
    demand(len(plut)>=1,"no genuine FEX original-main puts 3-stage source observation")
    demand(all(p==("800003fd0","1030","1030","804087bc0","0","1","1","1","1","1") for p in plut),
           "FEX source-authentic puts got value or unproven-state changed")
    mprotect=re.findall(
      r"KERNIX_G0_REAL_ORIGINAL_MAIN_PT_GNU_RELRO_AFTER_LIBC_RELRO_NEXT_MPROTECT10_SOURCE_ONLY_PASS "
      r"addr=([0-9a-f]+) len=([0-9a-f]+) prot=(\d+) rights=(\S+) "
      r"NOT_SEALED_NO_FULL_RELOCATION_PROOF",log)
    demand(len(mprotect)>=1 and all(v==("800003000","1000","1","rw-p") for v in mprotect),
           "FEX same first original guest source main RELRO page was not RW and unsealed")
    demand(re.search(
      r"KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL "
      r"num=10 rip=801025db9 rdi=800003000 rsi=1000 rdx=1(?:\s|$)",log) is not None,
      "FEX real original guest syscall10 boundary absent")
    return found

def classify(source,native,log):
    demand(isinstance(source,dict) and source.get("schema")==SOURCE_SCHEMA
           and source.get("main_sha256")==MAIN_SHA,"not original source-attested main eight inventory")
    demand(source.get("source_relro_dynamic_target_count")==8
           and source.get("source_has_2_relative_5_globdat_1_jumpslot") is True
           and source.get("native_real_mprotect_applied") is False
           and source.get("FEX_main_PT_GNU_RELRO_sealed") is False,"original source only intent lost")
    demand(isinstance(native,dict) and native.get("schema")==NATIVE_SCHEMA
           and native.get("source_main_sha256")==MAIN_SHA
           and native.get("source_ldso_sha256")==LDSO_SHA
           and native.get("native_main_exited_cleanly") is True
           and native.get("native_exit_code")==0
           and native.get("gdb_error") is None,"native source reference altered")
    demand(native.get("source_inventory_sha256")==hashlib.sha256(
       json.dumps(source,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
       "native reference not for exact original source")
    main_native=int(native["native_main_guest_base"],16)
    libc_native=int(native["native_libc_guest_base"],16)
    demand(native.get("native_original_main_relro_mprotect_address")==hex(main_native+0x3000)
           and native.get("native_rax_at_linux_mprotect_entry")=="0xffffffffffffffda"
           and native.get("native_mprotect_prot")=="0x1"
           and native.get("main_relro_writable_at_native_mprotect_entry") is True,
           "native true x86 preseal boundary not source matched")
    src=source["dynamic_source_targets"]
    native_values=native["original_main_relro_slot_values_at_native_mprotect_entry"]
    demand(len(src)==len(native_values)==8,"incomplete original main x86 snapshot")
    native_by_offset={int(v["source_target_offset"],16):v for v in native_values}
    demand(len(native_by_offset)==8,"native source target collision")
    source_by_offset={int(v["source_target"],16):v for v in src}
    demand(set(source_by_offset)==set(native_by_offset),"native source main target keys differ")
    fex=capture_markers(log)
    strong_count=0
    for row in native_values:
        offset=int(row["source_target_offset"],16)
        info=source_by_offset[offset]
        demand(row["source_symbol"]==info["source_symbol"]
               and row["source_relocation_type"]==info["type"],"original source symbol/relocation type mismatch")
        val=int(row["native_slot_value"],16)
        if info["type"]==8:
            demand(val==((main_native+info["source_addend"])&((1<<64)-1)),
                   "native relative slot does not match original source addend")
        else:
            name=info["source_symbol"]
            demand(offset==NAMED_OFFSETS[name],"source originally named target changed")
            expected=libc_native+STRONG_VA[name] if name in STRONG_VA else 0
            demand(val==expected,"native original exported/weak symbol pointer changed")
            if name in fex:
                marker=fex[name]
                fex_live=marker["live"]
            else:
                demand(name=="puts","not source FEX PLT entry")
                fex_live=FEX_LIBC_BASE+STRONG_VA["puts"]
            demand(fex_live==(FEX_LIBC_BASE+(val-libc_native) if name not in WEAK else 0),
                   "native-FEX source symbol export byte-offset disagreement")
            strong_count+=1
    demand(strong_count==6,"not all six original libc imports cross-compared")
    return {
        "schema":"kernix.g0.original-main-8-native-x86-vs-FEX-ARM64-source-readonly-value-differential.v1",
        "main_original_sha256":MAIN_SHA,
        "source_main_DT_RELA_total":8,"source_main_DT_JMPREL_total":1,
        "source_main_in_RELRO_eight_targets":8,
        "native_x86_eight_values_match_original_source":True,
        "FEX_arm64_symbolic_GLOB_DAT_source_snapshots_matched":5,
        "FEX_arm64_puts_PLT_source_snapshot_matched":True,
        "native_to_FEX_six_import_values_match_after_libc_load_bias_normalization":True,
        "FEX_arm64_two_RELATIVE_values_match_expected_in_aggregate_only":True,
        "FEX_arm64_individual_two_RELATIVE_qwords_crosscompared":False,
        "FEX_arm64_all_original_main_store_writer_PCs_proven":False,
        "FEX_arm64_original_main_RELRO_RW_at_first_mprotect":True,
        "FEX_arm64_mprotect10_unsupported":True,
        "FEX_arm64_guest_main_RELRO_sealed":False,
        "FEX_arm64_GNU_ldso_self_irelative_executed_proven":False,
        "Android_Bionic_Wine_or_real_PC_games_proven":False,
        "game_memory_failure_causes_not_inferred_from_G0":True}

def negatives(source,native,log):
    cases=[
       ("forged native libc base",lambda s,n,l:n.update(native_libc_guest_base="0x804000000")),
       ("fake native original seal",lambda s,n,l:n.update(main_relro_writable_at_native_mprotect_entry=False)),
       ("forged source ownership",lambda s,n,l:s.update(main_sha256="0"*64)),
       ("drop native put slot",lambda s,n,l:n["original_main_relro_slot_values_at_native_mprotect_entry"].pop(2)),
       ("fake native __libc_start_main target",lambda s,n,l:n["original_main_relro_slot_values_at_native_mprotect_entry"][3].update(native_slot_value="0x1234")),
       ("wrong native relative value",lambda s,n,l:n["original_main_relro_slot_values_at_native_mprotect_entry"][0].update(native_slot_value="0x0")),
       ("false original exit",lambda s,n,l:n.update(native_exit_code=117)),
       ("forged weak slot",lambda s,n,l:n["original_main_relro_slot_values_at_native_mprotect_entry"][4].update(native_slot_value="0xff")),
       ("swapped source symbol",lambda s,n,l:n["original_main_relro_slot_values_at_native_mprotect_entry"][4].update(source_symbol="puts")),
       ("wrong mprotect stage",lambda s,n,l:n.update(native_rax_at_linux_mprotect_entry="0x0")),
       ("fake PLT source metadata",lambda s,n,l:s.update(source_main_plt_rela_count=0)),
       ("fake exact x86 source inventory digest",lambda s,n,l:n.update(source_inventory_sha256="0"*64)),
    ]
    for i,(title,edit) in enumerate(cases,1):
        s=copy.deepcopy(source)
        n=copy.deepcopy(native)
        edit(s,n,log)
        try:classify(s,n,log)
        except (Refuse,KeyError,TypeError,ValueError):
            print("KERNIX_G0_FEX_VS_NATIVE_MAIN_RELRO_FALSE_PROMOTION_%02d_REJECTED %s"%(i,title))
        else:raise Refuse("forged FEX/native main RELRO evidence accepted: "+title)
    return len(cases)

def main(argv):
    if len(argv)!=5 or argv[1] not in ("validate","selftest"):
        print("Usage: compare.py validate|selftest SOURCE_INV_JSON NATIVE_RECEIPT_JSON FEX_FROZEN_JOB_LOG",file=sys.stderr)
        return 2
    source=json.loads(Path(argv[2]).read_text())
    native=json.loads(Path(argv[3]).read_text())
    log=Path(argv[4]).read_text(errors="replace")
    out=classify(source,native,log)
    print(json.dumps(out,sort_keys=True,indent=2))
    if argv[1]=="selftest":
        demand(negatives(source,native,log)==12,"negative proof count mismatch")
    print("KERNIX_G0_MAIN_RELRO_ORIGINAL_8_TARGETS_NATIVE_X86_VS_FEX_ARM64_READONLY_SYMBOLS_MATCH_SOURCE_RELATIVE_AGGREGATE_ONLY_NO_FEX_SEAL")
    return 0

if __name__=="__main__":
    try:raise SystemExit(main(sys.argv))
    except (Refuse,KeyError,TypeError,ValueError) as exc:
        print("KERNIX_G0_NATIVE_X86_FEX_MAIN_RELRO_READONLY_DIFFERENTIAL_FAIL_CLOSED: "+str(exc),file=sys.stderr)
        raise SystemExit(1)
