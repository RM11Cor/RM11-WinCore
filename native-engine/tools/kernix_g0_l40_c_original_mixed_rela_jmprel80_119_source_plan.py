#!/usr/bin/env python3
"""KERNIX original GNU source80..119 G0-L40-C MIXED DT_RELA + DT_JMPREL.

Never assume that the 40 sources are all eagerly written at interpreter
load or have zero old qwords. Original GNU x86-64 libc has 86 DT_RELA:
indices80..84 GLOB_DAT, #85 IRELATIVE; indices86..101 are 16
JUMP_SLOT (nonzero original source PLT qwords); indices102..119 are
18 IRELATIVE (nonzero original JMPREL PLT entries).  Stage C requires
IFUNC resolver calls and genuine lazy/eager PLT binding event evidence.
This is a zero-new-native-evidence source-only stage plan.
"""
from __future__ import annotations
import hashlib,json,sys
from collections import Counter
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA,LDSO_SHA,decode_original_libc,classify,
)
from kernix_g0_original_dt_rela29_source_type_and_writer_plan_after_91 import original_dynsym
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import LIBC_BIAS

SCHEMA="kernix.g0.l40c.original-gnu-authentic-dtrela80-85-jmprel86-119-mixed-40-source-plan.v1"
OUT="KERNIX-G0-L40-C-Original-GNU-Mixed-RELA-JMPREL80-119-40-SHA-Typed-SOURCE-ONLY.json"
INDICES=list(range(80,120))
TYPES={6:"R_X86_64_GLOB_DAT",7:"R_X86_64_JUMP_SLOT",37:"R_X86_64_IRELATIVE"}
RELATIVE_INIT=6
PLT_INIT=34

def need(ok,msg):
    if not ok:raise AssertionError("KERNIX_G0_L40_C_ORIGINAL_MIXED_ELF_SOURCE_FAIL_CLOSED: "+msg)
def read(p:Path,max_bytes=2500000):
    need(p.is_file() and not p.is_symlink(),"actual original GNU input "+str(p))
    v=p.read_bytes()
    need(0<len(v)<=max_bytes,"bounded original GNU SHA input "+str(p))
    return v

def run(triad:Path,canonical:Path,out:Path):
    libc=read(triad/"lib/x86_64-linux-gnu/libc.so.6")
    ldso=read(triad/"lib64/ld-linux-x86-64.so.2",600000)
    need(len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA,
         "exact SHA original 2118168-byte GNU x86_64 libc")
    need(len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA,
         "exact SHA original GNU ld-linux interpreter")
    allrows=decode_original_libc(libc)
    classification=classify(allrows)
    need(classification["original_total_RELA_and_JMPREL"]==147
         and classification["original_DT_RELA_count"]==86
         and classification["original_DT_JMPREL_count"]==61,
         "86 real DT_RELA and 61 real JMPREL originals, not a synthetic table")
    evidence=json.loads(read(canonical))
    need(evidence["schema"]==
          "kernix.g0.original-gnu-libc-147-distinct-source-writer-receipts-specialized-dtrela44-after146.v1"
         and evidence["source_original_libc_sha256"]==LIBC_SHA
         and evidence["source_original_ldso_sha256"]==LDSO_SHA
         and evidence["original_relocations_total"]==147
         and evidence["previously_attested_original_source_indices"]==list(range(147))
         and evidence["previously_independently_attested_native_writer_target_count"]==147
         and evidence["all_147_same_guest_native_execution_proven"] is False,
         "prior 147 individual real native writers do not establish stage C one process")
    prior=evidence["original_147_relocation_source_records"]
    need(len(prior)==147,"exact 147 previous original individual source rows")
    rows=[]
    for idx in INDICES:
        r=allrows[idx]
        table="DT_RELA" if idx<86 else "DT_JMPREL"
        ordinal=idx if idx<86 else idx-86
        typ=6 if idx<85 else (37 if idx==85 or idx>=102 else 7)
        initial=r["original_source_qword"]
        need(r["index"]==idx and r["table"]==table
             and r["table_index"]==ordinal and r["r_type"]==typ
             and r["source_guest_target"]==hex(LIBC_BIAS+int(r["r_offset"],16))
             and (initial=="0x0" if idx<86 else int(initial,16)!=0),
             "true original GNU mixed RELA/JMPREL source tuple and file initial qword "+str(idx))
        proven=prior[idx]
        need(proven["source_index"]==idx and proven["source_table"]==table
             and proven["source_table_ordinal"]==ordinal
             and proven["source_relocation_type"]==TYPES[typ]
             and proven["original_source_guest_target"]==r["source_guest_target"]
             and proven["original_source_file_old_qword"]==initial,
             "true independently certified original 147 index source metadata parity "+str(idx))
        sym=original_dynsym(libc,r["r_sym"]) if r["r_sym"] else None
        need((sym is None if typ==37 else sym is not None
              and sym["symbol_index"]==r["r_sym"]),
             "true original dynsym zero for IRELATIVE, real symbol for others")
        behavior=(
            "eager_original_GLOB_DAT_direct_native_store"
            if typ==6 else
            "ELF_IFUNC_resolver_invocation_then_native_slot_update_require_dynamic_CPU_GNU_evidence"
            if typ==37 else
            "JUMP_SLOT_may_remain_original_nonzero_PLT_until_actual_call_or_BindNow"
        )
        rows.append({
            "index":idx,
            "original_table":table,"original_table_ordinal":ordinal,
            "relocation_type":TYPES[typ],"relocation_type_number":typ,
            "symbol_index":r["r_sym"],
            "symbol_name":sym["symbol_name"] if sym else None,
            "symbol_source_defined_candidate_if_non_TLS":(
                sym["source_definition_address_candidate_if_non_TLS"] if sym else None),
            "signed_addend":r["r_addend"],
            "original_guest_target":r["source_guest_target"],
            "original_source_file_qword":initial,
            "original_source_qword_zero":initial=="0x0",
            "binding_event_required":behavior,
            "native_process_writer_observed_this_plan":False,
            "original_IFUNC_resolver_executed_this_plan":False,
            "true_dynamic_loader_symbol_scope_proven_this_plan":False,
        })
    need(len(rows)==40 and len({x["original_guest_target"] for x in rows})==40
         and [x["index"] for x in rows]==INDICES,
         "40 unique SHA original mixed DT_RELA and DT_JMPREL source target indices")
    types=dict(sorted(Counter(x["relocation_type"] for x in rows).items()))
    tables=dict(sorted(Counter(x["original_table"] for x in rows).items()))
    need(types=={"R_X86_64_GLOB_DAT":5,"R_X86_64_IRELATIVE":19,"R_X86_64_JUMP_SLOT":16}
         and tables=={"DT_JMPREL":34,"DT_RELA":6},
         "5 true GLOB_DAT, 19 native IFUNC IRELATIVE, 16 JUMP_SLOT original GNU ELF")
    require_resolver=[x["index"] for x in rows if x["relocation_type"]=="R_X86_64_IRELATIVE"]
    require_lazy=[x["index"] for x in rows if x["relocation_type"]=="R_X86_64_JUMP_SLOT"]
    need(require_resolver==[85]+list(range(102,120)),
         "one DT_RELA IRELATIVE 85 and eighteen DT_JMPREL native original IFUNC 102..119")
    need(require_lazy==list(range(86,102)),
         "sixteen authentic original GNU JUMP_SLOT source indices")
    windows=[]
    for n in range(10):
        group=rows[4*n:4*n+4]
        windows.append({
            "window_number":n+1,
            "original_indices":[r["index"] for r in group],
            "original_tables":[r["original_table"] for r in group],
            "exact_original_source_old_qwords":[r["original_source_file_qword"] for r in group],
            "maximum_simultaneous_native_ARM64_watchpoints":4,
            "independent_genuine_store_or_resolver_trace_required":True,
            "same_guest_original_GNU_native_process_pid_required":True,
            "all_targets_in_window_proven":False,
        })
    out.mkdir(parents=True,exist_ok=True)
    d={
       "schema":SCHEMA,
       "original_source_libc_sha256":LIBC_SHA,
       "original_source_ldso_sha256":LDSO_SHA,
       "original_147_source_writer_targets_already_individually_proven":147,
       "stage":"G0-L40-C",
       "original_source_indices":INDICES,
       "real_original_source_type_counts":types,
       "real_original_table_counts":tables,
       "six_initially_zero_DT_RELA_source_indices":list(range(80,86)),
       "thirtyfour_initially_nonzero_JMPREL_source_indices":list(range(86,120)),
       "true_IFUNC_IRELATIVE_indices_require_actual_resolver_proof":require_resolver,
       "true_JUMP_SLOT_indices_require_genuine_binding_trigger":require_lazy,
       "all_forty_source_records":rows,
       "ten_groups_of_four_original_source_watches":windows,
       "real_one_FEX_inferior_process_required":True,
       "GNU_loader_lazy_versus_eager_PLT_binding_must_be_validated":True,
       "original_IFUNC_return_zero_must_not_be_rejected_without_abi_check":True,
       "new_same_guest_native_writers_proven":0,
       "stage_C_same_guest_40_original_writers_proven":False,
       "all_147_same_guest_native_execution_proven":False,
       "full_147_original_loader_relocation_closure_proven":False,
       "Android_Bionic_Wine_Proton_games_proven":False
    }
    (out/OUT).write_text(json.dumps(d,indent=2)+"\n")
    print("KERNIX_G0_L40_C_AUTHENTIC_GNU_SOURCE_40_TYPED_MIXED_RELA_JMPREL_SHA_PASS",types,tables,
          "SOURCE_ONLY_NO_NEW_NATIVE_EVIDENCE",flush=True)
    return d

if __name__=="__main__":
    need(len(sys.argv)==4,
         "usage original_immutable_GNU_libc_ldso_guest_triad canonical147_individual_writer_ledger output")
    run(*map(Path,sys.argv[1:]))
