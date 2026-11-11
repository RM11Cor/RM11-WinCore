#!/usr/bin/env python3
"""SHA-pinned original GNU libc DT_RELA30 source metadata, after certified ledger92.

Read exact ELF relocation and dynamic symbol before choosing a FEX native writer
experiment. This source discovery creates NO hardware proof and NEVER increments 92.
"""
from __future__ import annotations
import hashlib
import json
import sys
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA, LDSO_SHA, decode_original_libc, classify,
)
from kernix_g0_original_dt_rela29_source_type_and_writer_plan_after_91 import original_dynsym
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import LIBC_BIAS, GUEST_MAIN

INDEX = 30
SCHEMA = "kernix.g0.original-gnu-dt-rela30-source-and-symbol-after-certified92.v1"
NAME = "original-libc-DT-RELA30-exact-source-type-symbol-writer-plan-NO-NATIVE-PROOF"
TYPES = {1:"R_X86_64_64", 6:"R_X86_64_GLOB_DAT", 18:"R_X86_64_TPOFF64"}
PREVIOUS = "kernix.g0.original-gnu-libc-147-relocation-cohort-native-writer-ledger92.v1"

def require(ok, label):
    if not ok:
        raise AssertionError("KERNIX_G0_DTRELA30_SOURCE_DISCOVERY_FAIL_CLOSED: "+label)

def load(path, maximum):
    require(path.is_file() and not path.is_symlink(), "original regular input "+str(path))
    b = path.read_bytes()
    require(0 < len(b) <= maximum, "bounded input "+str(path))
    return b

def run(triad:Path, ledger92:Path, repo:Path, output:Path)->dict:
    libc=load(triad/"lib/x86_64-linux-gnu/libc.so.6", 2500000)
    ldso=load(triad/"lib64/ld-linux-x86-64.so.2", 500000)
    require(len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA,
            "original libc exact SHA256")
    require(len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA,
            "original ld.so exact SHA256")
    rows=decode_original_libc(libc)
    require(classify(rows)["original_total_RELA_and_JMPREL"]==147, "147 original GNU source rows")
    row=rows[INDEX]
    require(row["index"]==30 and row["table"]=="DT_RELA" and row["table_index"]==30
            and row["r_type"] in TYPES and row["r_sym"]>0
            and row["r_addend"]==0
            and row["original_source_qword"]=="0x0", "GNU source DT_RELA30 non-IFUNC zero initial")
    target=row["source_guest_target"]
    require(target==hex(LIBC_BIAS+int(row["r_offset"],16)),
            "authentic original ELF writable destination guest target")
    foff=source_offset(libc,int(row["r_offset"],16),8,6,nonexec=True)
    require(libc[foff:foff+8]==bytes(8), "original zero qword from file")
    require(target not in {r["source_guest_target"] for r in rows[:30]},
            "distinct original GNU relocation destination")

    proof=json.loads(load(ledger92,2500000))
    require(proof["schema"]==PREVIOUS
            and proof["source_original_libc_sha256"]==LIBC_SHA
            and proof["source_original_ldso_sha256"]==LDSO_SHA
            and proof["original_relocations_total"]==147
            and proof["previously_independently_attested_native_writer_target_count"]==92
            and proof["remaining_requires_separate_native_hardware_evidence"]==55
            and proof["remaining_non_IFUNC_DT_RELA_indices"]==list(range(30,85))
            and proof["remaining_IFUNC_indices"]==[]
            and proof["native_GNU_DT_RELA29_GLOBDAT_sym655___curbrk_REAL_FEX_ARM64_STORE_independently_proven"] is True
            and proof["full_GLOB_DAT_dynamic_symbol_scope_preemption_and_versioning_proven"] is False
            and proof["all_147_same_guest_native_execution_proven"] is False
            and proof["Android_Bionic_Wine_Proton_games_proven"] is False,
            "certified 92 native targets + 55 pending, no Android or full dynamic scope")
    cert=proof["previously_attested_original_source_indices"]
    require(len(cert)==len(set(cert))==92 and 30 not in cert, "no double count of target30")
    rec=proof["original_147_relocation_source_records"][30]
    require(rec["source_index"]==30
            and rec["source_table"]=="DT_RELA"
            and rec["source_table_ordinal"]==30
            and rec["original_source_guest_target"]==target
            and rec["original_source_file_old_qword"]=="0x0"
            and rec["source_relocation_type"]==TYPES[row["r_type"]],
            "unchanged 147 source-cohort entry index30")
    symbol=original_dynsym(libc,row["r_sym"])
    require(symbol["symbol_index"]==row["r_sym"]
            and symbol["symbol_name"]
            and symbol["runtime_symbol_lookup_or_versioned_preemption_proven"] is False,
            "exact ELF symbol discovered only, not runtime lookup proven")
    host=repo/GUEST_MAIN
    require(host.is_file() and not host.is_symlink(), "original FEX GNU guest host driver")
    markers=[i for i,line in enumerate(host.read_text().splitlines(),1)
             if line.strip()=="++RealOriginalLdsoLibcCloses;"]
    require(len(markers)==1,"unique original FEX driver stop for hardware watchpoint")
    gdb=("set pagination off\nset confirm off\nset breakpoint pending on\n"
         "handle SIGBUS nostop noprint pass\nhandle SIGCHLD nostop noprint pass\n"
         f"break {GUEST_MAIN}:{markers[0]}\n"
         "commands\nsilent\n"
         f'printf "KERNIX_G0_ORIGINAL_RELA30_SOURCE_ARM type={TYPES[row["r_type"]]} target={target} initial=0x0 SOURCE_ONLY=1\\n"\n'
         f"x/gx {target}\n"
         f"watch -location *(unsigned long long *){target}\n"
         "condition 2 $pc >= 0xffff00000000 && $x28 >= 0xffff00000000\n"
         "continue\nend\nrun\n"
         f'printf "KERNIX_G0_ORIGINAL_RELA30_RAW_HIT target={target} pc=0x%lx x4=0x%lx x13=0x%lx x28=0x%lx NOT_CERTIFIED=1\\n",$pc,$x4,$x13,$x28\n'
         f"x/gx {target}\n"
         "x/i $pc-4\n"
         'printf "KERNIX_G0_RELA30_NO_NATIVE_CERTIFICATION_FROM_SOURCE_DISCOVERY=1\\n"\n'
         "quit\n")
    require(gdb.count("watch -location *(unsigned long long *)"+target)==1
            and gdb.count("KERNIX_G0_ORIGINAL_RELA30_SOURCE_ARM")==1
            and gdb.count("KERNIX_G0_ORIGINAL_RELA30_RAW_HIT")==1,
            "bounded index30 GDB source hardware observation only")
    result={
        "schema":SCHEMA,
        "original_source_libc_sha256":LIBC_SHA,
        "original_source_ldso_sha256":LDSO_SHA,
        "original_source_index":30,
        "original_table":"DT_RELA",
        "original_table_ordinal":30,
        "original_relocation_type_id":row["r_type"],
        "original_relocation_type":TYPES[row["r_type"]],
        "original_symbol":symbol,
        "original_source_signed_addend":row["r_addend"],
        "original_source_relocation_offset":row["r_offset"],
        "original_guest_target":target,
        "original_source_initial_qword":"0x0",
        "prior_independently_certified_native_writer_target_count":92,
        "remaining_requires_native_hardware_proof":55,
        "source_only_not_in_prior_certified_target_list":True,
        "new_native_writer_target_evidence_from_this_source_discovery":0,
        "source_only_no_native_writer_proven":True,
        "full_dynamic_symbol_preemption_and_versioning_proven":False,
        "all_147_same_guest_native_execution_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    output.mkdir(parents=True,exist_ok=True)
    (output/(NAME+".json")).write_text(json.dumps(result,indent=2)+"\n")
    (output/(NAME+".gdb")).write_text(gdb)
    print("KERNIX_G0_RELA30_ORIGINAL_GNU_SOURCE_ONLY_UNIQUE_AFTER_92_55_PENDING",
          json.dumps({"index":30,"type":result["original_relocation_type"],
                      "symbol":symbol,"target":target},sort_keys=True))
    return result

if __name__=="__main__":
    require(len(sys.argv)==5,"usage sha-original-triad certified-ledger92 repository-root output-dir")
    run(*map(Path,sys.argv[1:]))
