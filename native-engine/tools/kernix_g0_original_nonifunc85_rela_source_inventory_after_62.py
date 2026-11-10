#!/usr/bin/env python3
"""Source-only G0 SHA-pinned GNU libc 85 remaining non-IFUNC DT_RELA rows.

After independently certified 62 distinct writer targets, classify the
unaltered original R_X86_64_64, R_X86_64_TPOFF64, R_X86_64_GLOB_DAT source
relocations before designing three distinct writer/code paths. No target is
counted from this inventory.
"""
from __future__ import annotations
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA, LDSO_SHA, classify, decode_original_libc,
)
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset

NAMES = {1:"R_X86_64_64",18:"R_X86_64_TPOFF64",6:"R_X86_64_GLOB_DAT"}
EXPECTED={1:8,18:16,6:61}
FIRST=0
LAST=85


def require(ok:bool, label:str)->None:
    if not ok:
        raise AssertionError("ORIGINAL GNU 85 NON-IFUNC SOURCE FAIL-CLOSED: "+label)


def authenticated_records(triad:Path,certified_ledger62:Path)->tuple[list[dict],dict]:
    lp=triad/"lib/x86_64-linux-gnu/libc.so.6"
    dp=triad/"lib64/ld-linux-x86-64.so.2"
    require(lp.is_file() and dp.is_file() and not lp.is_symlink()
            and not dp.is_symlink(),"real immutable GNU source triad")
    libc,ldso=lp.read_bytes(),dp.read_bytes()
    require(len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA,
            "original x86 GNU libc exact source and SHA")
    require(len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA,
            "original x86 GNU ldso exact source and SHA")
    rows=decode_original_libc(libc)
    orig=classify(rows)
    require(orig["original_total_RELA_and_JMPREL"]==147
            and orig["original_DT_RELA_count"]==86
            and orig["original_DT_JMPREL_count"]==61,
            "all original 147 records exactly pinned")

    require(certified_ledger62.is_file() and not certified_ledger62.is_symlink(),
            "real prior 62-source independent ledger")
    proof=json.loads(certified_ledger62.read_text())
    have=set(proof["previously_attested_original_source_indices"])
    pending=set(proof["remaining_non_IFUNC_DT_RELA_indices"])
    require(proof["schema"]==
            "kernix.g0.original-gnu-libc-147-relocation-cohort-native-writer-ledger62.v1",
            "exact original source ledger62 schema")
    require(proof["previously_independently_attested_native_writer_target_count"]==62
            and proof["remaining_requires_separate_native_hardware_evidence"]==85
            and proof["remaining_IFUNC_indices"]==[]
            and proof["native_IFUNC85_DT_RELA_real_zero_to_zero_FEX_JIT_hardware_STORE_independently_proven"] is True,
            "prior independent 62 and 85 pending")
    require(len(have)==62 and pending==set(range(FIRST,LAST)),
            "the exact 85 remaining source indices are DT_RELA 0..84")
    require(have.isdisjoint(pending) and have|pending==set(range(147)),
            "source source-index distinct coverage without double count")
    require(proof["new_native_hardware_attestations_in_this_source_inventory"]==0
            and proof["all_147_same_guest_native_execution_proven"] is False
            and proof["Android_Bionic_Wine_Proton_games_proven"] is False,
            "source inventory no hardware execution or Android claims")

    cohort=[]
    for i in range(FIRST,LAST):
        row=rows[i]
        require(row["index"]==i and row["table"]=="DT_RELA"
                and row["table_index"]==i and row["r_type"] in EXPECTED,
                "original non-IFUNC DT_RELA exact ordinal/type "+str(i))
        require(row["original_source_qword"]=="0x0", "original nonIFUNC target zero "+str(i))
        guest=int(row["source_guest_target"],16)
        require(guest==0x804000000+int(row["r_offset"],16),
                "original guest target source offset "+str(i))
        where=source_offset(libc,int(row["r_offset"],16),8,6,nonexec=True)
        require(libc[where:where+8]==bytes(8),
                "actual original ELF target zero "+str(i))
        cohort.append({
            "index":i,
            "table":"DT_RELA",
            "table_index":i,
            "type_id":row["r_type"],
            "relocation_type":NAMES[row["r_type"]],
            "symbol_index":row["r_sym"],
            "signed_addend":row["r_addend"],
            "original_offset":row["r_offset"],
            "original_guest_target":row["source_guest_target"],
            "original_target_qword":"0x0",
            "native_original_loader_writer_for_this_index_proven":False,
        })
    return cohort,proof


def validate(cohort:list[dict])->None:
    require(len(cohort)==85 and [x["index"] for x in cohort]==list(range(85)),
            "85 exact consecutive source indices 0..84")
    require(all(x["table"]=="DT_RELA" and x["table_index"]==x["index"]
                and x["type_id"] in EXPECTED and
                x["relocation_type"]==NAMES[x["type_id"]] and
                x["original_target_qword"]=="0x0" and
                x["native_original_loader_writer_for_this_index_proven"] is False
                for x in cohort),
            "types, index, pending writer/oldqword semantics")
    require(Counter(x["type_id"] for x in cohort)==EXPECTED,
            "unaltered original 8 R64 / 16 TPOFF64 / 61 GLOB_DAT source classes")
    require(len({x["original_guest_target"] for x in cohort})==85,
            "85 mutually distinct original source targets")
    require(all(x["original_guest_target"]==
                hex(0x804000000+int(x["original_offset"],16))
                for x in cohort),"original GNU qword offset and guest target binding")


def mutation_tests(cohort:list[dict])->list[str]:
    def copied():
        return [dict(x) for x in cohort]
    mutations={
        "missing_source":lambda x:x.pop(),
        "swapped_source_order":lambda x:x.reverse(),
        "changed_first_type":lambda x:x[0].__setitem__("type_id",37),
        "duplicated_target":lambda x:x[1].__setitem__(
            "original_guest_target",x[0]["original_guest_target"]),
        "changed_zero_qword":lambda x:x[0].__setitem__(
            "original_target_qword","0x1"),
        "premature_native_writer_claim":lambda x:x[0].__setitem__(
            "native_original_loader_writer_for_this_index_proven",True),
    }
    rejected=[]
    for key,mutate in mutations.items():
        rows=copied()
        mutate(rows)
        try:validate(rows)
        except AssertionError:rejected.append(key)
        else:raise AssertionError("ACCEPTED forged source cohort "+key)
    require(len(rejected)==6,"all six source classification negative controls rejected")
    return rejected


def run(triad:Path,ledger:Path,out:Path)->dict:
    cohort,prior=authenticated_records(triad,ledger)
    validate(cohort)
    negatives=mutation_tests(cohort)
    groups={}
    for typ,name in NAMES.items():
        subset=[x for x in cohort if x["type_id"]==typ]
        require(len(subset)==EXPECTED[typ],name+" exact source count")
        groups[name]={
            "source_type_id":typ,
            "source_count":len(subset),
            "original_source_indices":[x["index"] for x in subset],
            "separate_original_x86_loader_writer_semantics_needed":True,
            "individual_FEX_hardware_writer_targets_certified_by_this_plan":0,
        }
    result={
        "schema":"kernix.g0.original-nonifunc85-dtrela-sha-source-after-native-ledger62.v1",
        "original_libc_sha256":LIBC_SHA,
        "original_ldso_sha256":LDSO_SHA,
        "total_original_source_relocations":147,
        "already_independently_attested_native_writer_targets":62,
        "previous_62_source_ledger_anchor":
            "https://github.com/RM11Cor/RM11-WinCore/actions/runs/42864875847",
        "remaining_original_DTRELA_nonIFUNC_count":85,
        "remaining_original_source_indices":list(range(85)),
        "remaining_original_relocation_type_groups":groups,
        "all_85_source_records":cohort,
        "first_next_original_source_index":0,
        "first_next_original_source_type":cohort[0]["relocation_type"],
        "first_next_original_source_target":cohort[0]["original_guest_target"],
        "source_mutations_rejected":negatives,
        "new_native_writer_targets_proven_by_this_source_only_plan":0,
        "any_remaining_nonIFUNC_same_guest_native_writer_proven":False,
        "all_147_same_guest_relocations_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_GNU_LAST_85_SOURCE_TYPES_INVENTORIED_NO_NEW_NATIVE_WRITERS",
          json.dumps({"groups":{k:v["source_count"] for k,v in groups.items()},
                      "first":cohort[0],"keep_independent":62},sort_keys=True))
    return result


if __name__=="__main__":
    require(len(sys.argv)==4,"usage original_source_triad prior_independent_62_ledger output_json")
    run(*map(Path,sys.argv[1:]))
