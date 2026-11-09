#!/usr/bin/env python3
"""LAST original libc JUMP_SLOT #101 source-only hardware watch plan.

Every previous actual writer #86..100 has certified original SHA-pinned
ARM64 FEX hardware evidence. This source stage alone proves NO new write.
"""
import hashlib
import json
from pathlib import Path
import sys
from kernix_g0_libc_rela_source_inventory_gate import make_inventory
from kernix_g0_original_libc_relocation_type_transition_gate import classify, decode_original_libc

LIBC_SHA="7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906"
LDSO_SHA="cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"
OLD_SCRIPT="original-libc-fifth-symbolic-jmprel-native-write-watch-plan.gdb"
PLAN="original-libc-last-jumpslot-101-source-watch-plan.json"
GDB="original-libc-last-jumpslot-101-real-native-write-watch.gdb"
PREV="original-libc-symbolic-jmprel-97-100-same-native-guest-verified.json"


def prepare(dist:Path):
    root=dist/"original-source-pinned-root"
    lp=root/"lib/x86_64-linux-gnu/libc.so.6"
    dp=root/"lib64/ld-linux-x86-64.so.2"
    assert lp.is_file() and not lp.is_symlink()
    assert dp.is_file() and not dp.is_symlink()
    libc,ldso=lp.read_bytes(),dp.read_bytes()
    assert len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA
    assert len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
    inv=make_inventory(libc)
    assert inv==json.loads((dist/"original-libc-147-rela-jmprel-source-inventory.json").read_text())
    typed=classify(decode_original_libc(libc))
    assert typed==json.loads((dist/"original-libc-147-rela-jmprel-typed-source-next-stage-plan.json").read_text())
    assert typed["genuine_source_JUMP_SLOT_indices"]==list(range(86,102))
    assert typed["individually_real_hardware_attested_JUMP_SLOT_before_last"]==15
    assert typed["last_JUMP_SLOT_live_FEX_hardware_writer_proven"] is False
    assert typed["last_unproven_source_JUMP_SLOT"]=={
        "index":101,"symbol":19,"guest_target":"0x804202d70","original_qword":"0x283c0"}
    assert typed["original_source_IRELATIVE_count"]==46
    assert typed["original_other_RELA_count"]==85

    proven=json.loads((dist/PREV).read_text())
    assert proven["libc_sha256"]==LIBC_SHA and proven["ldso_sha256"]==LDSO_SHA
    assert proven["four_individual_real_native_hardware_writes_in_ONE_FEX_guest_proven"] is True
    assert proven["indices"]==[97,98,99,100]
    assert proven["source_original_writer_indices_prior"]==list(range(86,97))
    assert proven["total_individually_real_native_attested_original_libc_JMPREL"]==15
    assert proven["twelve_actual_same_process_hw_batch_log_mutations_rejected"] is True
    assert len(proven["negative_case_names"])==12
    assert [w["after_real_hardware_write_qword"] for w in proven["writers"]]==[
        "0x801015c20","0x801001480","0x8010142e0","0x8010042f0"]
    assert all(w["original_source_result_ELF_RX"]=="ld-linux" for w in proven["writers"])
    assert proven["one_process_full_147_relocation_closure_proven"] is False
    row=inv["next_source_candidates"][14]
    assert row["index"]==101 and row["table"]=="DT_JMPREL"
    assert row["r_type"]==7 and row["r_sym"]==19
    assert row["source_guest_target"]=="0x804202d70" and row["source_qword"]=="0x283c0"
    assert int(row["r_offset"],16)+0x804000000==int(row["source_guest_target"],16)
    assert [r["index"] for r in inv["next_source_candidates"]]==list(range(87,102))
    # No accidental selection of #102+ IRELATIVE/IFUNC.
    assert 102 not in inv["next_source_candidate_indices"]

    prior=(dist/OLD_SCRIPT).read_text()
    assert prior.count("index=90 target=0x804202c48 original=0x28170")==1
    assert prior.count("watch -location *(unsigned long long *)0x804202c48")==1
    assert prior.count("x/gx 0x804202c48")==2
    assert "awatch" not in prior and "NOT_YET_SOURCE_ATTESTED=1" in prior
    script=prior.replace("0x804202c48","0x804202d70")
    script=script.replace("index=90 ","index=101 ")
    script=script.replace("original=0x28170 ","original=0x283c0 ")
    assert script.count("index=101 target=0x804202d70 original=0x283c0")==1
    assert script.count("watch -location *(unsigned long long *)0x804202d70")==1
    assert script.count("x/gx 0x804202d70")==2
    assert "0x804202c48" not in script and "index=90 " not in script
    assert "awatch" not in script
    (dist/GDB).write_text(script)
    receipt={
        "schema":"kernix.g0.last-original-libc-JUMP_SLOT-101-source-only-watch.v1",
        "source_libc_sha256":LIBC_SHA,
        "source_ldso_sha256":LDSO_SHA,
        "prior_real_FEX_native_JUMP_SLOT_writer_indices":list(range(86,101)),
        "last_source_index":101,
        "last_source_r_type":7,
        "last_source_symbol":19,
        "last_source_guest_target":"0x804202d70",
        "last_source_qword":"0x283c0",
        "native_watchpoint_mode":"write-only",
        "hardware_watchpoints_armed_in_this_stage":False,
        "last_source_writer_real_native_hardware_proven":False,
        "all_16_original_JUMP_SLOT_writers_proven":False,
        "all_46_original_IFUNC_resolver_paths_proven":False,
        "remaining_85_other_RELA_writer_semantics_proven":False,
        "one_process_147_relocations_closed":False,
        "Android_Bionic_Wine_Proton_games_proven":False
    }
    (dist/PLAN).write_text(json.dumps(receipt,indent=2)+"\n")
    print("KERNIX_G0_LAST_ONE_ORIGINAL_JUMP_SLOT_101_NATIVE_HW_WATCH_SOURCE_ONLY_PREPARED_NOT_EXECUTED")


if __name__=="__main__":
    assert len(sys.argv)==2
    prepare(Path(sys.argv[1]))
