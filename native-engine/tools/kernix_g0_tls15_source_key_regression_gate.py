#!/usr/bin/env python3
"""Source-only guard against corrupting earlier certified TLS relocation keys.

This does not execute FEX or certify a new native writer; it protects the
real-arm64 run, independent proof and conditional ledger from copy/edit errors.
"""
from pathlib import Path
import sys

ROOT_FILES = {
    "raw": "native-engine/tools/kernix_g0_original_dtrela15_tls_tpoff64_fex_native_raw_probe.sh",
    "gate": "native-engine/tools/kernix_g0_original_rela15_tpoff64_tls_native_independent_gate.py",
    "ledger": "native-engine/tools/kernix_g0_original_libc_147_ledger78_after_rela15_tls.py",
    "independent_workflow": ".github/workflows/kernix-g0-original-rela15-tpoff64-tls-native-independent.yml",
    "ledger_workflow": ".github/workflows/kernix-g0-original-libc-147-source-ledger78-cohorts.yml",
}

OLD_KEYS = (
    "native_GNU_DT_RELA3_TLS_TPOFF64_sym0_addend88_REAL_FEX_ARM64_STORE_independently_proven",
    "native_GNU_DT_RELA5_TLS_TPOFF64_sym0_addend80_REAL_FEX_ARM64_STORE_independently_proven",
)

def require(ok, why):
    if not ok:
        raise AssertionError("KERNIX_G0_TLS15_STATIC_SOURCE_KEY_FAIL_CLOSED: " + why)

def audit(pieces):
    for name in ("raw", "gate", "ledger"):
        data = pieces[name]
        for key in OLD_KEYS:
            require(data.count(key) == 1, name + " must preserve actual earlier TLS ledger key " + key)
        require("addend328" not in data and "addend320" not in data,
                name + " corrupted earlier TLS addend key detected")
    require("(15,'DT_RELA',15,18,0,'0x202fe0',32,'0x0')" in pieces["raw"],
            "source-only raw program must bind exact immutable RELA15 GNU relocation tuple")
    require("assert r['source_guest_target']=='0x804202fe0'" in pieces["raw"]
            and pieces["raw"].count("0x804202fe0") == 4,
            "source-only raw must preserve all four real original guest target bindings")
    require("(15,\"DT_RELA\",15,18,0,\"0x202fe0\",32,TGT,\"0x0\")" in pieces["gate"],
            "independent gate must bind actual original GNU source relocation")
    require("(15, \"DT_RELA\", 15, 18, 0, \"0x202fe0\", 32, \"0x804202fe0\", \"0x0\")" in pieces["ledger"],
            "ledger must bind actual original GNU source index/offset/addend/guest target")
    require('NEW="0xffffffffffffff98"' in pieces["gate"],
            "independent gate must verify native -104 rather than inferred/stale old TLS value")
    require('"observed_native_writer_qword"] == "0xffffffffffffff98"' in pieces["ledger"],
            "ledger must verify actual -104 native written qword")
    require('run-id: 42989954318' in pieces["independent_workflow"],
            "independent gate must fetch the fixed ARM64 FEX raw run, not an earlier failed run")
    require('run-id: 42990003246' in pieces["ledger_workflow"],
            "ledger must fetch the fixed TLS15 independent run")
    require("one_original_GNU_RELA15_TLS_TPOFF64_native_writer_receipt" in pieces["gate"],
            "native proof must require exact original source receipt")
    require("sixteen_fake_original_TLS_native_hardware_traces_rejected" in pieces["gate"],
            "native proof must retain independent rejection of 16 forged hardware traces")
    require("Android_Bionic_Wine_Proton_games_proven" in pieces["ledger"],
            "do not erase original explicit Android game proof limitations")

def main(root):
    files = {}
    for label, rel in ROOT_FILES.items():
        p = root / rel
        require(p.is_file() and not p.is_symlink(), "missing or symlink " + rel)
        files[label] = p.read_text()
    audit(files)
    attacks = [
        ("mutate earlier addend88", "raw", OLD_KEYS[0], OLD_KEYS[0].replace("addend88", "addend328")),
        ("mutate earlier addend80", "raw", OLD_KEYS[1], OLD_KEYS[1].replace("addend80", "addend320")),
        ("mutate original target", "raw", "0x804202fe0", "0x804202ff0"),
        ("mutate independent expected native value", "gate", 'NEW="0xffffffffffffff98"', 'NEW="0xffffffffffffff80"'),
        ("mutate pinned raw run", "independent_workflow", "run-id: 42989954318", "run-id: 42988713758"),
        ("mutate pinned independent proof", "ledger_workflow", "run-id: 42990003246", "run-id: 42988789805"),
    ]
    for desc, label, old, new in attacks:
        require(old in files[label], "negative test fixture exists: " + desc)
        changed = dict(files)
        changed[label] = changed[label].replace(old, new, 1)
        try:
            audit(changed)
        except AssertionError:
            pass
        else:
            raise AssertionError("KERNIX_G0_TLS15_STATIC_SOURCE_KEY_UNDETECTED_FORGERY: " + desc)
    print("KERNIX_G0_TLS15_SOURCE_KEY_BINDING_PASS_SIX_NEGATIVE_CONTROLS_NO_NATIVE_PROOF")

if __name__ == "__main__":
    require(len(sys.argv) == 2, "usage repository-root")
    main(Path(sys.argv[1]))
