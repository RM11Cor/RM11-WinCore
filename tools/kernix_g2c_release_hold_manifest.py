#!/usr/bin/env python3
"""G2-C evidence join: bounded, deterministic, CI-only, NEVER a release permit.

Fail closed on mismatched guest bits, license/source receipts, provenance or
inconsistent identities. Does not execute any guest, build an APK or approve
LGPL redistribution. Original FEX runtime admission is a DIFFERENT gate.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

from kernix_g2c_fixture_gate import FILES, SOURCE_SHA, ARCHIVE_SHA

FIXED_BLOB="2e917bded609e3e016fc19d981410cd8d0fcb35d"
LIBC_SHA=FILES["lib/x86_64-linux-gnu/libc.so.6"][1]
LOADER_SHA=FILES["lib64/ld-linux-x86-64.so.2"][1]
GUEST_SHA=FILES["bin/kernix-dynamic-app"][1]
SOURCE_NAMES={"glibc_2.39.orig.tar.xz","glibc_2.39-0ubuntu8.debian.tar.xz",
              "cross-toolchain-base_68ubuntu5.tar.xz"}


def require(condition, reason):
    if not condition:
        raise ValueError("G2C_RELEASE_HOLD_REJECTED: "+reason)


def read_json(file):
    obj=json.loads(Path(file).read_text(encoding="utf-8"))
    require(type(obj) is dict,"Expected JSON object")
    return obj


def hash_bytes(content):
    return hashlib.sha256(content).hexdigest()


def verify(fixture_root, binary_receipt, source_receipt,
           source_witness, mit_notice, ubuntu_notice, lgpl_notice):
    fixture_root=Path(fixture_root)
    provenance=read_json(fixture_root/"PROVENANCE.json")
    manifest=read_json(fixture_root/"manifest.json")
    require(provenance.get("schema")=="kernix.g2c.android-handoff-CI-only.v1" and
            provenance.get("source_sha")==SOURCE_SHA and
            provenance.get("archive_sha256")==ARCHIVE_SHA and
            provenance.get("fex_linux_arm64_pass") is True and
            provenance.get("android_guest_execution_verified") is False and
            provenance.get("android_apk_packaged") is False and
            provenance.get("licenses_reviewed_for_distribution") is False,
            "CI-only guest provenance changed or falsely upgraded")
    require(manifest.get("schema")=="kernix.g2c.android-fixed-guest-inputs.v1" and
            manifest.get("source_git_sha")==SOURCE_SHA and
            manifest.get("android_device_executed") is False and
            manifest.get("guest_dynamic_loader_executed") is False and
            manifest.get("wine_or_games_tested") is False,
            "Guest executable input manifest not original or claims runtime pass")
    require(set(manifest.get("files",{}))==set(FILES) and
            set(manifest.get("extraction_allowlist",[]))==set(FILES) and
            len(manifest.get("extraction_allowlist",[]))==len(FILES),
            "Guest file list mismatch")
    for name,(size,digest) in FILES.items():
        path=fixture_root/name
        require(path.is_file() and not path.is_symlink() and
                path.stat().st_size==size and hash_bytes(path.read_bytes())==digest and
                manifest["files"][name]=={"size":size,"sha256":digest},
                "Guest path/SHA not original: "+name)

    binary=read_json(binary_receipt)
    require(binary.get("schema")=="kernix.g2c.exact-libc-binary-license-review.v1" and
            binary.get("package")=="libc6-amd64-cross" and
            binary.get("version")=="2.39-0ubuntu8cross1" and
            binary.get("source_package")=="cross-toolchain-base" and
            binary.get("installed_cross_libc_exact_hash_match") is True and
            binary.get("installed_cross_dynamic_loader_exact_hash_match") is True and
            binary.get("guest_file_sha256")=={key:digest for key,(size,digest) in FILES.items()},
            "Exact cross-glibc bytes/Ubuntu package receipt differ")
    require(binary.get("license_notice_available") is True and
            binary.get("license_reviewed_for_distribution") is False and
            binary.get("distribution_approved") is False and
            binary.get("fex_guest_executed_on_android") is False,
            "License proof missing or illegally promoted to approved")
    notice=Path(ubuntu_notice).read_bytes()
    require(hash_bytes(notice)==binary.get("upstream_package_copyright_sha256") and
            len(notice)==binary.get("upstream_package_copyright_bytes") and
            b"LGPL" in notice and b"2.1" in notice,
            "Original distro copyright notice unavailable/altered")
    lgpl=Path(lgpl_notice).read_bytes()
    require(len(lgpl)>10000 and
            (b"GNU LESSER GENERAL PUBLIC LICENSE" in lgpl or
             b"GNU LIBRARY GENERAL PUBLIC LICENSE" in lgpl) and
            b"2.1" in lgpl,
            "Full LGPL-2.1 license notice missing")

    source=read_json(source_receipt)
    require(source.get("schema")=="kernix.g2c.ubuntu-corresponding-source-2024.v1" and
            source.get("ubuntu_binary_package")==binary["package"] and
            source.get("ubuntu_binary_version")==binary["version"] and
            source.get("cross_toolchain_source")=="cross-toolchain-base_68ubuntu5" and
            source.get("underlying_glibc_source")=="glibc_2.39-0ubuntu8" and
            source.get("exact_guest_libc_and_loader_matched_ubuntu_cross_package") is True and
            source.get("corresponding_source_artifacts_accessible") is True and
            source.get("dsc_clear_signed_text_digest_checked") is True and
            source.get("dsc_pgp_signature_cryptographically_verified") is False and
            source.get("source_reproducible_build_proven") is False and
            source.get("license_reviewed_for_distribution") is False and
            source.get("distribution_approved") is False and
            source.get("guest_dynamic_loader_executed_on_android") is False and
            source.get("wine_or_windows_game_executed") is False,
            "Source availability receipt mismatch or asserted unsupported approval")
    entries=source.get("source_files",{})
    require(set(entries)==SOURCE_NAMES,"Corresponding source inventory mismatch")
    for name in SOURCE_NAMES:
        value=entries[name]
        require(re.fullmatch("[0-9a-f]{64}",str(value.get("sha256",""))) is not None
                and isinstance(value.get("bytes"),int) and value["bytes"]>1000
                and value.get("source_url","").startswith(
                  "https://archive.ubuntu.com/ubuntu/pool/main/"),
                "Invalid Ubuntu source SHA/size/URL: "+name)

    witness=Path(source_witness).read_bytes()
    sha1=hashlib.sha1(f"blob {len(witness)}\\0".encode()+witness).hexdigest()
    require(sha1==FIXED_BLOB and
            b"SPDX-License-Identifier: MIT" in witness and
            b"0x4b45524e49584732" in witness and
            b"ld-linux" in witness,
            "Compiled x86 witness source changed")
    mit=Path(mit_notice).read_bytes()
    require(len(mit)>500 and b"MIT License" in mit and
            b"Copyright (c) 2026 KERNIX contributors" in mit,
            "Pinned guest witness MIT notice missing")

    # These bytes are a READINESS-REPORT, explicitly NOT a grant to publish.
    return {
        "schema":"kernix.g2c.combined-pre-release-evidence-HOLD.v1",
        "branch":"kernix-native-engine-v1",
        "fixture_linux_fex_original_source_sha":SOURCE_SHA,
        "fixed_guest_source_git_blob":FIXED_BLOB,
        "fixed_guest_elf_sha256":GUEST_SHA,
        "glibc_sha256":LIBC_SHA,
        "ld_linux_sha256":LOADER_SHA,
        "verified_exact_guest_elf_files":4,
        "verified_license_and_source_receipts":True,
        "glibc_binary_package":binary["package"],
        "glibc_binary_version":binary["version"],
        "corresponding_source_tarball_receipts":sorted(SOURCE_NAMES),
        "ubuntu_copyright_sha256":hash_bytes(notice),
        "lgpl_license_sha256":hash_bytes(lgpl),
        "mit_witness_source_sha256":hash_bytes(witness),
        "mit_license_sha256":hash_bytes(mit),
        "legal_redistribution_review_complete":False,
        "redistribution_approved":False,
        "qualifying_signed_fex_runner_sha256":None,
        "fex_candidate_in_apk":False,
        "guest_glibc_or_loader_in_apk":False,
        "g2c_x86_dynamic_pie_executed_on_android":False,
        "guest_ld_linux_executed":False,
        "wine_or_windows_games_executed":False,
        "release_action":"HOLD_NO_APK_NO_GUEST_EXECUTION",
    }


def main():
    p=argparse.ArgumentParser()
    for key in ("fixture","binary_receipt","source_receipt","witness",
                "mit_notice","ubuntu_notice","lgpl_notice","output"):
        p.add_argument(key)
    a=p.parse_args()
    value=verify(a.fixture,a.binary_receipt,a.source_receipt,a.witness,
                 a.mit_notice,a.ubuntu_notice,a.lgpl_notice)
    out=Path(a.output)
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
    print("KERNIX_G2C_EXACT_SOURCE_BINARY_LICENSE_COMBINED_GATE_PASS_RELEASE_STILL_CLOSED")


if __name__=="__main__":
    main()
