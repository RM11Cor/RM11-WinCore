#!/usr/bin/env python3
"""G2-C exact Ubuntu 2024 x86 glibc + cross-toolchain source receipt (CI only).

Fetches nothing. Caller provides pristine Ubuntu upstream source artifacts.
Checks both .dsc source records, each referenced source tarball's complete
SHA-256 and actual fixed guest provenance receipt. Never packages or runs
glibc, FEX, Windows PE or games; does NOT grant legal redistribution rights.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

GLIBC_DSC = "glibc_2.39-0ubuntu8.dsc"
GLIBC_DSC_SHA256 = "af44b50b4aba75916f920337523d89698c465fafb720268bb87b2555000bea7a"
GLIBC_PATCH = "glibc_2.39-0ubuntu8.debian.tar.xz"
GLIBC_PATCH_SHA256 = "24d8627f34850f05554158b085499d255c67af27be9762d6a911b168852c1dd2"
GLIBC_ORIG = "glibc_2.39.orig.tar.xz"
CROSS_DSC = "cross-toolchain-base_68ubuntu5.dsc"
CROSS_TAR = "cross-toolchain-base_68ubuntu5.tar.xz"
# Ubuntu noble source page publishes MD5, independently from DSC's SHA256.
CROSS_DSC_PUBLISHED_MD5 = "d2fff0de79a9947c8a8128b95a219a38"
CROSS_TAR_PUBLISHED_MD5 = "6f0cce7f01ad0f77de3a6c889f6a30cc"
MAX_DOWNLOADS = {
    GLIBC_DSC: 25000,
    GLIBC_PATCH: 1000000,
    GLIBC_ORIG: 24000000,
    CROSS_DSC: 25000,
    CROSS_TAR: 100000,
}
UBUNTU_BASE_URLS = {
    "glibc": "https://archive.ubuntu.com/ubuntu/pool/main/g/glibc/",
    "cross-toolchain-base": "https://archive.ubuntu.com/ubuntu/pool/main/c/cross-toolchain-base/",
}


def hash_bytes(value, algorithm="sha256"):
    h = hashlib.new(algorithm)
    h.update(value)
    return h.hexdigest()


def require(condition, error):
    if not condition:
        raise ValueError(error)


def obtain(folder, name):
    file = folder / name
    require(file.is_file() and not file.is_symlink(), "Missing or linked upstream source: " + name)
    length = file.stat().st_size
    require(0 < length <= MAX_DOWNLOADS[name], "Unexpected upstream source size: " + name)
    return file.read_bytes()


def parse_dsc(value, expected_source, expected_version):
    # Debian .dsc is an ASCII clear-signed control document; verify exact
    # signed text is structurally consistent, not a cryptographic PGP proof.
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("DSC not valid UTF-8") from exc
    require(text.startswith("-----BEGIN PGP SIGNED MESSAGE-----\n"),
            "DSC missing PGP clearsign envelope")
    body = text.split("\n\n", 1)
    require(len(body) == 2 and "\n-----BEGIN PGP SIGNATURE-----" in body[1],
            "DSC signature envelope missing")
    signed_text = body[1].split("\n-----BEGIN PGP SIGNATURE-----",1)[0]
    def unique(field):
        result = re.findall(r"^"+re.escape(field)+r": (.+)$",signed_text,re.M)
        require(len(result)==1, "DSC field not unique: "+field)
        return result[0].strip()
    require(unique("Source") == expected_source, "DSC source package mismatch")
    require(unique("Version") == expected_version, "DSC source revision mismatch")
    signed = re.search(r"^Checksums-Sha256:\n((?: [^\n]*\n)+)",signed_text,re.M)
    require(signed is not None, "DSC missing SHA256 list")
    checksums = {}
    for line in signed.group(1).strip().splitlines():
        fields = line.strip().split()
        require(len(fields)==3, "Malformed DSC checksum row")
        digest, size, name = fields
        require(re.fullmatch(r"[0-9a-f]{64}",digest) is not None, "Malformed SHA256")
        require(size.isdecimal() and name not in checksums and
                ".." not in name and "/" not in name,
                "DSC size, duplicate or unsafe filename")
        checksums[name] = (int(size),digest)
    return checksums


def audit(artifact_dir, fixture_receipt):
    artifact_dir = Path(artifact_dir)
    glibc_dsc = obtain(artifact_dir,GLIBC_DSC)
    cross_dsc = obtain(artifact_dir,CROSS_DSC)
    require(hash_bytes(glibc_dsc)==GLIBC_DSC_SHA256,
            "Published Ubuntu 2024 glibc DSC SHA256 differs")
    require(hash_bytes(obtain(artifact_dir,GLIBC_PATCH))==GLIBC_PATCH_SHA256,
            "Published Ubuntu 2024 glibc Debian patches SHA256 differs")
    require(hash_bytes(cross_dsc,"md5")==CROSS_DSC_PUBLISHED_MD5,
            "Published cross-toolchain DSC MD5 differs")
    require(hash_bytes(obtain(artifact_dir,CROSS_TAR),"md5")==CROSS_TAR_PUBLISHED_MD5,
            "Published cross-toolchain tar MD5 differs")
    glibc=parse_dsc(glibc_dsc,"glibc","2.39-0ubuntu8")
    cross=parse_dsc(cross_dsc,"cross-toolchain-base","68ubuntu5")
    require(GLIBC_ORIG in glibc and GLIBC_PATCH in glibc,
            "Missing matching 2024 libc source tarballs")
    require(CROSS_TAR in cross and len(cross)==1,
            "Missing or additional cross-toolchain source tar")
    checked={}
    for label,entries,names in [
        ("glibc",glibc,[GLIBC_ORIG,GLIBC_PATCH]),
        ("cross-toolchain-base",cross,[CROSS_TAR])
    ]:
        for name in names:
            contents=obtain(artifact_dir,name)
            size,digest=entries[name]
            require(len(contents)==size and hash_bytes(contents)==digest,
                    "Source SHA256 not matched to .dsc: "+name)
            checked[name]={"sha256":digest,"bytes":size,
                           "source_url":UBUNTU_BASE_URLS[label]+name}
    fixture=json.loads(Path(fixture_receipt).read_text())
    require(fixture.get("schema")=="kernix.g2c.exact-libc-binary-license-review.v1" and
            fixture.get("package")=="libc6-amd64-cross" and
            fixture.get("version")=="2.39-0ubuntu8cross1" and
            fixture.get("source_package")=="cross-toolchain-base" and
            fixture.get("installed_cross_libc_exact_hash_match") is True and
            fixture.get("installed_cross_dynamic_loader_exact_hash_match") is True and
            fixture.get("distribution_approved") is False,
            "Exact guest library provenance not established or distribution flags unsafe")
    return {
        "schema":"kernix.g2c.ubuntu-corresponding-source-2024.v1",
        "ubuntu_binary_package":"libc6-amd64-cross",
        "ubuntu_binary_version":"2.39-0ubuntu8cross1",
        "cross_toolchain_source":"cross-toolchain-base_68ubuntu5",
        "underlying_glibc_source":"glibc_2.39-0ubuntu8",
        "upstream_urls":{
            "glibc":UBUNTU_BASE_URLS["glibc"]+GLIBC_DSC,
            "cross_toolchain_base":UBUNTU_BASE_URLS["cross-toolchain-base"]+CROSS_DSC
        },
        "source_files":checked,
        "exact_guest_libc_and_loader_matched_ubuntu_cross_package":True,
        "dsc_clear_signed_text_digest_checked":True,
        "dsc_pgp_signature_cryptographically_verified":False,
        "corresponding_source_artifacts_accessible":True,
        "source_reproducible_build_proven":False,
        "license_reviewed_for_distribution":False,
        "distribution_approved":False,
        "guest_dynamic_loader_executed_on_android":False,
        "wine_or_windows_game_executed":False,
        "note":"CI-only source receipt; source availability is NOT a complete LGPL compliance review."
    }


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("source_dir")
    parser.add_argument("exact_libc_review")
    parser.add_argument("output_json")
    args=parser.parse_args()
    record=audit(Path(args.source_dir),Path(args.exact_libc_review))
    dest=Path(args.output_json)
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(record,indent=2,sort_keys=True)+"\n")
    print("KERNIX_G2C_UPSTREAM_2024_GLIBC_CORRESPONDING_SOURCE_RECEIPT_PASS_NO_DISTRIBUTION")


if __name__=="__main__":
    main()
