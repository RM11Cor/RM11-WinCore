#!/usr/bin/env python3
"""KERNIX signed host preview G2-C no-ship APK member firewall.

Must run AFTER Android Gradle signed release and BEFORE uploading it.
Checks real archive member bytes (including renamed files), exact
G2-C guest SHA-256, x86 ELF64 header, forbidden JIT runner markers,
Android native ABI, duplicate paths and symlinks. It does NOT verify
APK signatures, run native code, grant distribution or claim FEX pass.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import zipfile

from kernix_g2c_fixture_gate import FILES

REQUIRED = {
    "lib/arm64-v8a/libFEXCore.so",
    "lib/arm64-v8a/libkernix_g2c_data_only_child.so",
    "classes.dex",
    "AndroidManifest.xml",
}
DENY_NAMES = re.compile(
    r"(?:^|/)(?:kernix-dynamic-app|libc\.so\.6|ld-linux-x86-64\.so\.2|"
    r"libkernix_g2c_android_direct_pie_probe\.so|g2c-fixed-v1)(?:$|/)",
    re.I,
)
FORBIDDEN_GUEST_MARKERS = (
    b"KERNIX_G2C_ANDROID_FEX_DIRECT_PIE_ENTRY_PASS_NOT_GLIBC_V1",
    b"--kernix-g2c-execute-fixed-snapshot-direct-entry-v1",
)
PINNED_GUEST_DIGESTS = {sha for size,sha in FILES.values()}


def fail(reason):
    raise ValueError("KERNIX_G2C_APK_GUEST_RELEASE_FIREWALL_REJECTED: "+reason)


def scan(apk):
    apk=Path(apk)
    if not apk.is_file() or apk.stat().st_size > 200*1024*1024:
        fail("APK archive missing or oversized")
    seen=set()
    count=0
    total=0
    core_hash=None
    page_hash=None
    with zipfile.ZipFile(apk,"r") as archive:
        for info in archive.infolist():
            name=info.filename
            if (name in seen or not name or name.startswith("/") or
                "\\" in name or "//" in name or
                any(part in (".","..") for part in name.split("/"))):
                fail("duplicate/redirected archive entry")
            seen.add(name)
            if DENY_NAMES.search(name):
                fail("G2-C guest or JIT runner leaked by filename: "+name)
            mode=info.external_attr >> 16
            if stat.S_IFMT(mode)==stat.S_IFLNK:
                fail("APK contains symlink")
            if info.is_dir():
                continue
            count+=1
            total+=info.file_size
            if info.file_size>64*1024*1024 or total>300*1024*1024:
                fail("uncompressed archive data unexpectedly large")
            if info.flag_bits & 0x1:
                fail("encrypted APK member")
            with archive.open(info) as stream:
                content=stream.read(64*1024*1024+1)
            if len(content)!=info.file_size:
                fail("truncated or oversized member")
            digest=hashlib.sha256(content).hexdigest()
            if digest in PINNED_GUEST_DIGESTS:
                fail("exact original SHA-pinned G2-C guest ELF shipped under a renamed path")
            if (content[:4]==b"\x7fELF" and len(content)>=20 and
                content[4]==2 and content[5]==1 and content[18:20]==b"\x3e\0"):
                fail("standalone x86_64 ELF found inside host-only APK: "+name)
            if name.startswith("lib/"):
                if not (name.startswith("lib/arm64-v8a/") and name.endswith(".so")
                        and content[:4]==b"\x7fELF" and len(content)>=20
                        and content[18:20]==b"\xb7\0"):
                    fail("non-Android-AArch64 packaged native library")
                if any(marker in content for marker in FORBIDDEN_GUEST_MARKERS):
                    fail("G2-C runtime JIT candidate hidden inside native library")
            if name=="lib/arm64-v8a/libFEXCore.so":
                core_hash=digest
            if name=="lib/arm64-v8a/libkernix_g2c_data_only_child.so":
                page_hash=digest
    if not REQUIRED.issubset(seen) or count<4 or not core_hash or not page_hash:
        fail("missing expected original FEXCore or safe G2-C native child")
    return {
        "schema":"kernix.g2c.signed-apk-native-contents-no-guest.v1",
        "apk_sha256":hashlib.sha256(apk.read_bytes()).hexdigest(),
        "member_count":count,
        "total_uncompressed_bytes":total,
        "fexcore_aarch64_sha256":core_hash,
        "g2c_data_only_aarch64_sha256":page_hash,
        "original_fixed_guest_sha256_not_present":True,
        "standalone_x86_64_elf_not_present":True,
        "native_runtime_candidate_not_present":True,
        "guest_glibc_not_present":True,
        "apk_signature_checked_in_this_gate":False,
        "g2c_dynamic_pie_executed_on_android":False,
        "distribution_approved":False,
        "release_action":"HOST_PREVIEW_DATA_ONLY",
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("apk")
    p.add_argument("output")
    args=p.parse_args()
    result=scan(args.apk)
    dest=Path(args.output)
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("KERNIX_G2C_SIGNED_PREVIEW_APK_FULL_MEMBER_X86_GUEST_JIT_RELEASE_FIREWALL_PASS_NOT_DEVICE")


if __name__=="__main__":
    main()
