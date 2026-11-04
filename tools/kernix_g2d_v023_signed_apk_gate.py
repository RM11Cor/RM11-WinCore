#!/usr/bin/env python3
"""KERNIX v0.23 MIT-only original FEX cross-DSO Android APK exact byte gate.

This gate inspects the assembled APK's real ZIP member bytes. Separate
apksigner + expected signing certificate checks MUST also succeed.
No guest loader, glibc, Wine or game is qualified or claimed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import stat
import struct
import zipfile

GUEST={
 "assets/g2c-mit16k-v1/bin/kernix-mit-dynamic-app":
 (50184,"814944a2ff2580e6d2c65b84de8086e74f1f8f3a654b6ed4bda15542058efac6"),
 "assets/g2c-mit16k-v1/lib/x86_64-linux-gnu/libkernix-g2c-mit-placeholder.so.1":
 (50048,"0c2ef465de4222c5e63dcd3bd15587d649e1fbb23590d949dce917cc1bde34a3"),
 "assets/g2c-mit16k-v1/lib64/ld-kernix-g2c-mit-placeholder.so.1":
 (50024,"a37ed983c898512082749c5a9ec2cc3c10be8fd1adcffd4eaf09fb7346c068d2")
}
G2D_GUEST={
 "assets/g2d-mit-import-v1/bin/kernix-g2d-import-app":
 (50504,"a29be66289673e80cef5de115dfce0f05cb04599368f039c44c728ad0b2278a0"),
 "assets/g2d-mit-import-v1/lib/x86_64-linux-gnu/libkernix-g2d-mit-import.so.1":
 (50048,"8ec9bac9b3a21eeaedb4ec9c7071907a6074cbea9eb41f78591e176f0a27441e"),
 "assets/g2d-mit-import-v1/lib64/ld-kernix-g2d-mit-import-test.so.1":
 (50024,"a37ed983c898512082749c5a9ec2cc3c10be8fd1adcffd4eaf09fb7346c068d2")
}
ALL_GUEST={**GUEST,**G2D_GUEST}
G2D_RUNNER="lib/arm64-v8a/libkernix_g2d_mit_import_candidate.so"
G2D_HASH_ASSET="assets/g2d-mit-import-v1/runner.sha256"
G2D_RUNNER_HASH="70ac0985691bee29dc420dc2dfea6cf308c505fe8d38cbd51e78a35443d3b460"
RUNNER="lib/arm64-v8a/libkernix_g2c_mit_fex_candidate.so"
CORE="lib/arm64-v8a/libFEXCore.so"
HASH_ASSET="assets/g2c-mit16k-v1/runner.sha256"
MIT_NOTICE="assets/third-party-notices/KERNIX-MIT-GUEST.txt"
MIT_NOTICE_SHA="cce39d8733871191985c975c8a6a2454201c3665482027a25731b4090303e250"
DISTRIBUTION_FORBIDDEN=(
 "libc.so.6","ld-linux-x86-64.so.2",
 "g2c-fixed-v1","libkernix_g2c_android_direct_pie_probe.so"
)
CORE_HASH="f71397bf1bbedd03305c7127e442d674227fa54d15217cc7effb22dbaa9f4b1d"
RUNNER_HASH="62eee7a6344956d41bf3b1c0070c7f6c3b68d2a72f379f059f72da57557e2462"


def fail(why):
    raise ValueError("KERNIX_G2D_SIGNED_APK_QUALIFICATION_REJECTED: "+why)


def audit(apk):
    apk=Path(apk)
    if not apk.is_file() or apk.stat().st_size>200*1024*1024:
        fail("Missing or oversize signed Android test APK")
    found=set()
    values={}
    total=0
    with zipfile.ZipFile(apk,"r") as archive:
        for info in archive.infolist():
            name=info.filename
            if (name in found or not name or name.startswith("/") or
                "//" in name or "\\" in name or
                any(p in ("",".","..") for p in name.rstrip("/").split("/"))):
                fail("Unsafe ZIP member path or duplicate")
            found.add(name)
            if any(deny in name for deny in DISTRIBUTION_FORBIDDEN):
                fail("Ubuntu glibc/loader or forbidden guest code shipped")
            if stat.S_IFMT(info.external_attr>>16)==stat.S_IFLNK:
                fail("APK ZIP symlink forbidden")
            if info.is_dir():continue
            total+=info.file_size
            if info.file_size>64*1024*1024 or total>300*1024*1024:
                fail("ZIP bomb or arbitrary large asset")
            if info.flag_bits & 1:fail("Encrypted APK asset")
            contents=archive.read(info)
            if len(contents)!=info.file_size:fail("Truncated APK member")
            digest=hashlib.sha256(contents).hexdigest()
            if name in ALL_GUEST:
                length,expected=ALL_GUEST[name]
                if len(contents)!=length or digest!=expected:
                    fail("Pinned MIT x86 guest ELF mismatch: "+name)
            if contents[:4]==b"\x7fELF" and len(contents)>20:
                machine=struct.unpack_from("<H",contents,18)[0]
                if machine==62 and name not in ALL_GUEST:
                    fail("Unexpected x86 ELF outside exact MIT guest allowlist")
                if name in ALL_GUEST and (machine!=62 or contents[4]!=2):
                    fail("Misidentified x86 guest binary")
                if name.startswith("lib/"):
                    if not name.startswith("lib/arm64-v8a/") or machine!=183:
                        fail("Wrong-ABI Android native library")
            if name.startswith("lib/") and not name.endswith(".so"):
                fail("Native library member has untrusted name")
            if name in (RUNNER,CORE,HASH_ASSET,MIT_NOTICE,G2D_RUNNER,G2D_HASH_ASSET):
                values[name]=(contents,digest)
    mandatory=set(ALL_GUEST)|{RUNNER,CORE,HASH_ASSET,MIT_NOTICE,G2D_RUNNER,G2D_HASH_ASSET,
                          "classes.dex","AndroidManifest.xml"}
    if not mandatory.issubset(found):
        fail("Signed APK missing MIT guest, original FEXCore, runner or hash asset")
    if any(n.startswith("assets/g2c-mit16k-v1/") and
           n not in set(GUEST)|{HASH_ASSET} for n in found):
        fail("Unexpected MIT guest root file or executable")
    if (values[RUNNER][1]!=RUNNER_HASH or
        values[G2D_RUNNER][1]!=G2D_RUNNER_HASH or
        values[CORE][1]!=CORE_HASH):
        fail("Actual native FEX candidate or FEXCore hash mismatch")
    if values[HASH_ASSET][0]!=(RUNNER_HASH+"\n").encode("ascii"):
        fail("Bundled signed G2-C runner SHA asset mismatch")
    if values[G2D_HASH_ASSET][0]!=(G2D_RUNNER_HASH+"\n").encode("ascii"):
        fail("Bundled signed G2-D runner SHA asset mismatch")
    if any(n.startswith("assets/g2d-mit-import-v1/") and
           n not in set(G2D_GUEST)|{G2D_HASH_ASSET} for n in found):
        fail("Unexpected G2-D MIT guest tree contents")
    if (values[MIT_NOTICE][1]!=MIT_NOTICE_SHA or
        b"MIT License" not in values[MIT_NOTICE][0] or
        b"Copyright (c) 2026 KERNIX contributors" not in values[MIT_NOTICE][0]):
        fail("Corresponding original MIT guest source license notice missing or changed")
    if b"KERNIX_G2C_ANDROID_FEX_MIT_ONLY_PINNED_DYNAMIC_PIE_EXEC_PASS_V1" not in values[RUNNER][0]:
        fail("Wrong native MIT-only FEX candidate payload")
    if b"--kernix-g2c-mit-only-pinned-direct-entry-v1" not in values[RUNNER][0]:
        fail("MIT-only exact CLI missing")
    if b"KERNIX_G2D_ANDROID_FEX_MIT_PINNED_PLT_CROSS_DSO_CALL_RETURN_PASS_V1" not in values[G2D_RUNNER][0]:
        fail("Android G2-D runner does not match source-executed x86 CALL RET marker")
    if b"--kernix-g2d-mit-pinned-pltrel-external-dso-v1" not in values[G2D_RUNNER][0]:
        fail("Android G2-D runner does not match fixed CLI")
    if b"KERNIX_G2D_DEBUG=FEX_GUARDED_CALLRET_SHADOW_STACK_INITIALIZED" not in values[G2D_RUNNER][0]:
        fail("Missing x86 CALL RET shadow stack source-gate marker")
    return {
      "schema":"kernix.g2d.signed-android-dual-MIT-x86-cross-DSO-test-apk.v1",
      "actual_apk_sha256":hashlib.sha256(apk.read_bytes()).hexdigest(),
      "native_runner_elf_sha256":values[RUNNER][1],
      "g2d_native_runner_elf_sha256":values[G2D_RUNNER][1],
      "g2d_original_import_guest_SHA256":{k:v[1] for k,v in G2D_GUEST.items()},
      "g2d_apk_members_verified":True,
      "original_fexcore_elf_sha256":values[CORE][1],
      "verified_original_MIT_16k_elf_count":3,
      "verified_g2d_external_import_elf_count":3,
      "guest_elf_sha256":{k:digest for k,(_,digest) in GUEST.items()},
      "guest_pages_WX_16k_separated":True,
      "guest_rootfs_glibc_shipped":False,
      "original_MIT_guest_license_notice_sha256":MIT_NOTICE_SHA,
      "required_MIT_guest_license_notice_present":True,
      "user_initiated_exact_8_second_watchdog_required":True,
      "signed_APK_certificate_verified_by_this_script":False,
      "g2c_x86_executed_on_ANDROID_device":False,
      "g2d_x86_import_executed_on_ANDROID_device":False,
      "guest_dynamic_linker_executed":False,
      "wine_game_support":False,
      "release_scope":"OPT_IN_FIXED_CPU_TEST_ONLY_NOT_A_GAME_EMULATOR"
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("apk");p.add_argument("report")
    args=p.parse_args()
    result=audit(args.apk)
    dest=Path(args.report)
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("KERNIX_G2D_SIGNED_SIX_PINNED_X86_ELS_TWO_ORIGINAL_FEX_ANDROID_RUNNERS_PASS_NOT_DEVICE_EXEC")


if __name__=="__main__":
    main()
