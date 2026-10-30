#!/usr/bin/env python3
"""Stage ONLY a source-pinned rebuilt Bionic Winebus Unix DLL for APK assets.

Verifies the *actual signed legacy winebus.so / PE pair* against byte pins,
then the *actual source-built ARM64 ELF* and provenance inside a downloaded
GitHub Actions archive. Does not replace the Android imagefs during build.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import zipfile

SOURCE_PIN="256288853b206373cbf65b775143d33bb11035dd"
LEGACY_ELF_SHA="cca5501a884e504e1e414960ac69742938ecc4ba4a6a7e2685d818eb713f9f60"
LEGACY_PE_SHA="a571101b6eec5ed5ac75de34828990d46e22d8aab4a85d24696494db30a85061"
NEW_ELF_SHA="42e9fefde6d579f76e734181fbcac7289cce7c71c5ef63374f49fb71f5d0aabe"
BUILT_RUN=41063689320
ASSET_NAME="rm11-native-hid-winebus.so"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def verify_elf(buf):
    if len(buf)<65536 or len(buf)>16*1024*1024:
        raise ValueError("RM11_WINEBUS_ELF_UNEXPECTED_SIZE")
    if buf[:4]!=b"\x7fELF" or buf[4]!=2 or buf[5]!=1:
        raise ValueError("RM11_WINEBUS_ELF64_LITTLE_ENDIAN_REQUIRED")
    if struct.unpack_from("<H",buf,18)[0]!=183:
        raise ValueError("RM11_WINEBUS_NOT_AARCH64")
    for mark in (b"RM11_NATIVE_HID_BUS",b"RM11_WINE_NATIVE_HID="):
        if mark not in buf:
            raise ValueError("RM11_WINEBUS_NATIVE_HID_MARKER_ABSENT:"+str(mark))


def tar_member(archive:Path, member:str,max_bytes=20*1024*1024):
    if not member.startswith("./") or ".." in member.split("/"):
        raise ValueError("UNSAFE_TAR_MEMBER_REQUEST")
    p=subprocess.run(["tar","-I","zstd","-xOf",str(archive),member],
                     stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
    if p.returncode or len(p.stdout)>max_bytes:
        raise ValueError("PINNED_WINE_TAR_MEMBER_FAILURE:"+member+":"
                         +p.stderr.decode(errors="replace")[:1000])
    return p.stdout


def stage(legacy:Path,rebuilt:Path,asset:Path,manifest:Path):
    with zipfile.ZipFile(legacy) as root:
        for name,want in (
            ("lib/wine/aarch64-unix/winebus.so",LEGACY_ELF_SHA),
            ("lib/wine/aarch64-windows/winebus.sys",LEGACY_PE_SHA),
        ):
            data=root.read(name)
            if sha256(data)!=want:
                raise ValueError("RM11_LEGACY_WINEBUS_NOT_SOURCE_PINNED:"+name)
    native=tar_member(rebuilt,"./lib/wine/aarch64-unix/winebus.so")
    verify_elf(native)
    if sha256(native)!=NEW_ELF_SHA:
        raise ValueError("RM11_WINEBUS_BINARY_NOT_FROM_VERIFIED_RUN")
    source=tar_member(rebuilt,"./WINE-SOURCE.txt",4096).decode()
    if SOURCE_PIN not in source or "The412Banner/proton-wine" not in source:
        raise ValueError("RM11_WINE_SOURCE_PIN_UNVERIFIED")
    proof=json.loads(tar_member(rebuilt,
        "./source-info/RM11-HID-SOURCE-ABI.json",8192))
    if proof.get("source_pin")!=SOURCE_PIN or proof.get("wine_pe_driver_untouched") is not True:
        raise ValueError("RM11_NATIVE_HID_PE_ABI_CHANGED")
    recorded=tar_member(rebuilt,
        "./source-info/RM11-HID-WINEBUS-SHA256.txt",4096).decode()
    if NEW_ELF_SHA not in recorded:
        raise ValueError("RM11_SOURCE_BUILD_ELF_SHA_PROVENANCE_ABSENT")
    asset.parent.mkdir(parents=True,exist_ok=True)
    manifest.parent.mkdir(parents=True,exist_ok=True)
    # Assets are staged only in ephemeral CI, not written to user data.
    asset.write_bytes(native)
    out={
        "schema":"rm11.native.hid.winebus.asset.v1",
        "source_revision":SOURCE_PIN,
        "source_url":"https://github.com/The412Banner/proton-wine",
        "source_build_run":BUILT_RUN,
        "legacy_unix_winebus_sha256":LEGACY_ELF_SHA,
        "legacy_arm64_pe_winebus_sha256":LEGACY_PE_SHA,
        "new_unix_winebus_sha256":NEW_ELF_SHA,
        "asset":ASSET_NAME,
        "native_abi":"aarch64-elf64-bionic",
        "wine_pe_unix_call_slots":"PRESERVED_SOURCE_PATCH",
        "native_device_enumeration":"UNVERIFIED_REQUIRES_REAL_ANDROID_LOG",
        "activation":"APP_STARTUP_SHA256_GATED",
        "xinput_game_success":"UNVERIFIED",
    }
    manifest.write_text(json.dumps(out,sort_keys=True,indent=2)+"\n")
    print("RM11_NATIVE_HID_SOURCE_AND_PINNED_PE_ELF_VERIFIED")
    print("RM11_NATIVE_HID_ASSET_SHA256="+NEW_ELF_SHA)


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--legacy-stack",type=Path,required=True)
    p.add_argument("--rebuilt-tar",type=Path,required=True)
    p.add_argument("--asset",type=Path,required=True)
    p.add_argument("--manifest",type=Path,required=True)
    a=p.parse_args()
    stage(a.legacy_stack,a.rebuilt_tar,a.asset,a.manifest)


if __name__=="__main__":main()
