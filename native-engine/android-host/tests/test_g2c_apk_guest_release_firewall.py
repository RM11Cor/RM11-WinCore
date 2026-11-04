#!/usr/bin/env python3
"""Host-only hostile ZIP tests for the signed KERNIX APK guest firewall."""
import io
import json
from pathlib import Path
import stat
import sys
import tempfile
import warnings
import zipfile

sys.path.insert(0,str(Path(__file__).resolve().parents[3]/"tools"))
from kernix_g2c_apk_guest_release_firewall import scan

def native(marker=b""):
    elf=bytearray(64)
    elf[:6]=b"\x7fELF\x02\x01"
    elf[18:20]=b"\xb7\x00"  # Android AArch64
    return bytes(elf)+marker

def x86():
    elf=bytearray(64)
    elf[:6]=b"\x7fELF\x02\x01"
    elf[18:20]=b"\x3e\x00"
    return bytes(elf)+b"fixed-other-x86-program"

def test(root):
    fixture=Path(root)
    base={
        "lib/arm64-v8a/libFEXCore.so":native(b"ORIGINAL-FEXCORE"),
        "lib/arm64-v8a/libkernix_g2c_data_only_child.so":native(b"PAGE-ONLY"),
        "classes.dex":b"dex\n035\x00test",
        "AndroidManifest.xml":b"fake android manifest in test, unsigned!",
    }
    with tempfile.TemporaryDirectory(prefix="kernix-g2c-zip-firewall-") as temp:
        apk=Path(temp)/"test-only-not-signed.apk"
        def write(entries, symlink=None, duplicated=None):
            with warnings.catch_warnings():
                warnings.simplefilter("ignore",UserWarning)
                with zipfile.ZipFile(apk,"w",compression=zipfile.ZIP_DEFLATED) as out:
                    for name,content in entries.items():
                        if name==symlink:
                            entry=zipfile.ZipInfo(name)
                            entry.create_system=3
                            entry.external_attr=(stat.S_IFLNK|0o777)<<16
                            out.writestr(entry,content)
                        else:
                            out.writestr(name,content)
                    if duplicated is not None:
                        out.writestr(duplicated,entries[duplicated])
        def reject(entries,label,symlink=None,duplicated=None):
            write(entries,symlink,duplicated)
            try: scan(apk)
            except ValueError: return
            raise AssertionError("Unsafe APK content accepted: "+label)

        write(base)
        ok=scan(apk)
        assert ok["release_action"]=="HOST_PREVIEW_DATA_ONLY"
        assert ok["original_fixed_guest_sha256_not_present"] is True
        assert ok["guest_glibc_not_present"] is True
        assert ok["g2c_dynamic_pie_executed_on_android"] is False
        assert ok["apk_signature_checked_in_this_gate"] is False

        a=dict(base)
        a["assets/renamed-unexpected-data.bin"]=(fixture/"bin/kernix-dynamic-app").read_bytes()
        reject(a,"original x86 guest ELF hidden as renamed asset")
        a=dict(base)
        a["assets/libc-copy.txt"]=(fixture/"lib/x86_64-linux-gnu/libc.so.6").read_bytes()
        reject(a,"original x86 libc hidden as renamed asset")
        a=dict(base)
        a["assets/other.elf"]=x86()
        reject(a,"non-pinned x86 ELF")
        a=dict(base)
        a["lib/arm64-v8a/libhidden.so"]=native(
            b"KERNIX_G2C_ANDROID_FEX_DIRECT_PIE_ENTRY_PASS_NOT_GLIBC_V1")
        reject(a,"hidden runnable G2-C JIT marker")
        a=dict(base)
        a["lib/arm64-v8a/libhidden.so"]=native(
            b"--kernix-g2c-execute-fixed-snapshot-direct-entry-v1")
        reject(a,"hidden G2-C direct-entry flag")
        a=dict(base)
        a["lib/x86_64/libhost.so"]=x86()
        reject(a,"unexpected x86 native architecture")
        a=dict(base)
        a["assets/g2c-fixed-v1/manifest.json"]=b"fake"
        reject(a,"G2-C rootfs path")
        a=dict(base)
        a["assets/../outside"]=b"arbitrary"
        reject(a,"ZIP traversal")
        a=dict(base)
        a["lib/arm64-v8a/hijack.so"]=b"../../somewhere"
        reject(a,"ZIP symlink",symlink="lib/arm64-v8a/hijack.so")
        reject(base,"ZIP duplicate",duplicated="classes.dex")
        a=dict(base)
        a.pop("lib/arm64-v8a/libkernix_g2c_data_only_child.so")
        reject(a,"missing safe G2-C child")
        a=dict(base)
        a["lib/arm64-v8a/libFEXCore.so"]=x86()
        reject(a,"wrong FEXCore ARM64 ELF ABI")
        print("KERNIX_G2C_SIGNED_APK_RENAMED_X86_ELF_NOSYMLINK_JIT_MARKER_ADVERSARIAL_PASS")

if __name__=="__main__":
    if len(sys.argv)!=2:raise SystemExit("Usage: test_g2c_apk_guest_release_firewall.py FIXTURE")
    test(sys.argv[1])
