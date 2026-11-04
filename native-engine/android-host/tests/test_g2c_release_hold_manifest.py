#!/usr/bin/env python3
"""Adversarial checks for the CI-only G2-C combined NO-SHIP release gate."""
import json
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parents[3]/"tools"))
from kernix_g2c_release_hold_manifest import verify


def rejection(fn,what):
    try: fn()
    except (ValueError,OSError,KeyError,TypeError):
        return
    raise AssertionError("G2-C illegally accepted "+what)


def run(args):
    if len(args)!=8:
        raise ValueError("Expected 7 fixture/receipt/notice paths")
    fixture,binary,source,witness,mit,ubuntu,lgpl=map(Path,args[1:])
    with tempfile.TemporaryDirectory(prefix="kernix-g2c-combined-release-hold-") as temp:
        dest=Path(temp)
        b=dest/"binary.json"
        s=dest/"source.json"
        shutil.copy2(binary,b)
        shutil.copy2(source,s)
        def check(fixture_path=fixture,notice=ubuntu,mit_path=mit,lgpl_path=lgpl):
            return verify(fixture_path,b,s,witness,mit_path,notice,lgpl_path)
        value=check()
        assert value["release_action"]=="HOLD_NO_APK_NO_GUEST_EXECUTION"
        assert value["verified_exact_guest_elf_files"]==4
        assert value["redistribution_approved"] is False
        assert value["g2c_x86_dynamic_pie_executed_on_android"] is False
        assert value["qualifying_signed_fex_runner_sha256"] is None

        binary_rec=json.loads(binary.read_text())
        source_rec=json.loads(source.read_text())
        def change(where,original,field,value):
            obj=json.loads(original.read_text())
            obj[field]=value
            where.write_text(json.dumps(obj))
            rejection(check,field)
            shutil.copy2(original,where)
        change(b,binary,"distribution_approved",True)
        change(b,binary,"installed_cross_libc_exact_hash_match",False)
        change(b,binary,"package","libc6-amd64")
        change(b,binary,"guest_file_sha256",{})
        change(b,binary,"upstream_package_copyright_sha256","0"*64)
        change(s,source,"distribution_approved",True)
        change(s,source,"corresponding_source_artifacts_accessible",False)
        change(s,source,"dsc_pgp_signature_cryptographically_verified",True)
        change(s,source,"source_files",{})
        change(s,source,"ubuntu_binary_version","2.39-0ubuntu9")

        notice=dest/"tampered-copyright"
        notice.write_bytes(ubuntu.read_bytes()+b"\nTAMPER")
        rejection(lambda:check(notice=notice),"altered copyright text")

        orig_mit=mit.read_bytes()
        altered=dest/"altered-MIT"
        altered.write_bytes(orig_mit.replace(b"MIT License",b"XIT License",1))
        rejection(lambda:check(mit_path=altered),"wrong MIT notice")

        orig_lgpl=lgpl.read_bytes()
        altered_lgpl=dest/"altered-lgpl"
        altered_lgpl.write_bytes(orig_lgpl[:250])
        rejection(lambda:check(lgpl_path=altered_lgpl),"truncated LGPL")

        guest=dest/"g2c-fixed-v1"
        shutil.copytree(fixture,guest)
        elf=guest/"bin/kernix-dynamic-app"
        elf.chmod(0o600)
        blob=bytearray(elf.read_bytes());blob[91]^=0x01;elf.write_bytes(blob)
        rejection(lambda:check(fixture_path=guest),"mutated x86 guest ELF")
        shutil.copy2(fixture/"bin/kernix-dynamic-app",elf)
        manifest=guest/"manifest.json"
        obj=json.loads(manifest.read_text())
        obj["android_device_executed"]=True
        manifest.write_text(json.dumps(obj))
        rejection(lambda:check(fixture_path=guest),"false Android success")

        assert check()["release_action"]=="HOLD_NO_APK_NO_GUEST_EXECUTION"
        print("KERNIX_G2C_PRE_RELEASE_SOURCE_LICENSE_WITNESS_SHA_TAMPER_GATE_PASS_HOLD_NO_APK")


if __name__=="__main__":
    run(sys.argv)
