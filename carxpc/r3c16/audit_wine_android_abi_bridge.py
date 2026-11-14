#!/usr/bin/env python3
"""R3-C16 provenance gate: original Android AArch64 FEX and x86 Linux Wine.
Does NOT perform x86 Win64 execution, guest rootfs setup or Vulkan rendering.
"""
from pathlib import Path
import hashlib,json,struct,sys

def sha(p):
    with open(p,"rb") as f: return hashlib.file_digest(f,"sha256").hexdigest()

def elf_arm64(p):
    with open(p,"rb") as f: head=f.read(64)
    assert head[:6]==bytes([127,69,76,70,2,1]),"NOT_64BIT_LE_ELF"
    assert struct.unpack_from("<H",head,18)[0]==183,"NOT_ARM64_MACHINE"

def main(android_dir,wine_dir,output):
    android=Path(android_dir)
    wine=Path(wine_dir)
    output=Path(output)
    meta=json.loads((android/"candidate.json").read_text())
    assert meta["fex_source_sha"]=="02e24ca5c01ed0c864466ed573db347336f70170"
    assert meta["fex_sha256"]=="f71397bf1bbedd03305c7127e442d674227fa54d15217cc7effb22dbaa9f4b1d"
    assert meta["runner_sha256"]=="b145d4da32a38305d19634fb4777766eec917c72ab172421f52f23849a0074b1"
    for filename,expected in [
        ("libFEXCore.so",meta["fex_sha256"]),
        ("libkernix_g0_original_ldso_continuation.so",meta["runner_sha256"])
    ]:
        f=android/filename
        elf_arm64(f)
        assert sha(f)==expected,("FEX_HASH_MISMATCH",filename)
    assert meta["android_device_executed"] is False
    assert meta["guest_glibc_initialized"] is False
    assert meta["wine_executed"] is False

    wf=wine/"wine-11.0-upstream-x86_64-linux-glibc-runtime.tar.gz"
    manifest=json.loads((wine/"wine-stage-files-sha256.json").read_text())
    assert manifest["schema"]=="kernix.wine11-linux-x86_64-stage.v1"
    assert manifest["upstream_commit"]=="db11d0fe6a169c457e23d007e20404643d067aa8"
    assert manifest["android_bionic_compatible"] is False
    wsha=sha(wf)
    assert wsha==(wine/"wine-linux-x64-stage.tar.gz.sha256").read_text().split()[0],"WINE_ARCHIVE_HASH_MISMATCH"
    assert wf.stat().st_size>1000000,"WINE_ARCHIVE_TRUNCATED"

    result={
       "schema":"r4.carx.r3c16.wine-win64-bionic-integration-boundary.v1",
       "target":"Android ARM64 host + FEX guest Linux x86-64 + Wine Win64 PE",
       "host_android_fexcore_sha256_verified":True,
       "host_android_guest_sample_runner_sha256_verified":True,
       "wine11_linux_x86_64_guest_source_commit":manifest["upstream_commit"],
       "wine11_linux_x86_64_guest_archive_sha256":wsha,
       "wine_guest_archive_bytes":wf.stat().st_size,
       "wine_guest_is_linux_x86_64_NOT_android_host_arm64":True,
       "wine_glibc_guest_dependency_closure_android_verified":False,
       "guest_rootfs_for_android_staged_and_verified":False,
       "generalized_x86_linux_syscall_bridge_for_wine_executed":False,
       "wine_x64_ntdll_kernel32_loaded_on_android":False,
       "win64_pe_executed_under_fex_wine_android":False,
       "dxvk_d3d11_vulkan_presented_from_game":False,
       "carx_street_exe_started":False,
       "stage":"SOURCE_INPUTS_VERIFIED_ANDROID_WINE_BRIDGE_PENDING"
    }
    output.write_text(json.dumps(result,indent=2)+"\n")
    print("CARX_R3C16_SOURCE_VERIFIED_WIN64_WINE_GUEST_BOUNDARY_NO_ANDROID_EXEC_PROOF",wsha)

if __name__=="__main__":
    assert len(sys.argv)==4
    main(*sys.argv[1:])
