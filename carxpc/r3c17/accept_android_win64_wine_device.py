#!/usr/bin/env python3
"""R3C17 Android Win64 PE device acceptance contract.

This is a consistency validator for *on-device* evidence. Compiling it or
passing synthetic unit tests NEVER proves Android Wine execution. A real
Android runtime must emit the required events from an actual guest child.
"""
from __future__ import annotations
import json,sys,re
from pathlib import Path

SCHEMA="r4.carx.r3c17.android-arm64-bionic-fex-wine-win64-pe.v1"
FEX_COMMIT="02e24ca5c01ed0c864466ed573db347336f70170"
# Source-controlled original MinGW Win64 PE64 fixture (actual compiled binary).
PE_SHA="7a3b6d182d892d3ac4f3af4f5c5b56789e64beb2868fcf40993a752ab84306bf"
PE_PASS="CARX_R3C16_REAL_WIN64_PE_WINAPI_VMEM_TLS_STDOUT_PASS"

def validate(obj:dict)->dict:
    assert type(obj) is dict and obj.get("schema")==SCHEMA, "SCHEMA_INVALID"
    dev=obj.get("device")
    assert type(dev) is dict, "DEVICE_MISSING"
    assert dev.get("os")=="Android" and dev.get("libc")=="Bionic", "NOT_ANDROID_BIONIC_HOST"
    assert dev.get("abi")=="arm64-v8a", "NOT_ANDROID_ARM64"
    assert type(dev.get("android_sdk")) is int and dev["android_sdk"]>=26, "INVALID_ANDROID_SDK"
    assert dev.get("real_hardware_test") is True, "NOT_ON_DEVICE"

    runner=obj.get("runtime")
    assert type(runner) is dict, "RUNTIME_MISSING"
    assert runner.get("fex_upstream_git_sha")==FEX_COMMIT, "FEX_SOURCE_NOT_PINNED"
    assert runner.get("fex_host_platform")=="android-bionic-arm64", "FEX_LINUX_HOST_NOT_ANDROID"
    assert runner.get("wine_guest_platform")=="linux-glibc-x86_64", "WINE_GUEST_ABI_INVALID"
    assert runner.get("wine_guest_rootfs_sha256")=="86fafa2f5072aa2c47b7025ca591d945007584ecda37ae92eee208a95283f4b0", "GUEST_ROOTFS_HASH_CHANGED"
    assert runner.get("guest_prefix_inside_rootfs") is True, "GUEST_PREFIX_NOT_INSIDE_ROOTFS"
    assert runner.get("guest_prefix_parent_owned_by_android_app") is True, "WINE_PREFIX_PARENT_NOT_OWNED"
    assert runner.get("wine_distribution")=="ubuntu-noble-linux-x86_64-guest", "SOURCE_WINE11_NOT_YET_INTEGRATED"

    child=obj.get("guest_child")
    assert type(child) is dict,"CHILD_MISSING"
    for key in ("android_bionic_process_spawned","linux_x86_64_guest_ldso_entered",
                "windows_ntdll_pe_loaded","windows_kernel32_pe_loaded",
                "wine_win64_real_PE_executed",
                "windows_virtualalloc_tls_protect_writefile_verified",
                "no_host_android_TLS_overwrite","no_untrusted_guest_pointer_to_host",
                "no_wx_mappings"):
        assert child.get(key) is True, "DEVICE_GATE_UNPROVEN_"+key
    assert child.get("pe_image_sha256")==PE_SHA, "WINDOWS_PE_BYTES_DIFFERENT"
    assert child.get("pe_machine")=="AMD64", "NOT_REAL_WINDOWS_X64_PE"
    assert type(child.get("exit_code")) is int and child["exit_code"]==0, "WIN64_GUEST_PROCESS_NONZERO_EXIT"

    # Ordered original child transcript, not a single uncorrelated success
    # flag; stdout exact marker is necessary but not sufficient by itself.
    log=obj.get("native_child_log")
    assert type(log) is str and 40<len(log)<2_000_000, "MISSING_DEVICE_CHILD_LOG"
    markers=[
      "CARX_R3C17_ANDROID_ARM64_FEX_BIONIC_NATIVE_CHILD_STARTED",
      "CARX_R3C17_GUEST_LINUX_X86_64_LDSO_EXECUTED",
      "CARX_R3C17_WINE_NTDLL_PE64_LOADED",
      "CARX_R3C17_WINE_KERNEL32_PE64_LOADED",
      PE_PASS,
      "CARX_R3C17_WIN64_PE_GUEST_EXIT0_ANDROID_BIONIC"
    ]
    prev=-1
    for marker in markers:
        at=log.find(marker,prev+1)
        assert at>prev, "CHILD_LOG_EVENT_MISSING_OR_OUT_OF_ORDER_"+marker
        prev=at
    assert "KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL" not in log, "UNSUPPORTED_GUEST_SYSCALL"
    assert "FEX_BIONIC_HOST_TLS_CORRUPTED" not in log, "HOST_TLS_CORRUPTED"
    assert not re.search(r"\b(?:SIGSEGV|SIGBUS|SIGKILL|fatal signal)\b",log,re.I), "NATIVE_CHILD_FATAL_SIGNAL"
    assert obj.get("wine_android_device_boot_proven") is True, "DEVICE_WINE_BOOT_NOT_PROVEN"
    assert obj.get("carx_game_boot_proven") is False, "GAME_BOOT_FALSE_POSITIVE"
    assert obj.get("vulkan_triangle_presented") is False, "GRAPHICS_FALSE_POSITIVE"
    return {
      "schema":"r4.carx.r3c17.android-device-win64-gate-result.v1",
      "accepted_device_wine_win64_smoke":True,
      "game_boot_proven":False,
      "graphics_presented":False,
      "device_abi":"arm64-v8a",
      "accepted_test":"original real Win64 PE through FEX Wine on Android Bionic"
    }

def fixture()->dict:
    return {
      "schema":SCHEMA,
      "device":{"os":"Android","libc":"Bionic","abi":"arm64-v8a","android_sdk":36,"real_hardware_test":True},
      "runtime":{"fex_upstream_git_sha":FEX_COMMIT,"fex_host_platform":"android-bionic-arm64","wine_guest_platform":"linux-glibc-x86_64",
                 "wine_guest_rootfs_sha256":"86fafa2f5072aa2c47b7025ca591d945007584ecda37ae92eee208a95283f4b0",
                 "guest_prefix_inside_rootfs":True,"guest_prefix_parent_owned_by_android_app":True,"wine_distribution":"ubuntu-noble-linux-x86_64-guest"},
      "guest_child":{**{x:True for x in (
         "android_bionic_process_spawned","linux_x86_64_guest_ldso_entered",
         "windows_ntdll_pe_loaded","windows_kernel32_pe_loaded",
         "wine_win64_real_PE_executed","windows_virtualalloc_tls_protect_writefile_verified",
         "no_host_android_TLS_overwrite","no_untrusted_guest_pointer_to_host","no_wx_mappings")},
         "pe_image_sha256":PE_SHA,"pe_machine":"AMD64","exit_code":0},
      "native_child_log":"\n".join([
         "CARX_R3C17_ANDROID_ARM64_FEX_BIONIC_NATIVE_CHILD_STARTED",
         "CARX_R3C17_GUEST_LINUX_X86_64_LDSO_EXECUTED",
         "CARX_R3C17_WINE_NTDLL_PE64_LOADED",
         "CARX_R3C17_WINE_KERNEL32_PE64_LOADED",
         PE_PASS,
         "CARX_R3C17_WIN64_PE_GUEST_EXIT0_ANDROID_BIONIC"]),
      "wine_android_device_boot_proven":True,
      "carx_game_boot_proven":False,
      "vulkan_triangle_presented":False
    }

def selftest():
    # The fixture is deliberately SYNTHETIC; never persist or submit it as
    # proof of real Android execution.
    x=fixture()
    assert validate(x)["accepted_device_wine_win64_smoke"]
    tests=[]
    def bad(name,fn):
        y=json.loads(json.dumps(x))
        fn(y)
        try: validate(y)
        except AssertionError: tests.append(name)
        else: raise AssertionError("SYNTHETIC_NEGATIVE_ACCEPTED_"+name)
    bad("not_android",lambda y:y["device"].update(os="Linux"))
    bad("not_hardware",lambda y:y["device"].update(real_hardware_test=False))
    bad("wrong_fex",lambda y:y["runtime"].update(fex_upstream_git_sha="0"*40))
    bad("linux_host",lambda y:y["runtime"].update(fex_host_platform="linux-glibc-arm64"))
    bad("rootfs_changed",lambda y:y["runtime"].update(wine_guest_rootfs_sha256="0"*64))
    bad("unowned_guest_prefix",lambda y:y["runtime"].update(guest_prefix_parent_owned_by_android_app=False))
    bad("no_kernel32",lambda y:y["guest_child"].update(windows_kernel32_pe_loaded=False))
    bad("wrong_pe_sha",lambda y:y["guest_child"].update(pe_image_sha256="0"*64))
    bad("exit137",lambda y:y["guest_child"].update(exit_code=137))
    bad("guest_tls_host_override",lambda y:y["guest_child"].update(no_host_android_TLS_overwrite=False))
    bad("marker_only",lambda y:y.update(native_child_log=PE_PASS))
    bad("unordered_log",lambda y:y.update(native_child_log=y["native_child_log"].replace("CARX_R3C17_WINE_NTDLL_PE64_LOADED","MISSING")))
    bad("unsupported_syscall",lambda y:y.update(native_child_log=y["native_child_log"]+"\nKERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL"))
    bad("fatal_signal",lambda y:y.update(native_child_log=y["native_child_log"]+"\nSIGKILL"))
    bad("carx_false_positive",lambda y:y.update(carx_game_boot_proven=True))
    bad("graphics_false_positive",lambda y:y.update(vulkan_triangle_presented=True))
    assert len(tests)==16
    print("CARX_R3C17_ANDROID_DEVICE_WIN64_GATE_16_SYNTHETIC_NEGATIVES_PASS_NO_ANDROID_EXECUTION_CLAIM")

if __name__=="__main__":
    if len(sys.argv)==2 and sys.argv[1]=="--synthetic-selftest":
        selftest()
    elif len(sys.argv)==2:
        report=json.loads(Path(sys.argv[1]).read_text())
        print(json.dumps(validate(report),indent=2))
    else:
        raise SystemExit("Usage: accept_android_win64_wine_device.py REPORT.json | --synthetic-selftest")
