#!/usr/bin/env python3
"""Apply RM11 native HID PnP backend to the EXACT historical Wine source pin.

Native Wine/PE Unix-call ABI safety:
* Keep enum unix_funcs in unixlib.h exactly unchanged.
* Keep Winebus PE main.c and winebus.sys unchanged.
* Replace ONLY the existing SDL backend function pointers in unixlib.c.
* Provide a source-matched unix winebus.so rebuild; do not mix with an
  unverified prebuilt one or publish an APK from this script.
"""
import argparse
import shutil
import subprocess
from pathlib import Path

PIN="256288853b206373cbf65b775143d33bb11035dd"
FILES={
    "app/src/main/cpp/rm11_native_hid_gamepad.c":"unix/rm11_native_hid_gamepad.c",
    "app/src/main/cpp/rm11_native_hid_gamepad.h":"unix/rm11_native_hid_gamepad.h",
    "app/src/main/cpp/rm11_native_hid_transport.c":"unix/rm11_native_hid_transport.c",
    "app/src/main/cpp/rm11_native_hid_transport.h":"unix/rm11_native_hid_transport.h",
    "app/src/main/cpp/winebus/rm11_winebus_native_hid.c":"unix/rm11_winebus_native_hid.c",
}
CALLS="    sdl_bus_init,\n    sdl_bus_wait,\n    sdl_bus_stop,"
REPLACEMENT="    rm11_winebus_init,\n    rm11_winebus_wait,\n    rm11_winebus_stop,"


def patch(wine: Path, rm11: Path):
    wine=wine.resolve()
    rm11=rm11.resolve()
    revision=subprocess.check_output(
        ["git","-C",str(wine),"rev-parse","HEAD"],text=True).strip()
    if revision!=PIN:
        raise RuntimeError("WINE_SOURCE_REVISION_MISMATCH_NO_PATCH:" + revision)
    target=wine/"dlls/winebus.sys"
    source=target/"unixlib.c"
    content=source.read_text()
    if content.count(CALLS)!=1:
        raise RuntimeError("WINE_UNIX_CALL_SLOT_SIGNATURE_MISMATCH")
    header='''/* RM11 source-pinned virtual HID bus: preserve all PE unixcall indices */
extern NTSTATUS rm11_winebus_init(void *);
extern NTSTATUS rm11_winebus_wait(void *);
extern NTSTATUS rm11_winebus_stop(void *);

'''
    anchor="const unixlib_entry_t __wine_unix_call_funcs[] ="
    if content.count(anchor)!=1:
        raise RuntimeError("WINE_UNIX_DISPATCH_TABLE_NOT_FOUND")
    source.write_text(content.replace(anchor,header+anchor)
                      .replace(CALLS,REPLACEMENT))
    makefile=target/"Makefile.in"
    lines=makefile.read_text()
    marker="\tbus_sdl.c \\\n"
    if lines.count(marker)!=1:
        raise RuntimeError("WINE_MAKEFILE_SOURCE_LIST_MISMATCH")
    # Wine's make system compiles unix/*.c for the native winebus.so only,
    # never for the Windows PE winebus.sys (msvcrt lacks sys/mman.h).
    additional = "".join(
        "\tunix/" + name + " \\\n"
        for name in (
            "rm11_winebus_native_hid.c",
            "rm11_native_hid_gamepad.c",
            "rm11_native_hid_transport.c",
        )
    )
    makefile.write_text(lines.replace(marker,marker+additional))
    for local,name in FILES.items():
        origin=rm11/local
        if not origin.is_file():
            raise RuntimeError("RM11_CONTROLLER_SOURCE_MISSING:" + local)
        (target/name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(origin,target/name)
    assert 'unix/rm11_winebus_native_hid.c' in makefile.read_text()
    assert 'unix/rm11_native_hid_gamepad.c' in makefile.read_text()
    assert 'unix/rm11_native_hid_transport.c' in makefile.read_text()
    return {
        "source_pin": PIN,
        "unixlib_call_order_unchanged": True,
        "wine_pe_driver_untouched": True,
        "wine_unix_driver_source_patched": True,
        "new_native_source_files": sorted(FILES.values()),
        "apk_publish_allowed": False,
    }


def main():
    import json
    p=argparse.ArgumentParser()
    p.add_argument("--wine-source",type=Path,required=True)
    p.add_argument("--rm11-repo",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    result=patch(a.wine_source,a.rm11_repo)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print("RM11_PINNED_WINE_NATIVE_HID_UNIX_CALL_SLOTS_UNCHANGED")
    print("RM11_PE_UNIX_ABI_COMPATIBILITY_SOURCE_PATCH_READY_NO_APK")


if __name__=="__main__":
    main()
