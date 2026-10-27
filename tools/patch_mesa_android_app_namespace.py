#!/usr/bin/env python3
"""Fail-closed, source-pinned Mesa Android application linker namespace patch.

Mesa's -Dandroid-stub=true builds temporary shared "hardware" stubs solely to
link vendor HAL Vulkan drivers. Such stubs MUST NOT be deployed on Android.
Their libhardware.so DT_NEEDED is private to Android's platform namespace.

For an *application-process* candidate only, compile an honest, local fallback
that makes legacy hw_get_module() return -ENOSYS (and NULL). This leaves Mesa's
fallback gralloc path available, but is NOT hardware gralloc, IMapper5, proper
UBWC, WSI, or device-presentation proof. Never publish this driver as ready.
"""
import argparse
from pathlib import Path

MESON_OLD = "  stub_libs = []"
MESON_NEW = """  # RM11 app-namespace candidate only: do not link private libhardware.so.
  # A local failure implementation rejects unsupported legacy gralloc HAL.
  stub_libs = [static_library(
    'rm11_legacy_hal_unavailable',
    files('hardware_stub.cpp'),
    include_directories : inc_include,
    install : false,
  )]"""
LIBS_OLD = "lib_names = ['hardware', 'log', 'nativewindow', 'sync']"
LIBS_NEW = "lib_names = ['log', 'nativewindow', 'sync']"
STUB_HEADER = "#include <hardware/hardware.h>"
STUB_NEW_HEADER = STUB_HEADER + "\n#include <errno.h>"
STUB_OLD_RETURN = "   return 0;"
STUB_NEW_RETURN = "   if (module)\n      *module = nullptr;\n   return -ENOSYS;"


def replace_once(text, old, new, file_label):
    if text.count(old) == 1:
        return text.replace(old, new, 1)
    if text.count(new) == 1 and old not in text:
        return text
    raise ValueError("RM11_MESA_NAMESPACE_SOURCE_DRIFT:" + file_label)


def patch_mesa(root):
    root = Path(root)
    meson = root / "src/android_stub/meson.build"
    stub = root / "src/android_stub/hardware_stub.cpp"
    for path in (meson, stub):
        if path.is_symlink() or not path.is_file():
            raise ValueError("RM11_MESA_REQUIRED_SOURCE_MISSING:" + path.name)
    m = meson.read_text(encoding="utf-8")
    h = stub.read_text(encoding="utf-8")
    if "hw_get_module(" not in h:
        raise ValueError("RM11_MESA_HW_GET_MODULE_NOT_FOUND")
    m = replace_once(m, MESON_OLD, MESON_NEW, "meson:stub_libs")
    m = replace_once(m, LIBS_OLD, LIBS_NEW, "meson:lib_names")
    h = replace_once(h, STUB_HEADER, STUB_NEW_HEADER, "hardware_stub:errno")
    h = replace_once(h, STUB_OLD_RETURN, STUB_NEW_RETURN,
                     "hardware_stub:fail_closed")
    if "lib_names = ['hardware'," in m or STUB_OLD_RETURN in h:
        raise ValueError("RM11_MESA_PRIVATE_HAL_STILL_ENABLED")
    if "return -ENOSYS;" not in h or "nullptr" not in h:
        raise ValueError("RM11_MESA_LEGACY_HAL_DID_NOT_FAIL_CLOSED")
    meson.write_text(m, encoding="utf-8")
    stub.write_text(h, encoding="utf-8")
    return {"source": str(root), "legacy_hw_get_module": "ALWAYS_ENOSYS",
            "android_private_libhardware_link": "REMOVED_FROM_BUILD_CONFIG",
            "hardware_gralloc_proved": False, "android_dlopen_proved": False}


def main():
    cli = argparse.ArgumentParser()
    cli.add_argument("--source", required=True)
    args = cli.parse_args()
    report = patch_mesa(args.source)
    print("RM11_MESA_APP_NAMESPACE_SOURCE_PATCH_APPLIED_NO_DEVICE_PROOF")
    for key, val in report.items():
        print(f"{key}={val}")


if __name__ == "__main__":
    main()
