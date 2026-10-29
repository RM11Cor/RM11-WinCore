#!/usr/bin/env python3
"""Instrument a pinned upstream AdrenoTools source COPY for isolated Wine mini diagnostics.
Never mutate signed pinned normal libadrenotools or hook libraries.
"""
import argparse
from pathlib import Path

UPSTREAM_COMMIT = "8fae8ce254dfc1344527e05301e43f37dea2df80"
PREFIX = "RM11_V49025_ADO_STAGE="


def patch(source: str) -> str:
    marker = "bool adrenotools_import_user_mem("
    if source.count(marker) != 1:
        raise ValueError("UPSTREAM_FUNCTION_BOUNDARY_CHANGED")
    head, tail = source.split(marker, 1)
    if head.count("void *adrenotools_open_libvulkan(") != 1:
        raise ValueError("OPEN_LIBVULKAN_SIGNATURE_CHANGED")

    def change(old: str, new: str) -> None:
        nonlocal head
        if head.count(old) != 1:
            raise ValueError("UPSTREAM_BRANCH_CHANGED: " + old[:70])
        head = head.replace(old, new, 1)

    change("#include <unistd.h>", "#include <unistd.h>\n#include <stdio.h>\n#include <errno.h>")
    change("if (!linkernsbypass_load_status())\n        return nullptr;",
           'if (!linkernsbypass_load_status()) { fprintf(stderr,"' + PREFIX + 'LINKER_NS_BYPASS_UNAVAILABLE\\n"); return nullptr; }')
    cases = (
        ('if (!(featureFlags & ADRENOTOOLS_DRIVER_FILE_REDIRECT) && fileRedirectDir)\n        return nullptr;', "UNEXPECTED_FILE_REDIRECT_PARAM"),
        ('if (!(featureFlags & ADRENOTOOLS_DRIVER_CUSTOM) && (customDriverDir || customDriverName))\n        return nullptr;', "UNEXPECTED_CUSTOM_PARAM"),
        ('if (!(featureFlags & ADRENOTOOLS_DRIVER_GPU_MAPPING_IMPORT) && userMappingHandle)\n        return nullptr;', "UNEXPECTED_MAPPING_PARAM"),
        ('if (!customDriverName || !customDriverDir)\n            return nullptr;', "CUSTOM_DRIVER_ARGUMENT_MISSING"),
        ('if (stat((std::string(customDriverDir) + customDriverName).c_str(), &buf) != 0)\n            return nullptr;', "CUSTOM_DRIVER_STAT_FAILED"),
        ('if (!fileRedirectDir)\n            return nullptr;', "REDIRECT_DIR_MISSING"),
        ('if (stat(fileRedirectDir, &buf) != 0)\n            return nullptr;', "REDIRECT_DIR_STAT_FAILED"),
        ('if (!linkernsbypass_link_namespace_to_default_all_libs(hookNs))\n        return nullptr;', "NAMESPACE_LINK_DEFAULT_FAILED"),
        ('if (!hookImpl)\n        return nullptr;', "HOOK_IMPL_DLOPEN_FAILED"),
        ('if (!initHookParam)\n        return nullptr;', "HOOK_IMPL_INIT_SYMBOL_MISSING"),
        ('if (!linkernsbypass_namespace_dlopen("libmain_hook.so", RTLD_GLOBAL, hookNs))\n        return nullptr;', "MAIN_HOOK_DLOPEN_FAILED"),
    )
    for old, name in cases:
        value = 'fprintf(stderr,"' + PREFIX + name + '\\n");'
        if name.endswith("STAT_FAILED"):
            value = 'fprintf(stderr,"' + PREFIX + name + ' errno=%d\\n",errno);'
        change(old, old.replace("return nullptr;", "{ " + value + " return nullptr; }"))
    change('    if (!linkernsbypass_link_namespace_to_default_all_libs(hookNs))',
           '    if (!hookNs) { fprintf(stderr,"' + PREFIX + 'NAMESPACE_CREATE_FAILED\\n"); return nullptr; }\n    if (!linkernsbypass_link_namespace_to_default_all_libs(hookNs))')
    change('    return linkernsbypass_namespace_dlopen_unique("/system/lib64/libvulkan.so", tmpLibDir, dlopenFlags, hookNs);',
           '    void *vulkan = linkernsbypass_namespace_dlopen_unique("/system/lib64/libvulkan.so", tmpLibDir, dlopenFlags, hookNs);\n'
           '    fprintf(stderr,"' + PREFIX + '%s\\n",vulkan ? "ANDROID_VULKAN_LOADER_OPENED" : "ANDROID_VULKAN_UNIQUE_DLOPEN_FAILED");\n'
           '    return vulkan;')
    return head + marker + tail


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    args = parser.parse_args()
    path = Path(args.source)
    raw = path.read_text(encoding="utf-8")
    edited = patch(raw)
    if edited == raw or edited.count(PREFIX) < 12:
        raise ValueError("MISSING_BRANCH_TRACES")
    path.write_text(edited, encoding="utf-8")
    print("RM11_V49025_PINNED_ADRENOTOOLS_PROBE_PATCH_APPLIED")


if __name__ == "__main__":
    main()
