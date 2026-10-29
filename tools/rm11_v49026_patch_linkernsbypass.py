#!/usr/bin/env python3
"""Instrument pinned linkernsbypass in the isolated AdrenoTools source COPY.
This intentionally leaves ordinary RM11 native provider and linker untouched.
"""
import argparse
from pathlib import Path

UPSTREAM_PIN = "aa3975893d83ef1bc84c321ec60c65fbf1287887"
PREFIX = "RM11_V49026_LNS_STAGE="


def patch(text):
    start = text.find('__attribute__((constructor)) static void resolve_linker_symbols()')
    if start < 0 or text.count('__attribute__((constructor)) static void resolve_linker_symbols()') != 1:
        raise ValueError("UNEXPECTED_PINNED_LINKER_SOURCE")
    pre, body = text[:start], text[start:]

    def repl(old, new):
        nonlocal body
        if body.count(old) != 1:
            raise ValueError("PINNED_LINKER_BRANCH_CHANGED: " + old[:90])
        body = body.replace(old, new, 1)

    repl('    if (android_get_device_api_level() < 28)\n        return;',
         '    fprintf(stderr,"' + PREFIX + 'CONSTRUCTOR_ENTERED api=%d\\n",android_get_device_api_level());\n'
         '    if (android_get_device_api_level() < 28) {\n'
         '        fprintf(stderr,"' + PREFIX + 'ANDROID_API_TOO_OLD\\n");\n'
         '        return;\n'
         '    }')
    repl('        mprotect(align_ptr(reinterpret_cast<void *>(&dlopen)), getpagesize(), PROT_WRITE | PROT_READ | PROT_EXEC);',
         '        if (mprotect(align_ptr(reinterpret_cast<void *>(&dlopen)), getpagesize(), PROT_WRITE | PROT_READ | PROT_EXEC) != 0) {\n'
         '            fprintf(stderr,"' + PREFIX + 'DLOPEN_PAGE_MPROTECT_DENIED errno=%d\\n", errno);\n'
         '            return static_cast<loader_dlopen_t>(nullptr);\n'
         '        }')
    repl('        while (!blInstr->Verify())\n            blInstr++;',
         '        const auto startPage=reinterpret_cast<uintptr_t>(align_ptr(reinterpret_cast<void *>(&dlopen)));\n'
         '        bool found=false;\n'
         '        for (size_t step=0;step<64;step++,blInstr++) {\n'
         '            if (reinterpret_cast<uintptr_t>(blInstr)+sizeof(*blInstr)>startPage+static_cast<uintptr_t>(getpagesize()))break;\n'
         '            if (blInstr->Verify()) {found=true;break;}\n'
         '        }\n'
         '        if (!found) {\n'
         '            fprintf(stderr,"' + PREFIX + 'ARM64_DLOPEN_CALL_BRANCH_NOT_FOUND\\n");\n'
         '            return static_cast<loader_dlopen_t>(nullptr);\n'
         '        }\n'
         '        fprintf(stderr,"' + PREFIX + 'ARM64_DLOPEN_CALL_BRANCH_FOUND\\n");')
    repl('    // Protect the loader_dlopen function to remove the BTI attribute (since this is an internal function that isn\'t intended to be jumped indirectly to)\n'
         '    mprotect(align_ptr(reinterpret_cast<void *>(&loader_dlopen)), getpagesize(), PROT_WRITE | PROT_READ | PROT_EXEC);',
         '    if (!loader_dlopen) return;\n'
         '    // Protect the internal target to remove its BTI attribute only in the isolated test.\n'
         '    if (mprotect(align_ptr(reinterpret_cast<void *>(loader_dlopen)),getpagesize(),PROT_WRITE | PROT_READ | PROT_EXEC) != 0) {\n'
         '        fprintf(stderr,"' + PREFIX + 'INTERNAL_LOADER_MPROTECT_DENIED errno=%d\\n",errno);\n'
         '        return;\n'
         '    }')
    repl('    if (!ldHandle)\n        return;',
         '    if (!ldHandle) {\n'
         '        fprintf(stderr,"' + PREFIX + 'LD_ANDROID_INTERNAL_OPEN_FAILED\\n");\n'
         '        return;\n'
         '    }\n'
         '    fprintf(stderr,"' + PREFIX + 'LD_ANDROID_INTERNAL_OPEN_OK\\n");')
    repl('    if (!android_link_namespaces_all_libs)\n        return;',
         '    if (!android_link_namespaces_all_libs) {\n'
         '        fprintf(stderr,"' + PREFIX + 'LD_LINK_NAMESPACES_ALL_LIBS_SYMBOL_MISSING\\n");\n'
         '        return;\n'
         '    }')
    repl('    if (!android_link_namespaces)\n        return;',
         '    if (!android_link_namespaces) {\n'
         '        fprintf(stderr,"' + PREFIX + 'LD_LINK_NAMESPACES_SYMBOL_MISSING\\n");\n'
         '        return;\n'
         '    }')
    repl('    if (!libdlAndroidHandle)\n        return;',
         '    if (!libdlAndroidHandle) {\n'
         '        fprintf(stderr,"' + PREFIX + 'LIBDL_ANDROID_INTERNAL_OPEN_FAILED\\n");\n'
         '        return;\n'
         '    }')
    repl('    if (!loader_android_create_namespace)\n        return;',
         '    if (!loader_android_create_namespace) {\n'
         '        fprintf(stderr,"' + PREFIX + 'CREATE_NAMESPACE_SYMBOL_MISSING\\n");\n'
         '        return;\n'
         '    }')
    repl('    if (!android_get_exported_namespace)\n        return;',
         '    if (!android_get_exported_namespace) {\n'
         '        fprintf(stderr,"' + PREFIX + 'EXPORTED_NAMESPACE_SYMBOL_MISSING\\n");\n'
         '        return;\n'
         '    }')
    repl('    lib_loaded = true;',
         '    lib_loaded = true;\n'
         '    fprintf(stderr,"' + PREFIX + 'ALL_PRIVATE_LINKER_SYMBOLS_RESOLVED\\n");')
    return pre + body


if __name__ == "__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--source",required=True)
    args=p.parse_args()
    path=Path(args.source)
    orig=path.read_text()
    new=patch(orig)
    if new.count(PREFIX)<12:
        raise ValueError("INCOMPLETE_DIAGNOSTIC_STAGES")
    path.write_text(new)
    print("RM11_V49026_PINNED_LINKER_BYPASS_INNER_TRACE_PATCHED")
