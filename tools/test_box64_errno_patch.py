#!/usr/bin/env python3
"""Offline fail-closed source guard for the pinned Android errno shim.

This confirms syntactic construction of the shim and the private wrapper
contract, not successful Box64 compilation nor guest Wine execution.
"""
from pathlib import Path
import importlib.util
import subprocess
import tempfile
import shutil

SRC = Path(__file__).resolve().parent / 'build_official_box64.py'
spec = importlib.util.spec_from_file_location('rm11_box64_v213', SRC)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory(prefix='rm11-v213-errno-') as td:
    root = Path(td)
    private = root / 'src/wrapped/wrappedlibc_private.h'
    impl = root / 'src/wrapped/wrappedlibc.c'
    types = root / 'src/wrapped/generated/wrappedlibctypes.h'
    types.parent.mkdir(parents=True)
    private.write_text('GO(__errno_location, pFv)\n', encoding='utf-8')
    types.write_text('', encoding='utf-8')
    sample = '''#include <errno.h>
#define EXPORT
struct x64emu_s { int unused; };
typedef struct x64emu_s x64emu_t;
#include "generated/wrappedlibctypes.h"
int main(void) {
    int* value=(int*)my___errno_location(0);
    errno=57;
    return !value || *value != 57;
}
'''
    impl.write_text(sample.replace('int main(void)', 'int main(void)'), encoding='utf-8')
    module.patch_android_errno_bridge(root)
    assert private.read_text().count('GOM(__errno_location, pFEv)') == 1
    text = impl.read_text()
    assert text.count('EXPORT void* my___errno_location(') == 1
    cc = shutil.which('cc') or shutil.which('clang')
    if cc:
        obj = root / 'errno-test'
        subprocess.run([cc, '-std=c11', '-Wall', '-Wextra', '-Werror', str(impl), '-o', str(obj)], check=True, timeout=20)
        subprocess.run([str(obj)], check=True, timeout=10)
    for edit in (False, True):
        if edit:
            private.write_text('GO(__errno_location, WRONG)\n')
        try:
            module.patch_android_errno_bridge(root)
        except RuntimeError:
            pass
        else:
            raise AssertionError('Errno patch must reject repeat or modified upstream sources')
print('PASS: V2.1.3 pthread-local errno bridge source and fail-closed patch validation (NOT on-device execution)')
