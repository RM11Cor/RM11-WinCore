#!/usr/bin/env python3
"""V2.2.4 host fixture for build-time-only Box64 opt-in; no device proof.

Synthetic Bionic mallopt makes this runnable without Android NDK. Does not test
pointer safety, Box64, Wine, or the problematic native allocator on REDMAGIC.
"""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('box64',ROOT/'build_official_box64.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
with tempfile.TemporaryDirectory(prefix='rm11-v224-malloc-fixture-') as t:
    root=Path(t)
    (root/'src').mkdir()
    (root/'src/main.c').write_text('''#include "core.h"

int main(int argc, const char **argv, char **env) {
    x64emu_t* emu = NULL;
    elfheader_t* elf_header = NULL;
    if (initialize(argc, argv, env, &emu, &elf_header, 1)) return -1;
    return emulate(emu, elf_header);
}
''')
    (root/'src/core.h').write_text('''typedef struct x64emu_s { int x; } x64emu_t;
typedef struct elfheader_s { int x; } elfheader_t;
int initialize(int,const char**,char**,x64emu_t**,elfheader_t**,int);
int emulate(x64emu_t*,elfheader_t*);
''')
    (root/'src/malloc.h').write_text('''#pragma once
#define M_BIONIC_SET_HEAP_TAGGING_LEVEL (-204)
#define M_HEAP_TAGGING_LEVEL_NONE (0)
int mallopt(int,int);
''')
    (root/'src/stub.c').write_text('''#include <stdlib.h>
#include <stdio.h>
#include "core.h"
int mallopt(int code,int level) {
    if(code!=-204 || level!=0 || getenv("RM11_FAKE_MALLOPT_FAIL")) return 0;
    return 1;
}
int initialize(int argc,const char** argv,char** env,x64emu_t** e,elfheader_t** h,int v) {
    (void)argc;(void)argv;(void)env;(void)e;(void)h;(void)v;
    puts("INITIALIZE_WAS_CALLED");return 0;
}
int emulate(x64emu_t*e,elfheader_t*h){(void)e;(void)h;return 0;}
''')
    mod.patch_box64_child_heap_isolation(root)
    patched=(root/'src/main.c').read_text()
    assert patched.count('RM11_HEAP_ISOLATION_APPLIED')==1
    cc=shutil.which('cc') or shutil.which('clang')
    if cc:
        exe=root/'test-main'
        subprocess.run([cc,'-std=c11','-Wall','-Wextra','-Werror','-DANDROID','-I',str(root/'src'),
                        str(root/'src/main.c'),str(root/'src/stub.c'),'-o',str(exe)],check=True)
        env=os.environ.copy();env.pop('RM11_TEST_DISABLE_BIONIC_HEAP_TAGS',None)
        normal=subprocess.run([str(exe)],env=env,check=True,capture_output=True,text=True)
        assert 'RM11_HEAP_ISOLATION_APPLIED' not in normal.stderr
        assert 'INITIALIZE_WAS_CALLED' in normal.stdout
        env['RM11_TEST_DISABLE_BIONIC_HEAP_TAGS']='1'
        changed=subprocess.run([str(exe)],env=env,check=True,capture_output=True,text=True)
        assert 'RM11_HEAP_ISOLATION_APPLIED' in changed.stderr
        assert 'INITIALIZE_WAS_CALLED' in changed.stdout
        env['RM11_FAKE_MALLOPT_FAIL']='1'
        failed=subprocess.run([str(exe)],env=env,capture_output=True,text=True)
        assert failed.returncode==123 and 'RM11_HEAP_ISOLATION_REJECTED' in failed.stderr
        assert 'INITIALIZE_WAS_CALLED' not in failed.stdout
    try:mod.patch_box64_child_heap_isolation(root)
    except RuntimeError:pass
    else:raise AssertionError('repeated patch allowed')
    (root/'src/main.c').write_text('int main(void) {return 0;}')
    try:mod.patch_box64_child_heap_isolation(root)
    except RuntimeError:pass
    else:raise AssertionError('unexpected Box64 main contract accepted')
print('PASS V2.2.4 Box64 subprocess heap-tag opt-in A/B gating, baseline and failure path (synthetic fixture only)')
