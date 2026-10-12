#!/usr/bin/env python3
"""Offline source-patch guard; synthetic compilation, NOT on-device Box64 proof."""
from pathlib import Path
import importlib.util
import subprocess
import tempfile
import shutil

SRC=Path(__file__).resolve().parent/'build_official_box64.py'
spec=importlib.util.spec_from_file_location('rm11_box_builder', SRC)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

sample='''#include <stdint.h>
#define EXPORT
#ifdef ANDROID
void EXPORT my___libc_init(void) { }
#else
EXPORT int32_t my___libc_start_main(void) { return 0; }
#ifdef BOX32
#ifdef ANDROID
void my32___libc_init(void) { }
#else
void my32___libc_start_main(void) { }
#endif
#endif
#endif
'''
with tempfile.TemporaryDirectory(prefix='rm11-v18-patch-') as folder:
    root=Path(folder)
    entry=root/'src/emu/entrypoint.c'
    entry.parent.mkdir(parents=True)
    entry.write_text(sample)
    private=root/'src/wrapped/wrappedlibc_private.h'
    private.parent.mkdir(parents=True)
    private.write_text('GOM(__libc_start_main, iFEpippppp)\n')
    module.patch_android_glibc_startup(root)
    patched=entry.read_text()
    assert 'RM11-V1.8' in patched
    assert patched.count('EXPORT int32_t my___libc_start_main(')==1
    assert patched.count('my___libc_init(')==1
    compiler=shutil.which('cc') or shutil.which('gcc')
    if compiler:
        for mode, expected_init in [('android', True), ('linux', False)]:
            obj=root/(mode+'.o')
            opts=['-DANDROID'] if expected_init else []
            subprocess.run([compiler,'-std=c11','-Werror','-Wall','-c',*opts,
                            str(entry),'-o',str(obj)],check=True,timeout=15)
            names=subprocess.check_output(['nm','--defined-only',str(obj)],text=True)
            assert 'my___libc_start_main' in names
            assert ('my___libc_init' in names)==expected_init
    try:
        module.patch_android_glibc_startup(root)
        raise AssertionError('Patch must refuse double application')
    except RuntimeError:
        pass
    private.write_text('no matching wrapper contract')
    entry.write_text(sample)
    try:
        module.patch_android_glibc_startup(root)
        raise AssertionError('Patch must refuse modified upstream wrapper API')
    except RuntimeError:
        pass
print('PASS: V1.8 fail-closed pinned startup patch exposes both Android and glibc entries; no Android behavior claimed')
