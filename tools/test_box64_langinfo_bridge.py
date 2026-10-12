#!/usr/bin/env python3
"""Host fixture simulating Android Bionic nl_item numbers. Not an NDK/on-device test."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile

spec=importlib.util.spec_from_file_location('rm11_box64',Path(__file__).with_name('build_official_box64.py'))
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
with tempfile.TemporaryDirectory(prefix='rm11-v223-langinfo-') as td:
    root=Path(td)
    priv=root/'src/wrapped/wrappedlibc_private.h'
    impl=root/'src/wrapped/wrappedlibc.c'
    types=root/'src/wrapped/generated/wrappedlibctypes.h'
    types.parent.mkdir(parents=True)
    priv.write_text('GO(nl_langinfo, pFi)\n')
    types.write_text('')
    (root/'langinfo.h').write_text('#ifndef RM11_LANGINFO_TEST\n#define RM11_LANGINFO_TEST\n#define CODESET 1\n#define DAY_7 14\nchar* nl_langinfo(int item);\n#endif\n')
    impl.write_text('''#include <errno.h>
#include <stdio.h>
#include <string.h>
#define EXPORT
struct x64emu_s { int unused; };typedef struct x64emu_s x64emu_t;
#include "generated/wrappedlibctypes.h"
char* nl_langinfo(int item) { return item == CODESET ? "UTF-8" : item == DAY_7 ? "Saturday" : "?"; }
int main(void) {
 if(strcmp(nl_langinfo(14),"Saturday")) return 1; /* reproduce root cause */
 if(strcmp(my_nl_langinfo(0,14),"UTF-8")) return 2; /* patched guest CODESET */
 if(strcmp(my_nl_langinfo(0,1),"UTF-8")) return 3;
 return 0;
}
''')
    mod.patch_android_nl_langinfo_codeset(root)
    assert 'GOM(nl_langinfo, pFEi)' in priv.read_text()
    assert impl.read_text().count('EXPORT char* my_nl_langinfo(')==1
    cc=shutil.which('cc') or shutil.which('clang')
    if cc:
        exe=root/'test-langinfo'
        subprocess.run([cc,'-std=c11','-Wall','-Wextra','-Werror','-DANDROID',
                        '-I',str(root),str(impl),'-o',str(exe)],check=True,timeout=15)
        subprocess.run([str(exe)],check=True,timeout=10)
    for mode in ('repeat','changed'):
        if mode=='changed': priv.write_text('GO(nl_langinfo, WRONG)\n')
        try:mod.patch_android_nl_langinfo_codeset(root)
        except RuntimeError:pass
        else:raise AssertionError('Must refuse patch on '+mode)
print('PASS V2.2.3 guest CODESET=14 -> Bionic CODESET=1 fixture; no allocator fix claimed')
