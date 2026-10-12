#!/usr/bin/env python3
"""V2.1.4 source patch guard, host-only GCC test. No device/runtime claim."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import signal

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('box64_v214', ROOT/'build_official_box64.py')
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
with tempfile.TemporaryDirectory(prefix='rm11-v214-abi-') as td:
    root=Path(td)
    priv=root/'src/wrapped/wrappedlibc_private.h'
    impl=root/'src/wrapped/wrappedlibc.c'
    types=root/'src/wrapped/generated/wrappedlibctypes.h'
    types.parent.mkdir(parents=True)
    priv.write_text('GO(__assert_fail, vFppup)\nGOW(__getdelim, lFppiS)\n')
    types.write_text('',encoding='utf-8')
    impl.write_text('''#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#define EXPORT
struct x64emu_s { int ignored; };
typedef struct x64emu_s x64emu_t;
#include "generated/wrappedlibctypes.h"
int main(int argc, char** argv) {
 (void)argv;
 if(argc > 1) my___assert_fail(0, "0", "rm11-host-test.c", 7, "main");
 FILE* f = tmpfile();
 if (!f) return 1;
 if (fputs("ABC\\n",f)==EOF || fflush(f)==EOF || fseek(f,0,SEEK_SET)) return 2;
 char* line=NULL; size_t n=0;
 ssize_t got=my___getdelim(0,&line,&n,'\\n',f);
 int success = got==4 && line && line[0]=='A' && line[3]=='\\n';
 free(line); fclose(f);
 return !success;
}
''',encoding='utf-8')
    mod.patch_android_glibc_misc_bridges(root)
    source=impl.read_text()
    assert 'GOM(__assert_fail, vFEppup)' in priv.read_text()
    assert 'GOM(__getdelim, lFEppiS)' in priv.read_text()
    assert source.count('EXPORT void my___assert_fail(')==1
    assert source.count('EXPORT ssize_t my___getdelim(')==1
    cc=shutil.which('cc') or shutil.which('clang')
    if cc:
        outfile=root/'host-test'
        subprocess.run([cc, '-std=c11','-Wall','-Wextra','-Werror',str(impl),'-o',str(outfile)],check=True,timeout=25)
        subprocess.run([str(outfile)],check=True,timeout=10)
        # Expect an assertion to abort instead of returning success.
        import resource
        def no_cores(): resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        failed=subprocess.run([str(outfile), "assert"], timeout=10, stderr=subprocess.DEVNULL, preexec_fn=no_cores)
        assert failed.returncode == -signal.SIGABRT, failed.returncode
    for which in ('repeat','changed'):
        if which=='changed':
            priv.write_text('GO(__assert_fail, vFppup)\nGOW(__getdelim, WRONG)\n',encoding='utf-8')
        try:
            mod.patch_android_glibc_misc_bridges(root)
        except RuntimeError:
            pass
        else:
            raise AssertionError('Patch must fail closed for '+which)
print('PASS V2.1.4 glibc alias source patch guard and native getdelim host test; NOT Android Box64 runtime')
