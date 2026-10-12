#!/usr/bin/env python3
"""V2.3.0 local contracts: pinned patch + actual C ownership behaviour.
No Git/network/NDK required; Android cross-compile remains a CI job.
"""
from pathlib import Path
import sys, tempfile, subprocess, shutil
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tools'))
from build_official_box64 import patch_rm11_owned_environment_snapshot

def check(cond, detail):
    if not cond: raise AssertionError(detail)

with tempfile.TemporaryDirectory(prefix='rm11-v23-') as td:
    d=Path(td)/'src/wrapped';d.mkdir(parents=True)
    source=d/'wrappedlibc.c'; defs=d/'wrappedlibc_private.h'
    defs.write_text('GO(getenv, pFp)\nGO(free, vFp)\nGO2(__secure_getenv, pFp, getenv)   // not always present\nGOW(secure_getenv, pFp)\n')
    source.write_text('#include <errno.h>\n#include "generated/wrappedlibctypes.h"\n')
    patch_rm11_owned_environment_snapshot(Path(td))
    code=source.read_text()
    hdr=defs.read_text()
    check('GOM(secure_getenv, pFEp)' in hdr and 'GOM(getenv, pFEp)' in hdr and 'GOM(free, vFEp)' in hdr, 'Wrapper signatures not bound')
    check('GO(free, vFp)' in hdr and 'GOW(secure_getenv, pFp)' in hdr, 'Non-Android fallback altered')
    check(code.count('RM11_ENV_BORROWED_FREE_PREVENTED')==1, 'Must have exact guard')
    check('free(ptr); /* ALL unrelated native allocations are freed normally. */' in code,'Other frees must not be skipped')
    try: patch_rm11_owned_environment_snapshot(Path(td))
    except RuntimeError: pass
    else: raise AssertionError('Re-applying patch did not refuse')

    if not shutil.which('cc'):
        print('PASS: V2.3 static patch safety; SKIP local C runtime (cc missing)')
        raise SystemExit(0)
    # Build the actual emitted adapter C code under a host stub x64emu_t.
    section=code.split('/* RM11_ENV_SNAPSHOT_V230:',1)[1].split('#endif',1)[0]
    c=('''#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#define EXPORT
#define ANDROID 1
typedef struct {int unused;} x64emu_t;
/* RM11_ENV_SNAPSHOT_V230:'''+section+'''
int main(void) {
   x64emu_t fake = {0};
   if (setenv("RM11_V23_TEST", "first", 1)) return 1;
   char *borrowed = my_secure_getenv(&fake, "RM11_V23_TEST");
   if (!borrowed || strcmp(borrowed,"first")) return 2;
   if (borrowed == getenv("RM11_V23_TEST")) return 3; /* native pointer must not escape */
   if (my___secure_getenv(&fake, "RM11_V23_TEST") != borrowed) return 4;
   if (my_getenv(&fake, "RM11_V23_TEST") != borrowed) return 10;
   my_free(&fake, borrowed); /* safe despite invalid guest free */
   if (strcmp(borrowed,"first")) return 5;
   char *ordinary = malloc(32);
   if (!ordinary) return 6;
   my_free(&fake, ordinary); /* must dispatch ordinary pointers to native free */
   if (setenv("RM11_V23_TEST", "second", 1)) return 7;
   char *fresh = my_secure_getenv(&fake,"RM11_V23_TEST");
   if (!fresh || fresh == borrowed || strcmp(fresh,"second")) return 8;
   if (strcmp(borrowed,"first")) return 9;
   puts("PASS RM11 V2.3 owned environment snapshot and selective free");
   return 0;
}
''')
    fn=Path(td)/'test.c';fn.write_text(c)
    out=Path(td)/'test'
    subprocess.run(['cc','-std=c11','-Werror','-Wall','-Wextra','-pthread',str(fn),'-o',str(out)],check=True)
    subprocess.run([str(out)],check=True)
print('PASS: V2.3 pinned source adapter contract and host C probe')
