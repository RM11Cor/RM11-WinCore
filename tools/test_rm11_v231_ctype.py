#!/usr/bin/env python3
"""Check pinned Box64 ctype wrapper and compiled x86_64 glibc ABI fallback.
No Android or Windows execution is implied by this host-only test.
"""
from pathlib import Path
import sys, tempfile, subprocess, shutil
root=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(root/'tools'))
from build_official_box64 import patch_android_glibc_ctype_loc
with tempfile.TemporaryDirectory(prefix='rm11-v231-ctype-') as tmp:
    d=Path(tmp)/'src/wrapped'; d.mkdir(parents=True)
    defs=d/'wrappedlibc_private.h';src=d/'wrappedlibc.c'
    (d/'generated').mkdir()
    (d/'generated/wrappedlibctypes.h').write_text('')
    defs.write_text('GO(__ctype_b_loc, pFv)\nGO(__ctype_tolower_loc, pFv)\nGO(__ctype_toupper_loc, pFv)\n',encoding='utf-8')
    src.write_text('#include <stdio.h>\n#include <pthread.h>\n#include <stdint.h>\n#define ANDROID\n#define EXPORT\ntypedef struct x64emu_s{int dummy;} x64emu_t;\n#include "generated/wrappedlibctypes.h"\n',encoding='utf-8')
    patch_android_glibc_ctype_loc(Path(tmp))
    text=defs.read_text()
    for symbol in ('__ctype_b_loc','__ctype_tolower_loc','__ctype_toupper_loc'):
        assert f'GOM({symbol}, pFEv)' in text, symbol
        assert f'GO({symbol}, pFv)' in text, symbol
    code=src.read_text()
    assert code.count('RM11_CTYPE_BRIDGE_V231')==2
    try: patch_android_glibc_ctype_loc(Path(tmp))
    except RuntimeError: pass
    else: raise AssertionError('Must refuse already patched source')
    cc=shutil.which('cc') or shutil.which('clang')
    if cc:
        # Compile actual C adapters with stub Box64 type and compare full C-locale
        # glibc table using host GNU libc as golden reference for 0..255.
        main=r'''
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <pthread.h>
#include <stdint.h>
extern const unsigned short int **__ctype_b_loc(void);
extern const int32_t **__ctype_tolower_loc(void);
extern const int32_t **__ctype_toupper_loc(void);
int main(void) {
  setlocale(LC_ALL, "C");
  const unsigned short **b=my___ctype_b_loc(NULL);
  const int32_t **lower=my___ctype_tolower_loc(NULL);
  const int32_t **upper=my___ctype_toupper_loc(NULL);
  if (!b || !*b || !lower || !*lower || !upper || !*upper) return 1;
  if (b!=my___ctype_b_loc(NULL) || lower!=my___ctype_tolower_loc(NULL)) return 2;
  for(int i=-128;i<=255;i++) {
    if ((*b)[i]!=(*__ctype_b_loc())[i]) {
      fprintf(stderr,"classification mismatch at %d (%04x != %04x)\n", i,(*b)[i],(*__ctype_b_loc())[i]);return 3;
    }
    if ((*lower)[i]!=(*__ctype_tolower_loc())[i]) {
      fprintf(stderr,"tolower mismatch at %d (%d != %d)\n",i,(*lower)[i],(*__ctype_tolower_loc())[i]);return 4;
    }
    if ((*upper)[i]!=(*__ctype_toupper_loc())[i]) {
      fprintf(stderr,"toupper mismatch at %d (%d != %d)\n",i,(*upper)[i],(*__ctype_toupper_loc())[i]);return 5;
    }
  }
  puts("PASS V2.3.1: glibc C-locale ctype 384 signed/unsigned entries and ABI");
  return 0;
}
'''
        src.write_text(code+'\n'+main)
        path=Path(tmp)/'ctype-test'
        subprocess.run([cc,'-std=c11','-Werror','-Wall','-Wextra','-pthread',str(src),'-o',str(path)],check=True,timeout=20)
        subprocess.run([str(path)],check=True,timeout=10)
    else:
        print('SKIP: C compiler unavailable')
print('PASS V2.3.1 ctype pinned patch, host ABI, compiled table comparison')
