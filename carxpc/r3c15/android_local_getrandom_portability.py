#!/usr/bin/env python3
"""Strict Android-Bionic portability shim for Linux ARM64 source test:
replace only local native getrandom call with same kernel syscall through
Bionic; NEVER forward a guest x86 pointer, never edit original guest ELFs.
"""
from pathlib import Path
import sys
p=Path(sys.argv[1])
s=p.read_text()
needle='#include <sys/random.h>\n#include <unistd.h>'
assert s.count(needle)==1,("unexpected pinned header includes",p)
s=s.replace(needle,'#include <sys/random.h>\n#include <sys/syscall.h>\n#include <unistd.h>',1)
needle='  const auto got=::getrandom(trustedLocal.data(),trustedLocal.size(),GRND_NONBLOCK);'
assert s.count(needle)==1,("unexpected source kernel call",p)
s=s.replace(needle,
'''#if defined(__ANDROID__)
  // Android NDK api26 does not declare glibc's ::getrandom().
  // Use the same AArch64 host kernel syscall on a trusted LOCAL buffer.
  // Guest destination is authenticated and populated only after success.
  const auto got=::syscall(__NR_getrandom,trustedLocal.data(),
                            trustedLocal.size(),GRND_NONBLOCK);
#else
  const auto got=::getrandom(trustedLocal.data(),trustedLocal.size(),GRND_NONBLOCK);
#endif''',1)
p.write_text(s)
assert s.count('::syscall(__NR_getrandom')==1
print('CARX_R3C15_BIONIC_GETRANDOM_TRUSTED_LOCAL_BUFFER_COMPAT_SOURCE_PATCH_PASS')
