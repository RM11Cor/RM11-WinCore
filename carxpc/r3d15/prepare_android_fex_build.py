#!/usr/bin/env python3
"""Repeat previously passing 42091689429 Bionic FEXCore build adapters."""
from pathlib import Path
import sys
if len(sys.argv)!=2: raise SystemExit("usage: prepare_android_fex_build.py /tmp/fex-src")
root=Path(sys.argv[1])
def unique(path,old,new):
    p=root/path
    s=p.read_text()
    n=s.count(old)
    assert n==1,(str(p),"UPSTREAM_ANDROID_PORT_ANCHOR_CHANGED",old[:90],n)
    p.write_text(s.replace(old,new,1))
unique("CMakeLists.txt",
    'elseif (NOT (WIN32 OR CMAKE_SYSTEM_NAME STREQUAL "Linux"))',
    'elseif (NOT (WIN32 OR CMAKE_SYSTEM_NAME STREQUAL "Linux" OR ANDROID))')
unique("CMakeLists.txt",
    'add_subdirectory(Source/)',
    '# R3D15: core-only Android AArch64 shared lib, no Linux executable frontend')
c=root/"FEXCore/Source/CMakeLists.txt"
s=c.read_text()
assert "AddLibrary(${PROJECT_NAME}_shared SHARED)" in s
assert "target_link_libraries(FEXCore_shared PRIVATE FEXCore_Base softfloat_3e)" not in s
c.write_text(s+"\n# Android Bionic fully linked original FEXCore deps, no stubs\n"
             "target_link_libraries(FEXCore_shared PRIVATE FEXCore_Base softfloat_3e)\n")
f=root/"FEXCore/Source/Utils/FileUtils.cpp"
s=f.read_text()
assert s.count("#include <unistd.h>")==1
s=s.replace("#include <unistd.h>", """#include <unistd.h>
#include <sys/syscall.h>
#ifdef __ANDROID__
static inline ssize_t kernix_android_getdents64(int fd, void* buffer, size_t bytes) {
  return ::syscall(__NR_getdents64, fd, buffer, bytes);
}
#endif""",1)
assert s.count('ssize_t read = getdents64(')==2
s=s.replace('ssize_t read = getdents64(',
            'ssize_t read = kernix_android_getdents64(')
f.write_text(s)
print("R3D15_ANDROID_FEX_UPSTREAM_BIONIC_PORT_SAME_AS_ACCEPTED_42091689429_PASS")
