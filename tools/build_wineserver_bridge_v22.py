#!/usr/bin/env python3
"""Build NDK Android ARM64 PIE wineserver shim into APK nativeLibraryDir."""
from pathlib import Path
import subprocess
import sys
from build_native_exec import find_compiler, verify_elf
ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/'app/src/main/jniLibs/arm64-v8a/librm11wineserverbridge.so'
SRC=ROOT/'app/src/main/cpp/WineServerBridge.c'

def main():
    cc=find_compiler()
    if cc is None:
        if '--required' in sys.argv: raise SystemExit('FAIL: Android NDK required for V2.2 wineserver bridge')
        print('SKIP: NDK not local, Wine wineserver bridge built on GitHub')
        return
    OUT.parent.mkdir(parents=True,exist_ok=True)
    subprocess.run([str(cc),'-O2','-fPIE','-pie','-fstack-protector-strong',
                    '-Wl,-z,relro,-z,now',str(SRC),'-o',str(OUT)],check=True)
    verify_elf(OUT)
    print('PASS: ARM64 wineserver bridge PT_INTERP built')

if __name__=='__main__': main()
