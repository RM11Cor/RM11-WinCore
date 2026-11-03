"""Pinned, CI-only FEXCore v0.21 x86 register-cache liveness witness.

Print frontend GPR dirty/cached masks during the real SYSCALL lowering.
Does not change guest state, syscall arguments, JIT spill behavior or APK.
Intended to tell whether R8/R10 are already absent from the frontend cache
before any JIT physical ARM SRA register snapshot.
"""
from pathlib import Path
import subprocess
import sys

PIN="02e24ca5c01ed0c864466ed573db347336f70170"

def patch(root: Path) -> None:
    sha=subprocess.check_output(["git","-C",str(root),"rev-parse","HEAD"],text=True).strip()
    if sha!=PIN: raise ValueError("unpinned upstream FEXCore source")
    p=root/"FEXCore/Source/Interface/Core/OpcodeDispatcher.cpp"
    s=p.read_text()
    a="#include <cstdint>\n"
    if s.count(a)!=1: raise ValueError("cannot anchor cstdint header")
    s=s.replace(a,a+"#include <cstdio>\n",1)
    anchor="  FlushRegisterCache();\n  _Syscall();\n}\n"
    if s.count(anchor)!=1 or s.count("KERNIX v0.16 Android-only fix")!=1:
        raise ValueError("v0.16 syscall register bridge source not present")
    witness="""  // KERNIX v0.21 CI-only: the actual IR frontend cache state before
  // canonical FlushRegisterCache() lowers each dirty guest GPR.
  // The diagnostic is compile-time; actual runtime values are independently
  // recorded by the fixed x86 guest memory witness / host syscall callback.
  {
    const auto R8Bit = 1ULL << (GPR0Index + FEXCore::X86State::REG_R8);
    const auto R10Bit = 1ULL << (GPR0Index + FEXCore::X86State::REG_R10);
    std::fprintf(stderr,
      "KERNIX_V021_FRONTEND_GPR_DIRTY written=0x%llx cached=0x%llx r8_dirty=%u r10_dirty=%u r8_cached=%u r10_cached=%u\\n",
      static_cast<unsigned long long>(RegCache.Written),
      static_cast<unsigned long long>(RegCache.Cached),
      (RegCache.Written & R8Bit) ? 1U : 0U,
      (RegCache.Written & R10Bit) ? 1U : 0U,
      (RegCache.Cached & R8Bit) ? 1U : 0U,
      (RegCache.Cached & R10Bit) ? 1U : 0U);
    std::fflush(stderr);
  }
"""
    p.write_text(s.replace(anchor,witness+anchor,1))
    print("KERNIX_V021_CI_SYSCALL_FRONTEND_DIRTY_WITNESS_INSTALLED")

if __name__=="__main__":
    if len(sys.argv)!=2: raise SystemExit("usage: v021_frontend.py FEX_GIT_ROOT")
    patch(Path(sys.argv[1]))
