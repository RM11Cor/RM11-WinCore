"""Isolated ARM64 A/B candidate: move real x86 R10/R8 IR captures before
x86 SYSCALL's RCX/R11/RFLAGS emulation.

Apply only AFTER the pinned v0.16 patch against the locked FEXCore revision.
This is for CI investigation, NOT the distributable Android APK.
"""
from pathlib import Path
import re
import subprocess
import sys

UPSTREAM_SHA = "02e24ca5c01ed0c864466ed573db347336f70170"

def patch(root: Path):
    if subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"],
                               text=True).strip() != UPSTREAM_SHA:
        raise ValueError("refuse unpinned FEXCore commit")
    front = root / "FEXCore/Source/Interface/Core/OpcodeDispatcher.cpp"
    s = front.read_text()
    opening = "  if (IsSyscallInst) {\n"
    capture = """  // KERNIX v0.16 Android-only fix.  The generic FEX guest-register cache
  // may keep an x86 syscall argument as an SSA value and not materialize
  // its static ARM64 register until after the host callback.  Snapshot the
  // true guest R10/R8 IR values into their CPUState slots before syscall.
  // The paired JIT patch deliberately skips spilling those two stale SRA
  // registers so the independently written state slots are not overwritten.
  if (Is64BitMode) {
    _StoreContextGPR(OpSize::i64Bit, LoadGPRRegister(X86State::REG_R10),
                     offsetof(FEXCore::Core::CPUState, gregs[X86State::REG_R10]));
    _StoreContextGPR(OpSize::i64Bit, LoadGPRRegister(X86State::REG_R8),
                     offsetof(FEXCore::Core::CPUState, gregs[X86State::REG_R8]));
  }
"""
    if s.count(capture) != 1 or s.count(opening) != 1:
        raise ValueError("v0.16 capture or syscall anchor changed")
    old = s.index(opening)
    old_capture = s.index(capture)
    if old_capture <= old or s.index("  FlushRegisterCache();", old) <= old_capture:
        raise ValueError("not v0.16 after flags: fail closed")
    # Preserve guest R10/R8 as live IR values before computing RFLAGS and
    # writing guest R11/RCX. Do not inject hard-coded guest register values.
    s = s.replace(capture, "", 1)
    s = s.replace(opening, capture.replace("v0.16 Android-only fix",
                     "v0.19 A/B early-register-capture candidate") + opening, 1)
    if not (s.index("v0.19 A/B early-register-capture candidate") <
            s.index(opening) < s.index("  FlushRegisterCache();")):
        raise ValueError("early capture insertion failed")
    front.write_text(s)
    print("KERNIX_V019_SYSCALL_EARLY_REAL_GPR_CAPTURE_APPLIED")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: early_capture.py PINNED_FEX_CLONE")
    patch(Path(sys.argv[1]))
