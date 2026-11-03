"""CI-only FEXCore physical-ARM-SRA-to-CPUState syscall diagnostic.

Apply after the exact pinned v0.16 Android-only patch in a throwaway native
ARM64 GitHub runner. Do not package this test in Android KERNIX.
Samples the actual ARM static registers x14 (guest x86 R10) and x12 (R8)
directly at the point the JIT transfers to its syscall callback. This tests
whether the IR frontend or JIT's static-register state is stale.
"""
from pathlib import Path
import subprocess
import sys

PIN = "02e24ca5c01ed0c864466ed573db347336f70170"

def patch(root: Path) -> None:
    if subprocess.check_output(["git","-C",str(root),"rev-parse","HEAD"],text=True).strip() != PIN:
        raise ValueError("unsupported FEX source commit")
    path = root / "FEXCore/Source/Interface/Core/JIT/BranchOps.cpp"
    s = path.read_text()
    anchor = """  // Jump to the syscall dispatch handler. We won't return after this.
  ldr(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.ThreadDispatchSyscallHandler));"""
    # The v0.16 source has exactly two references: declaration + mask use.
    # Requiring one wrongly rejected the correctly patched source before CMake.
    if s.count(anchor) != 1 or s.count("KERNIX_SyscallStateSlots") != 2:
        raise ValueError("expected pinned v0.16 syscall spill structure not found")
    code = """  // KERNIX v0.20 CI-only ARM SRA witness, no guest argument constants.
  // The pinned x86->ARM mapping is R10=x14 and R8=x12. Record machine
  // register values immediately before leaving JIT, bypassing IR loads.
  // This overwrites the v0.16 IR capture ONLY in this disposable test.
  str(ARMEmitter::Reg::r14.X(), STATE.R(),
      offsetof(FEXCore::Core::CpuStateFrame, State.gregs[FEXCore::X86State::REG_R10]));
  str(ARMEmitter::Reg::r12.X(), STATE.R(),
      offsetof(FEXCore::Core::CpuStateFrame, State.gregs[FEXCore::X86State::REG_R8]));

"""
    path.write_text(s.replace(anchor,code+anchor,1))
    print("KERNIX_V020_CI_DIRECT_ARM_SRA_SYSCALL_CAPTURE_APPLIED")

if __name__ == "__main__":
    if len(sys.argv) != 2: raise SystemExit("usage: script.py FEX_SOURCE_ROOT")
    patch(Path(sys.argv[1]))
