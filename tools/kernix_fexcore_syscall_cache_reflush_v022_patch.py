"""Pinned CI-only FEXCore x86-64 SYSCALL genuine register-cache reflush.

The preceding v0.21 ARM64 on-host investigation proved guest R8/R10 are
CACHED but not WRITTEN at the SYSCALL frontend boundary.  Test whether
forcing the existing live IR values through the normal fixed GPR writeout
and full JIT SRA spill repairs the actual host callback CPUState.

Do not package into Android before physical ARM64 callback + mmap passes.
No substituted guest constants or guest-memory witness is used as arguments.
"""
from pathlib import Path
import subprocess
import sys

PIN="02e24ca5c01ed0c864466ed573db347336f70170"

def patch(root: Path) -> None:
    sha=subprocess.check_output(["git","-C",str(root),"rev-parse","HEAD"],text=True).strip()
    if sha!=PIN: raise ValueError("unpinned upstream FEXCore source")
    front=root/"FEXCore/Source/Interface/Core/OpcodeDispatcher.cpp"
    jit=root/"FEXCore/Source/Interface/Core/JIT/BranchOps.cpp"
    s=front.read_text()
    original="""  // KERNIX v0.16 Android-only fix.  The generic FEX guest-register cache
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
    candidate="""  // KERNIX v0.22 CI-only: cached R8/R10 are not marked WRITTEN by the
  // ordinary guest code prior to SYSCALL. Mark their EXISTING live IR
  // values dirty so FlushRegisterCache binds both to real GPRFixed SRA
  // registers. No constants, guest stack, or fabricated syscall arguments.
  if (Is64BitMode) {
    StoreGPRRegister(X86State::REG_R10, LoadGPRRegister(X86State::REG_R10));
    StoreGPRRegister(X86State::REG_R8, LoadGPRRegister(X86State::REG_R8));
  }
"""
    if s.count(original)!=1: raise ValueError("required pinned v0.16 IR patch absent")
    front.write_text(s.replace(original,candidate,1))
    s=jit.read_text()
    original="""DEF_OP(Syscall) {
  // The two x86 syscall slots were written directly by the frontend IR.
  // Skip stale ARM64 SRA copies (x86 R8=x12, R10=x14) during spill.
  // For 32-bit int80 the original full register spill still applies.
  constexpr uint32_t KERNIX_SyscallStateSlots =
    (1U << ARMEmitter::Reg::r12.Idx()) | (1U << ARMEmitter::Reg::r14.Idx());
  if (CTX->Config.Is64BitMode()) {
    SpillStaticRegs(TMP1, {.GPRSpillMask = ~KERNIX_SyscallStateSlots});
  } else {
    SpillStaticRegs(TMP1);
  }
"""
    candidate="""DEF_OP(Syscall) {
  // KERNIX v0.22 CI-only: the frontend reflush creates GPRFixed writes,
  // so full canonical SRA spilling must be restored (including x12/x14).
  SpillStaticRegs(TMP1);
"""
    if s.count(original)!=1: raise ValueError("required pinned v0.16 JIT patch absent")
    jit.write_text(s.replace(original,candidate,1))
    print("KERNIX_V022_REGISTER_CACHE_REFLUSH_AND_FULL_SRA_SPILL_APPLIED")

if __name__=="__main__":
    if len(sys.argv)!=2: raise SystemExit("usage: v022 FEX_SOURCE_ROOT")
    patch(Path(sys.argv[1]))
