"""Pinned native ARM64 CI-only FEX JIT GPRFixed -> CPUState witness (v0.23).

Apply AFTER the locked v0.16 patch and v0.22 genuine cached register reflush.
R10 and R8 have been shown correct in guest stack stores but incorrect in the
syscall frame. Capture actual RA-assigned StoreRegister values directly from
the JIT's physical input register and prevent subsequent stale SRA spills from
overwriting the two state slots. Never supply literal flags/fd/argument values.

This is NOT a general or validated engine repair until live ARM64 tests pass.
"""
from pathlib import Path
import subprocess
import sys

PIN = "02e24ca5c01ed0c864466ed573db347336f70170"

def patch(root: Path) -> None:
    if subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip() != PIN:
        raise ValueError("unpinned upstream FEXCore commit")
    memory = root / "FEXCore/Source/Interface/Core/JIT/MemoryOps.cpp"
    branch = root / "FEXCore/Source/Interface/Core/JIT/BranchOps.cpp"
    mem=memory.read_text()
    anchor="""  if (RegClass == IR::RegClass::GPRFixed) {
    // Always use 64-bit, it's faster. Upper bits ignored for 32-bit mode.
    mov(ARMEmitter::Size::i64Bit, GetReg(Reg), GetReg(Op->Value));
  } else if (RegClass == IR::RegClass::FPRFixed) {"""
    candidate="""  if (RegClass == IR::RegClass::GPRFixed) {
    // Always use 64-bit, it's faster. Upper bits ignored for 32-bit mode.
    const auto Src=GetReg(Op->Value);
    mov(ARMEmitter::Size::i64Bit, GetReg(Reg), Src);

    // KERNIX v0.23: diagnostic only. Store the true register allocator
    // source as it is materialized. This bypasses IR _StoreContext lowering.
    // The subsequent Syscall spill excludes these two fields ONLY for this
    // disposable native test so it cannot overwrite the witness.
    if (CTX->Config.Is64BitMode() && Reg.Reg == FEXCore::X86State::REG_R10) {
      str(Src.X(), STATE.R(), offsetof(FEXCore::Core::CpuStateFrame, State.gregs[FEXCore::X86State::REG_R10]));
      std::fprintf(stderr, "KERNIX_V023_RA_GPRFIXED_STORE reg=R10 dst=x%u src=x%u\\n",
                   GetReg(Reg).Idx(), Src.Idx());
    }
    if (CTX->Config.Is64BitMode() && Reg.Reg == FEXCore::X86State::REG_R8) {
      str(Src.X(), STATE.R(), offsetof(FEXCore::Core::CpuStateFrame, State.gregs[FEXCore::X86State::REG_R8]));
      std::fprintf(stderr, "KERNIX_V023_RA_GPRFIXED_STORE reg=R8 dst=x%u src=x%u\\n",
                   GetReg(Reg).Idx(), Src.Idx());
    }
  } else if (RegClass == IR::RegClass::FPRFixed) {"""
    if mem.count(anchor) != 1:
        raise ValueError("v0.23 JIT StoreRegister source anchor mismatch")
    if mem.count('#include "FEXCore/Core/X86Enums.h"')!=1:
        raise ValueError("missing FEXCore X86 register enum header")
    memory.write_text(mem.replace('#include "FEXCore/Core/X86Enums.h"',
                           '#include "FEXCore/Core/X86Enums.h"\n#include <cstdio>',1).replace(anchor,candidate,1))

    s=branch.read_text()
    original="""DEF_OP(Syscall) {
  // KERNIX v0.22 CI-only: the frontend reflush creates GPRFixed writes,
  // so full canonical SRA spilling must be restored (including x12/x14).
  SpillStaticRegs(TMP1);
"""
    replacement="""DEF_OP(Syscall) {
  // KERNIX v0.23 CI-only: GPRFixed R8/R10 were captured on the true
  // source-register StoreRegister path above, so skip their SRA spill only.
  constexpr uint32_t KERNIX_StoreWitnessSRA =
      (1U << ARMEmitter::Reg::r12.Idx()) | (1U << ARMEmitter::Reg::r14.Idx());
  if (CTX->Config.Is64BitMode()) {
    SpillStaticRegs(TMP1, {.GPRSpillMask = ~KERNIX_StoreWitnessSRA});
  } else {
    SpillStaticRegs(TMP1);
  }
"""
    if s.count(original)!=1: raise ValueError("v0.22 full-spill JIT source anchor mismatch")
    branch.write_text(s.replace(original,replacement,1))
    print("KERNIX_V023_CI_GPRFIXED_PHYSICAL_SOURCE_CAPTURE_APPLIED")

if __name__=="__main__":
    if len(sys.argv)!=2: raise SystemExit("usage: patch.py PINNED_FEX_SOURCE_ROOT")
    patch(Path(sys.argv[1]))
