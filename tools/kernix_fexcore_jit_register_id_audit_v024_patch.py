"""KERNIX v0.24: CI-only register-allocation ID evidence for pinned FEXCore.

The v0.23 test incorrectly treated GPRFixed.Reg as an x86 register ID and
checked JIT-compile-time diagnostics as if they were host callback values.
Do not write or synthesize guest CPUState here. Capture the actual IR fixed
register and assigned ARM64 source/destination IDs at JIT emission, then
compare with real guest stack and syscall callback state independently.
This diagnostic is not an Android runtime repair.
"""
from pathlib import Path
import subprocess
import sys

PIN = "02e24ca5c01ed0c864466ed573db347336f70170"


def patch(root: Path) -> None:
    actual = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    if actual != PIN:
        raise ValueError("unpinned upstream FEXCore source")

    mem_path = root / "FEXCore/Source/Interface/Core/JIT/MemoryOps.cpp"
    src = mem_path.read_text()
    anchor = """  if (RegClass == IR::RegClass::GPRFixed) {
    // Always use 64-bit, it's faster. Upper bits ignored for 32-bit mode.
    mov(ARMEmitter::Size::i64Bit, GetReg(Reg), GetReg(Op->Value));
  } else if (RegClass == IR::RegClass::FPRFixed) {"""
    replacement = """  if (RegClass == IR::RegClass::GPRFixed) {
    // KERNIX v0.24: compile-time JIT emission diagnostic, not runtime
    // guest register evidence. Reg.Reg is the IR physical fixed-register
    // index; do not equate it with an x86 architectural register ID.
    const auto Src = GetReg(Op->Value);
    const auto Dest = GetReg(Reg);
    std::fprintf(stderr,
                 "KERNIX_V024_JIT_GPRFIXED_EMIT ir_fixed=%u arm_dst=%u arm_src=%u\\n",
                 static_cast<unsigned>(Reg.Reg), Dest.Idx(), Src.Idx());
    mov(ARMEmitter::Size::i64Bit, Dest, Src);
  } else if (RegClass == IR::RegClass::FPRFixed) {"""
    if src.count(anchor) != 1:
        raise ValueError("pinned JIT StoreRegister anchor changed")
    header = '#include "FEXCore/Core/X86Enums.h"'
    if src.count(header) != 1:
        raise ValueError("pinned JIT MemoryOps include anchor changed")
    mem_path.write_text(
        src.replace(header, header + "\n#include <cstdio>", 1)
        .replace(anchor, replacement, 1)
    )

    branch_path = root / "FEXCore/Source/Interface/Core/JIT/BranchOps.cpp"
    src = branch_path.read_text()
    anchor = """DEF_OP(Syscall) {
  // KERNIX v0.22 CI-only: the frontend reflush creates GPRFixed writes,
  // so full canonical SRA spilling must be restored (including x12/x14).
  SpillStaticRegs(TMP1);
"""
    replacement = """DEF_OP(Syscall) {
  // KERNIX v0.24: clearly label this as JIT emission-time evidence.
  // The unchanged CPUState callback is the only runtime correctness gate.
  std::fprintf(stderr, "KERNIX_V024_JIT_SYSCALL_EMIT full_static_spill=1\\n");
  SpillStaticRegs(TMP1);
"""
    if src.count(anchor) != 1:
        raise ValueError("v0.22 full-spill Syscall anchor changed")
    header = '#include <FEXCore/Core/X86Enums.h>'
    if src.count(header) != 1:
        raise ValueError("pinned JIT BranchOps include anchor changed")
    branch_path.write_text(
        src.replace(header, header + "\n#include <cstdio>", 1)
        .replace(anchor, replacement, 1)
    )
    print("KERNIX_V024_JIT_REGISTER_ID_AUDIT_PATCH_APPLIED")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: patch.py PINNED_FEX_SOURCE_ROOT")
    patch(Path(sys.argv[1]))
