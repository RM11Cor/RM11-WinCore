"""Pinned KERNIX Android-only FEXCore x86-64 syscall register ABI patch.

The original FEXCore revision is kept unchanged in source lock.  A patch is
applied to the throwaway NDK clone so two register argument values become
observable to the host callback even if RA treats their SRA bindings as dead.
Never synthesize mmap flags or fd; use only live x86 guest IR values.

Applies ONLY to the pinned upstream commit with exact source anchors.
"""
from pathlib import Path
import re
import subprocess
import sys

PIN = "02e24ca5c01ed0c864466ed573db347336f70170"

def patch(root: Path):
    sha=subprocess.check_output(["git","-C",str(root),"rev-parse","HEAD"],text=True).strip()
    if sha != PIN:
        raise ValueError("unpinned FEXCore commit; refusing ABI patch")
    front=root/"FEXCore/Source/Interface/Core/OpcodeDispatcher.cpp"
    jit=root/"FEXCore/Source/Interface/Core/JIT/BranchOps.cpp"
    mapping=root/"FEXCore/Source/Interface/Core/ArchHelpers/Arm64Emitter.cpp"
    # The SRA array is x86 register order; x86 R8 -> x12 and R10 -> x14.
    s=mapping.read_text()
    m=re.search(r"namespace x64 \{\s*#ifndef ARCHITECTURE_arm64ec.*?constexpr std::array<ARMEmitter::Register, 18> SRA\s*=\s*\{(.*?)\};",s,re.S)
    if not m:
        raise ValueError("FEX x64 SRA mapping not found")
    regs=re.findall(r"ARMEmitter::Reg::r(\d+)",m.group(1))
    if len(regs)!=16 or regs[8]!="12" or regs[10]!="14" or "REG_PF" not in m.group(1) or "REG_AF" not in m.group(1):
        raise ValueError("FEX syscall R8/R10 register mapping changed")

    src=front.read_text()
    anchor="  FlushRegisterCache();\n  _Syscall();\n}\n"
    if src.count(anchor)!=1:
        raise ValueError("pinned SYSCALL frontend anchor mismatch")
    replacement="""  // KERNIX v0.16 Android-only fix.  The generic FEX guest-register cache
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
  FlushRegisterCache();
  _Syscall();
}
"""
    front.write_text(src.replace(anchor,replacement,1))

    src=jit.read_text()
    anchor="DEF_OP(Syscall) {\n  SpillStaticRegs(TMP1);\n"
    if src.count(anchor)!=1:
        raise ValueError("pinned SYSCALL JIT spill anchor mismatch")
    replacement="""DEF_OP(Syscall) {
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
    jit.write_text(src.replace(anchor,replacement,1))
    print("KERNIX_PINNED_X86_SYSCALL_R10_R8_IR_TO_CONTEXT_ABI_PATCH_APPLIED")

if __name__=="__main__":
    if len(sys.argv)!=2: raise SystemExit("usage: patch.py UPSTREAM_GIT_ROOT")
    patch(Path(sys.argv[1]))
