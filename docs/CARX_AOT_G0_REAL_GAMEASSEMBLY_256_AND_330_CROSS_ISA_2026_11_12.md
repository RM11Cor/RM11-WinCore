# CarX Street x64 to ARM64 AOT – 256 real source samples and 330 comparisons

Checkpoint date 2026-11-12. Project branch carx-street-pc-port-v1.

## Source ground truth – the owner's exported original PC GameAssembly

Input is the small user-owned Android PortLab v1.0 ZIP held in a private
workspace, never placed in GitHub:

- SHA256 ZIP: 6bbde5cfaaaccb27ea12cda1be31ee0afc6975e49d019a9650d58355a7dc68d8
- GameAssembly.dll original PE x86-64 bytes: 142,049,792.
- Win64 exception table entries reported: 412,001.
- Executable regions 4–320 bytes eligible: 341,700.
- Exported sample regions: 256, 33,153 bytes of code.
- All 256 per-region SHA256 values matched their original manifest.
- No original proprietary bytes, machine-code disassemblies or
  translated code files are checked into this public repository.

Read-only GNU objdump structural audit (linear decoding, NOT a CFG or
original game execution) observed overlapping source features:

- 238/256 contain calls to targets outside the tiny fragment, including
  indirect calls.
- 134/256 reference RIP-relative memory and external PE data.
- 80/256 include SIMD/XMM/vector instruction families.
- 112/256 have no decoded RET.
- 82/256 contain INT3 padding/guards.
- 38/256 include MOVZX, MOVSX or MOVSXD extension operations.

A coarse isolation filter found 9 fragments with a RET and without
obvious calls/relocations/vector operations. Inspection found these
to be predominantly prologue-free EPILOGUES restoring Win64 stack,
not verified callable Unity/IL2CPP methods. Several longer fragments
contain indirect calls. Therefore the first true GameAssembly function
G0 gate is still OPEN. The owner does NOT need to resubmit the same ZIP.

## Real source-driven recompiler expansion completed

The build-time x86-64 to native AArch64 function-level recompiler
native-port/recompiler/x64_function_aot.py was expanded to support:

- 8-bit low registers AL/CL/DL/etc and high byte AH/BH/CH/DH,
  with correct preservation of all untouched bits.
- 16-bit AX/CX/DX/etc and R8W-R15W, preserving high GPR bits.
- 32-bit writes zero-extend to the full 64-bit register.
- Scalar 8-/16-/32-/64-bit stack memory reads and writes.
- MOVZX, MOVSX, MOVSXD with signed/zero extension.
- Arithmetic flags appropriate to actual width for ADD/SUB,
  AND/OR/XOR/CMP/TEST/INC/DEC.
- Full semantic rejection of yet unsupported vector, external
  call, indirect jump, Win64 SEH, RIP-relative global data operations.

Tested against real machine-code reference execution in GitHub
Actions #43220923792: 33 deliberately SYNTHETIC Windows x64 ABI
functions × 10 separate input vectors = **330/330 matching outputs**.
Cross-compilation uses aarch64-linux-gnu-g++; QEMU runs the ARM64
binary only inside CI, not on the owner's Android device or a
finished native port. The compiled AArch64 program does NOT contain
FEX/Wine/x86 decode machinery.

This is meaningful static compiler progress, NOT an original CarX
gameplay function successfully recompiled to Android.

## Actual technical next gate

The original Android v1.0 extraction chose random short Win64 PE
RUNTIME_FUNCTION ranges. This is the wrong unit of translation for
most original IL2CPP code because it can capture chained UNWIND_INFO,
cold fragments, jump thunks or mere stack epilogues.

The next engineering unit is a *genuine complete callable function*:
(1) recover Win64 UNWIND_INFO, chained entries and boundaries;
(2) construct a real x86 instruction CFG and resolve local calls;
(3) bind RIP-relative original PE data with address bounds and
relocations; (4) only then run reference-equivalent original code
and compile the exact verified behavior to AArch64; (5) build an
Android NDK/Bionic native target after test proof.

Until the source region corresponds to a genuine complete original
function, a successful conversion of a RET/stack epilogue **does not
count** as executing CarX gameplay code. Avoid another cosmetic
metadata inspector APK. Any next app version must actually provide
the original Win64 unwind and dependency evidence needed to move G0.
