# KERNIX G2-D — first cross-DSO x86 CALL/RET original-FEX fault diagnosis

**2026-11-04 — root cause identified; G2-D real-FEX validation is a separate
release gate. The already user-proven v0.22 Android G2-C APK is unchanged.**

## Observed, NOT speculative

[Failed real FEX Linux ARM64 run 41830017945](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41830017945)
captured the genuine native fault in an eight-second-bounded style
disposable CI process:

```text
KERNIX_G2D_DEBUG=FEX_CORE_INITIALIZED
KERNIX_G2D_DEBUG=FEX_X86_THREAD_READY
KERNIX_G2D_DEBUG=BEFORE_FEX_X86_CALL ...
Program received signal SIGSEGV
x25 = 0
si_addr = 0xfffffffffffffff0  [= -16]
```

The original FEX direct-entry G2-C tests in the same CI job still
**passed**; their MOV/HLT fixture does not use an x86 CALL or RET.
G2-D is the first fixture with a real ELF PLT `CALL` and an
independently linked x86 DSO provider `RET`.

## Source-derived mechanism

Upstream FEXCore's ARM64 JIT `BranchOps.cpp` uses a separate
**host call-return prediction stack** indexed by
`REG_CALLRET_SP` (AArch64 x25). It emits
`stp ... [REG_CALLRET_SP, -0x10]!` for x86 calls. Before G2-D's first
CALL, x25 was **zero**. The native fault at -16 is a precise
match for the missing call-return stack, not a corrupted libFEXCore
binary, DXVK, guest libc, Vulkan, or a wrong DT_NEEDED name.

An independently developed FEX integration also initializes both
`thread->CallRetStackBase` and
`thread->CurrentFrame->State.callret_sp`
with an anonymous RW shadow stack surrounded by PROT_NONE guard
pages, before beginning guest execution:
- [FEX upstream BranchOps.cpp](https://github.com/FEX-Emu/FEX/blob/main/FEXCore/Source/Interface/Core/JIT/BranchOps.cpp)
- [Bloodborne-Android reference FEX embedding](https://github.com/ducvd89/Bloodborne-Android/blob/master/cpu/guest_cpu_fex.cpp)

The KERNIX source fix is
`native-engine/android-host/kernix_g2d_real_fex_import_probe.cpp`:
`BoundedFEXCallRetStack` creates an anonymous RW stack with two
PROT_NONE guard pages, sets `thread->CallRetStackBase`, and initializes
`state.callret_sp` to the interior of the stack before
`context->ExecuteThread`. This is a **separate** Linux ARM64 CI-only
driver. The signed Android v0.22 CPU proof remains untouched.

## Remaining release gate

**All three gates now PASS** in
[original FEX native Linux ARM64 run 41830448479](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41830448479).
The exact original MIT x86 guest external function was called by FEX,
returned to the main x86 code, and reached
`RAX=0x4b45524e49584731` with process exit 0.
The successful run logged
`KERNIX_G2D_DEBUG=FEX_GUARDED_CALLRET_SHADOW_STACK_INITIALIZED`
before the new JIT x86 call. This verifies the specific initial
CALLRET shadow-stack fix without claiming any generic dynamic linker
or Android device execution.

The three required success criteria were:
1. The real GNU x86 PLT slot resolves to the external, SHA-pinned
   provider DSO's imported function with one valid
   `R_X86_64_JUMP_SLOT` relocation and a read-only GOT.
2. FEX JIT executes the x86 call/ret, using the initialized x25
   call-return stack, returns to the main _start, and exits cleanly.
3. Actual guest RAX becomes
   `0x4b45524e49584731` with no syscall, no Android guest code,
   no Linux dynamic interpreter startup and no Wine/game.

The Linux ARM64 FEX test now passes; **Android G2-D execution remains
unverified**. A separate Android Bionic source cross-link has been
added as a hard-exit-126 BUILD ONLY gate. A new signed Android test
APK must still be independently qualified and verified before any
user device trial.
