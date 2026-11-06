# KERNIX G0 — real GNU ld-linux post-cache unaligned ARM64 LDAR; embedded-FEX SIGBUS TSO backpatch gate

**Date:** 2026-11-06. **Branch:** `kernix-native-engine-v1` only.

## Proven actual blocker, not another guessed Linux syscall

The exact SHA256 source original x86 main, `ld-linux-x86-64.so.2`, and `libc.so.6` under original FEXCore ARM64 have completed the prior fixture syscall stream, then genuine unmodified GNU loader guest `brk(12)`, `access(21)` and optional `openat(257)` paths.

- [Actual original guest syscall progression #42264033595](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42264033595) SUCCESS **as an observation**; next event SIGBUS, not a new x86 syscall.
- [Native ARM64 GDB on real unmodified GNU ld-linux #42265011400](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42265011400) SUCCESS **as an observation**, original FEX generated ARM64 instruction at native PC `0xffffa4c75124`:
  `ldar x7, [x20]`. Native `x20=0x8000004a9`, `si_addr=0x8000004a9`, `SIGBUS si_code=1 (BUS_ADRALN)`. x20 is **not 8-byte aligned**, whereas AArch64 `LDAR` requires proper alignment. This is a native ARM64 JIT memory-ordering fault, not evidence of an invalid x86 source ELF pointer or missing source filesystem entry.
- The original direct `FEXCore::SignalDelegator` is **only the abstract/base contract** (upstream pinned `FEXCore/include/FEXCore/Core/SignalDelegator.h`). The real Linux userspace frontend's `FEX::HLE::SignalDelegator` (`Source/Tools/LinuxEmulation/LinuxSyscalls/SignalDelegator.{h,cpp}`) owns actual host `sigaction`, registered signals, altstack, backpatch and guest signal state. Our standalone embedded FEX host has so far instantiated only the base contract, with no equivalent host `SIGBUS` backpatch setup.
- [FEX official Memory Model Emulation](https://github.com/FEX-Emu/FEX/blob/main/FEXCore/docs/MemoryModelEmulation.md) documents intentionally emitted memory-model acquire loads and **backpatch to regular load plus barrier on unaligned fault**.
- [FEX official signals debugging](https://wiki.fex-emu.com/index.php/Development:Debugging_FEX_with_Signals) explicitly calls out JIT SIGBUS unaligned load/store backpatch.

## Required engineering repair: retain x86 memory ordering and integrate real fault handling

**DO NOT** fake-align guest source pointer, alter original ELF/source symbol, patch original GNU loader, turn a native fault into success, or globally disable x86 TSO in a production game engine. Misaligned x86 byte/word/dword/qword loads are legal and must be translated correctly. Real `SIGBUS` requires the **upstream FEX AArch64 memory-model unaligned exception handler/backpatch**, with signal-safe host `sigaction` and thread ownership, correct native AArch64 JIT PC mapping, proper context access, and a safe asynchronous-signal stack. SIGBUS from an owned original source ELF JIT page should be resolved by FEX; unrelated memory faults must remain fatal and fail closed.

Temporary **single-thread Linux differential only** uses `KERNIX_G0_DIAGNOSTIC_DISABLE_TSO_ONLY` to disable `CONFIG_TSO_ENABLED` in this test executable only. This can establish causality (unaligned native `LDAR` disappears) but is never an acceptable final solution because it can violate multithreaded x86 memory-ordering semantics. The test cannot be used as full GNU loader PASS unless original loader itself truly proves relocation completion.

- The initial single-process differential [run #42268547633](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42268547633) **FAILED at compile**, because the pinned FEX configuration enum is `CONFIG_TSOENABLED`, not `CONFIG_TSO_ENABLED`. The source-only diagnostic fix is commit `a8389186c10601c2d07030f4a4e5e0aec32fed81`.
- [Corrected real ARM64 TSO-disabled comparison #42270297887](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42270297887) **completed SUCCESS**. It compiled with the pinned original FEX source, verified original three ELF SHA256 identities, observed actual unmodified GNU loader guest `brk(12)`, `access(21)`, `openat(257)` and diagnostic TSO-off marker; GDB returned exit code 0 instead of the prior native unaligned `LDAR` SIGBUS. This is strong causal differential evidence only: no relocation-completion proof, no safe production memory model. The test is not a signed phone APK.
- The source-backed upstream signal integration path was independently located at pinned FEX `Source/Tools/LinuxEmulation/LinuxSyscalls/SignalDelegator.cpp` (SIGBUS / `BUS_ADRALN` JIT check), which calls `FEXCore::ArchHelpers::Arm64::HandleUnalignedAccess(... HalfBarrier ...)` in `FEXCore/Source/Utils/ArchHelpers/Arm64.cpp`. That original function backpatches an unaligned `LDAR` into `LDR` plus the original half-barrier `DMB_LD` and invalidates the host I-cache before retry; it is **not** the bare base `FEXCore::SignalDelegator`.
- A separate **Linux ARM64 CI-only** experiment now wires the original upstream FEX helper with TSO ON via a dedicated host `SIGBUS` alternate-stack handler, JIT address and `BUS_ADRALN` checks, fail-closed unrelated faults, and proof markers. Source commit `3a2d18ea96a993fd6eb1e5a1f80dc1b53fad85ae`; [run #42271329907](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42271329907). **Do not claim PASS before that run actually passes**, including the guest progression evidence. The isolated handler is diagnostic, not reviewed for production signal lifecycle/concurrency/Android.

## Exit criteria before proceeding to further loader syscalls

1. Normal TSO enabled, original FEX source pinned; run same unmodified original loader guest program and reproduce unaligned translated 64-bit memory load.
2. Embedded FEX native host registers the **actual upstream unaligned loadstore SIGBUS backpatch handler**, not a no-op `SignalDelegator`.
3. Source guest bytes unchanged; native FEX JIT performs the valid guest x86 unaligned load and continues *past* `0x8000004a9`, with independently evidenced registered handler invocation / altered native JIT code where appropriate.
4. Complete earlier `brk/access/openat` and original ELF `RELA/RELR` fixture tests without regression, no executable writable guest page, no guest pointer forwarded to host.
5. Only after true TSO-enabled embedded-FEX Linux ARM64 runtime PASS is the exact source cross-linked for Android/Bionic. Native 16KiB host pages remain unsupported until 4KiB guest subpage ownership is implemented.
6. This **is not** an installable APK, full original GNU dynamic loader/glibc initialization, Wine/Proton or any PC game. Preserve stable KERNIX v0.27, signed `org.kernix.diagnostics` v2 identity and all user game data.
