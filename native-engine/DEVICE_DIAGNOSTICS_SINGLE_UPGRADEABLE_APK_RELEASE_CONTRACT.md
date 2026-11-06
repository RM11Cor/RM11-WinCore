# KERNIX device diagnostics — one upgradeable Android package contract

## Decision: no more one-icon-per-opcode tests

User has confirmed old C3-D3..C3-D8C6 / G1 / G0 independent
diagnostic APKs may be uninstalled after their on-device evidence was
recorded. Those APKs served bounded acceptance gates; they were **not**
the stable emulator.

Starting with the next **functional, Linux-ARM64-proven** Android
runtime gate, new phone tests should be delivered through a single
long-lived application ID, proposed:

\`org.kernix.diagnostics\` (separate from stable KERNIX's package).

- One launcher icon: **KERNIX Diagnostics**. No additional app icons
  for each G0 ld-linux subtest or graphics frame count.
- Initial install once; subsequent signed APKs use the **same**
  package/application ID, identical original verified signing
  certificate, and **monotonically incremented versionCode** so
  Android's ordinary APK installer updates in place.
- The program must **not claim** cloud/automatic background updates.
  Installation of a newer APK is a user-controlled action.
- Primary display = **latest actionable diagnostic stage**;
  prior completed stages may be displayed as **historical read-only
  evidence**, NOT re-run without regression justification.
- Latest stage's native child is paired with an immutable, source
  witnessed SHA256 manifest; exact Linux guest ELF files and FEX
  library digests verified before execution. No runtime downloads,
  network or arbitrary EXE selection.
- One opt-in button, watchdog timeout, captured capped output,
  output marker-order validation, clear error/status, no root, no
  shared-storage modification, no persistent child processes, and
  explicit "NOT Linux full loader/NOT Wine/NOT games" on probes.
- Continue using **one original source-verified FEX + the pre-existing
  C3-D7B/C3-D7G host-owned guest memory model**. Avoid parallel
  implementations.
- On host 16K page devices, deny unsafe 4K guest page assumptions
  unless independent software subpage protection is actually proven.
- Existing KERNIX v0.27 stable application, installed game folders
  and prefixes remain untouched. Never use the stable package ID as
  diagnostic target or attempt in-place downgrade.
- Each device PASS requires a user-submitted actual Android process
  screenshot / export and an immutable build/run/source evidence JSON
  in \`native-engine/evidence/\`. A green GitHub Action/Android APK
  build does NOT count as execution on the phone.

## Existing bounded stages preserved (no repeat required)

1. Actual original FEX G0 x86 Linux \`pread64\` and genuine ldso
   header guest byte read: Android screen PASS.
2. Actual source-authentic FEX G0 x86 \`mmap\`, guest store/load, and
   \`munmap\`, native owner-held page release: Android screen PASS.
3. Original source SHA Linux ELF PT_LOAD + genuine AUXV + true FEX
   mmap/store/load/munmap in one native process: Android screen PASS.
4. Original \`ld-linux\` PT_INTERP first exact original source MOV
   instruction after guest heap syscalls in the same FEX context;
   source PT_LOAD bytes restored, bounded HLT: Android screen PASS.
5. Earlier G1 180-frame and Surface/Swapchain device probes are
   strictly bounded visual/presentation evidence; neither game
   renderer nor full Vulkan runtime was proved.

### Current unreleased integration gate

- **Linux ARM64:** original \`ld-linux\` source \`MOV\` plus source
  \`CALL rel32\` after real original FEX x86 heap guest syscalls
  in a *single* process, with correct native guarded host callret
  stack, guest return RIP, original target bounded HLT,
  W^X restoration, and all guest windows freed.
- Initial strict Clang constructor ordering fixed in
  \`d31e935894357f72fa97bd86033637e18d2a98b4\`.
- [CI #42097578226](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42097578226)
  compiled, but **segfaulted at actual execution**, NOT PASS. The
  original stderr artifact had no app-emitted stage marker before
  \`timeout\` reported a core dump.
- Source \`native-engine/android-host/tests/kernix_g0_original_elf_heap_then_ldso_mov_call_bounded_arm64.cpp\`
  now instruments exact phase markers without altering guest CPU
  state, source bytes, mmap policy or runtime logic.
- Live diagnostic CI:
  [#42156774041](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42156774041)
  started at the time this contract was authored. Its result must be
  inspected rather than guessed.
- **Do not publish yet another standalone diagnostic APK** or assign
  the new app package a fake runtime pass. First close the actual
  Linux ARM64 segfault at a verified narrow stage, then require
  Android/Bionic cross-link PASS, then prepare the unified
  updateable signed Android app.

## Definitive release acceptance checklist

The exact proposed \`org.kernix.diagnostics\` package may first ship
only after all conditions are proven in the same build pipeline:
(1) actual source-pinned original FEX Linux ARM64 functional PASS,
(2) original FEX Android/Bionic cross-link PASS,
(3) original source ELF and guest SHA256 witness match,
(4) original certificate signing and APK payload digest verification,
(5) versionCode strictly greater than previous diagnostics release
(or 1 on first install),
(6) all Java failure handling and native process isolation verified,
(7) release declares on-phone execution **PENDING**, never PASS.
User must then run exactly one specific test on their REDMAGIC
Android device and send its actual result.

Until (1) and (2) are proven, the latest archived signed APK remains
only a previously bounded diagnostic; a new APK would create
unnecessary clutter and false confidence.
