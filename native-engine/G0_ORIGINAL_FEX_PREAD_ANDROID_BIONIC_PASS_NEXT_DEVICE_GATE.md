# KERNIX G0 — verified Android/Bionic original FEX guest pread64 bridge

## Accepted results

- **Linux ARM64 actual x86 guest execution PASS**: GitHub Actions
  [42077098127](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42077098127).
  Source-pinned genuine upstream FEXCore and exact SHA256 original x86-64
  `ld-linux-x86-64.so.2`: x86 guest executed `pread64(17)` through
  authenticated live FEX CpuStateFrame, received original ELF bytes in a
  registered writable guest interval, and executed an x86 `movzbl`
  yielding actual ELF signature byte `0x7f` in RAX before bounded HLT.

- **Android/Bionic ARM64 compiled-and-linked PASS**: GitHub Actions
  [42078210874](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42078210874).
  The exact FEX/guest pread source, with GNU-as source-locked guest opcodes,
  cross-linked to original Android ARM64 FEXCore and Bionic dependencies.
  AArch64 ELF, Android linker and libc dynamic dependencies were verified.
  This executable was **BUILD-ONLY and deliberately removed** from artifacts;
  the workflow does not run it on Android or publish an APK.

## Scope and controls

The original ld-linux bytes were **used as guest-readable source data**,
not executed as dynamic interpreter code. Source and pread evidence do
not imply original glibc initialization, TLS/FS setup, relocations,
dynamic `PT_INTERP`, Linux guest `exit_group`, Wine/Proton, Windows PE,
DXVK/VKD3D or games. Previously proven fixed G0 Android `write`+ `getpid`
is still separate from this new test. Preserve existing KERNIX v0.27
and game data.

## Next functional gate

Build a new **isolated, source-pinned Android on-device original FEX
pread64** trial, not a repeat of fixed ELF instructions: place only
source-verified original guest files inside an owner-only private
directory; preserve SHA256 and no-follow closure; ensure glibc/ldso
redistribution notices/source are provided before any public APK;
supervise a bounded, user-initiated Android child process, require
the authentic guest's post-pread `RAX=0x7f` and ELF header marker.
The signed app must not accept arbitrary external game paths or
modify the stable install. **The test is device PENDING.**

After device PASS, proceed to real `PT_INTERP` handoff and original
x86-64 dynamic loader with authentic initial stack/AUXV, original
FS/TCB/TLS, relocations and safe guest syscall handling. Do not
create more one-opcode counter tests or claim game compatibility.

## UPDATE — bounded G0 original x86 guest pread64 physically PASSED on Android

The prior *phone pending* line above is the historical status of the
pre-release build, not the current status.

The user installed the separately signed
\`org.kernix.g0preaddevice\` build from immutable tag
\`kernix-g0-original-ldso-pread-android-263c26a6\` and supplied a
physical Android screenshot in this conversation showing all the
exact expected output fields:
- \`G0_ANDROID_ORIGINAL_LDSO_PREAD_PASS=1\`
- \`ORIGINAL_FEX_X86_PREAD64_EXECUTED=1\`
- \`GUEST_ELF_MAGIC_CONSUMED_RAX_7F=1\`
- \`EXIT_CODE=0\`
- \`ORIGINAL_LDSO_INSTRUCTIONS_EXECUTED=0\`
- \`GUEST_GLIBC_INITIALIZED=0\`
- \`WINE_PROTON_GAMES_EXECUTED=0\`

See user-screenshot evidence file
\`evidence/g0-original-fex-pread-source-ldso-android-device-screenshot-pass-20261105.json\`.
This is a successful **bounded** genuine FEX x86 \`pread64\` of
source-attested real ld-linux data, with the x86 guest consuming
the return buffer. It is not hardware cryptographic attestation and
is not proof that original interpreter instructions executed.

## Next full-process integration — real guarded startup stack host PASS

The exact SHA-pinned original Linux ELF main, ld-linux and glibc
preflight was used to build the authentic guest \`argc/argv/envp/AUXV\`
metadata; an actual kernel-selected, x86-canonical anonymous guest
stack VMA is now allocated with a non-executable native guard page
and rebased stack-internal pointers. The proven original PT_INTERP
load-bias, AT_BASE, AT_ENTRY and AT_PHDR **remain synthetic ELF
plan addresses until original PT_LOAD windows are mapped**.
Native Linux ARM64 runtime stack allocation/negative tests and
Android AArch64 Bionic cross-compilation both PASSED:
[GitHub Actions #42083257704](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42083257704).

Implementation:
- \`android-host/kernix_g0_owned_original_guest_startup_stack.h\`
- \`android-host/tests/kernix_g0_owned_original_guest_startup_stack_test.cpp\`

Machine evidence:
\`evidence/g0-source-original-ldso-owned-guarded-linux-x86-initial-stack-linux-arm64-and-bionic-compile-pass-20261105.json\`.

This is a **memory/stack entry preparation gate**, not a successful
dynamic loader launch or phone execution of the newly mapped stack.
Next whole-process test must map original PT_LOAD RX/RW with
source-checked permissions, safely bind actual runtime load biases
and AUXV, attach FEX RIP/RSP to the authentic PT_INTERP entry,
enforce W^X, and implement Linux guest relocations, IFUNC, TLS/FS,
required syscalls, process exit and cleanup. Do not publish an APK
for counting more individual opcodes or claim Windows/game support.
