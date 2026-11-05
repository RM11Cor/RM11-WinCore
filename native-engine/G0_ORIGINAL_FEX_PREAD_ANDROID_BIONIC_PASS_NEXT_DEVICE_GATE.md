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
