# KERNIX G2-D — first genuine x86-64 cross-DSO PLT import / JUMP_SLOT gate

**2026-11-04. v0.22 REDMAGIC device PASS is retained unchanged. G2-D is a
different, Linux ARM64 test-only source/CI gate; there is no G2-D APK.**

## Problem solved in this stage

The prior v0.22 G2-C witness entered the x86 PIE `_start`
DIRECTLY through original FEXCore and returned fixed RAX. Its
DT_NEEDED and PT_INTERP were real GNU ELF metadata but the dynamic
interpreter was deliberately a placeholder; no x86 symbol was
actually imported and no GOT relocation was applied.

G2-D creates a new MIT-only, 16KiB PT_LOAD-aligned x86 ET_DYN main
containing

```asm
_start:
    call kernix_g2d_imported_value@PLT
    addq $17,%rax
    hlt
```

An independently linked x86 shared DSO
`libkernix-g2d-mit-import.so.1` exports
`kernix_g2d_imported_value`, which returns
`0x4b45524e49584720` in RAX and then issues x86 `ret`.
The successful full x86 function call/return should therefore yield
**`RAX=0x4b45524e49584731`**, a value distinct from the G2-C proof.

The GNU linker outputs a **real** `R_X86_64_JUMP_SLOT`
`DT_JMPREL` relocation referencing undefined main symbol and
defined external x86 DSO symbol. There is a third MIT-owned
ELF PT_INTERP placeholder, still intentionally NOT executed as
an interpreter. No glibc or Ubuntu guest libraries are used.

## Byte pins from actual Ubuntu 24.04 GNU binutils 2.42

| Guest file | Bytes | SHA-256 |
|---|---:|---|
| `bin/kernix-g2d-import-app` | 50504 | `a29be66289673e80cef5de115dfce0f05cb04599368f039c44c728ad0b2278a0` |
| `lib/x86_64-linux-gnu/libkernix-g2d-mit-import.so.1` | 50048 | `8ec9bac9b3a21eeaedb4ec9c7071907a6074cbea9eb41f78591e176f0a27441e` |
| `lib64/ld-kernix-g2d-mit-import-test.so.1` | 50024 | `a37ed983c898512082749c5a9ec2cc3c10be8fd1adcffd4eaf09fb7346c068d2` |

These are **not** the hashes from another workstation's
different binutils release. The exact CI binary versions, sizes
and SHA-256 are pinned in
`native-engine/android-host/kernix_g2d_mit_import_linker.h`.

[GitHub x86 PLT/DSO preflight run 41828589814](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41828589814):
**SUCCESS**, proving that the exact GNU x86 relocation targets one
legitimate imported symbol from the separate shared object.
Independent negative tests reject a changed relocation type,
symbol index, addend, symbol bytes, DSO name or ELF architecture.

The real C++ host VM test additionally:
- Re-opens only exact fixed app-private files with O_NOFOLLOW,
  owner/mode/size checks, exact SHA-256 and frozen read-only
  anonymous snapshots.
- Checks DT_JMPREL, DT_PLTRELSZ, DT_PLTREL, the sole
  R_X86_64_JUMP_SLOT, undefined main symbol, matching DSO SONAME,
  exported symbol, exact x86 machine bytes and 16KiB PT_LOAD W^X.
- Builds full PT_INTERP / DT_NEEDED closure and guarded guest stack,
  stages the actual main and interpreter PT_LOAD from the same
  original snapshots.
- Reserves a separate x86 provider DSO mapping without MAP_FIXED,
  installs its original snapshot bytes as read-only data.
- Writes **exactly one 8-byte GOT slot**, pointing into the
  actual provider mapping; protects that page read-only again.
- Proves a modified original source or symlink redirect cannot
  change the already validated anonymous snapshots.
- Executes NO guest x86 code and NO FEX JIT in this host test.

## Next gate: real original FEXCore

`native-engine/android-host/kernix_g2d_real_fex_import_probe.cpp`
is separate from the stable G2-C Android candidate and is
**Linux ARM64 CI-only**. It repeats the same frozen-pinned ELF,
closure, one bounded relocation, read-only GOT protection, and then
marks only the two fixed x86 text sections RX and guest stack RW
so that genuine x86 call/ret can execute. Original pinned upstream
FEXCore JIT must call into the **other ELF DSO** and return
`RAX=0x4b45524e49584731` with no syscalls or extra files.

This test is added to the original ARM64 FEX workflow, with a
separate result JSON and timeout. It **passed** in the distinct original upstream FEXCore Linux ARM64
[run 41830448479](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41830448479).
The native driver returned **exit code 0**, with exact
`RAX=0x4b45524e49584731`, and the required markers:

```text
KERNIX_G2D_DEBUG=FEX_GUARDED_CALLRET_SHADOW_STACK_INITIALIZED
KERNIX_G2D_STAGE=REAL_GNU_LD_JUMP_SLOT_GOT_BOUND_TO_EXTERNAL_X86_PROVIDER_AND_REPROTECTED_READONLY
KERNIX_G2D_FEX_REAL_EXTERNAL_X86_FUNCTION_RAX=0x4b45524e49584731
KERNIX_G2D_ORIGINAL_FEX_X86_64_REAL_PLT_JUMP_SLOT_CROSS_DSO_CALL_RETURN_PASS_NO_GLIBC
```

The first run failed because FEX's `REG_CALLRET_SP` (AArch64
`x25`) was zero. GDB proved an actual fatal SIGSEGV at
`0xfffffffffffffff0` on the first host JIT call-return stack push.
The fix initializes an anonymous read/write FEX CALL/RET shadow stack
between two PROT_NONE guard pages, attaches it to the FEX thread
and sets `state.callret_sp` **before** `ExecuteThread`.
See `G2D_ARM64_ORIGINAL_FEX_CALLRET_SHADOW_STACK_ROOT_CAUSE.md`.

This is a **real** cross-DSO x86 CALL followed by x86 RET and a
successful FEX JIT return to main. It is still **not** a full Linux
dynamic interpreter, glibc startup, Wine or any game, and it has
**not** been run on an Android device.

Neither successful relocation on a host nor a real fixed call into
one DSO implies general ELF lazy linking, all symbol relocations,
glibc, Wine, Proton, PE, Windows games or graphics support.
There is no new Android trial APK; keep signed KERNIX v0.22.
