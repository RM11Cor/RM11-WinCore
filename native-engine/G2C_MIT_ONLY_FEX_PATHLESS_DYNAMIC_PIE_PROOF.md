# G2-C MIT-only x86 PIE: real FEXCore execution from immutable snapshots

**2026-11-04 — Ubuntu ARM64 JIT PASS; Android device NOT RUN.**

## Distinct from glibc

KERNIX now builds a genuine x86-64 ET_DYN PIE with PT_INTERP,
DT_NEEDED and Linux initial-stack/AUXV from **three MIT-owned ELF files**:

| File | Bytes | SHA-256 |
|---|---:|---|
| `bin/kernix-mit-dynamic-app` | 13320 | `ce7ed73417d68459fab6ea08d0f0c807c1ff04615727a724fadf3863f12b2e61` |
| `lib/x86_64-linux-gnu/libkernix-g2c-mit-placeholder.so.1` | 13184 | `aa8cf455237ee28a14c145cbe26cf5d690b8838cf8f8d01e4d1cf609ff268aee` |
| `lib64/ld-kernix-g2c-mit-placeholder.so.1` | 13160 | `16c1f89492ad15637017e8e652443de6554df50ea7e2b172abe27232c514c058` |

Original MIT assembly sources live in `native-engine/android-guest/`;
the build script is `native-engine/ci/kernix_g2c_build_mit_guest_fixture.sh`.
Two independent GNU x86 Linux builds yielded identical three-file
hashes; real PT_INTERP, DT_NEEDED, guest ELF closures and guarded
PHDR/AUXV/PT_LOAD staging passed
[CI 41817204369](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41817204369).

The same fixed three-file guest was executed by original upstream
FEXCore on Linux ARM64, with **real x86 JIT RAX=0x4b45524e49584732,
exit 0**, in
[run 41816933865](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41816933865).

Stronger evidence:
[run 41818264506](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41818264506)
**SUCCESS**, verifying exact app-owned ELF SHA-256 and O_NOFOLLOW,
copying each into independent anonymous PROT_READ snapshots, planning
all three ELF dependencies, guest PHDR and AUXV from ONLY the verified
in-memory bytes, staging RO guest main/interpreter/PT_LOAD, enabling
only fixed x86 main RX and executing the same original x86 _start
under FEXCore. The required markers include
`KERNIX_G2C_STAGE=MIT_ONLY_THREE_SHA256_PINNED_ELFS_NO_GLIBC` and
`KERNIX_G2C_STAGE=PT_INTERP_TRANSITIVE_NEEDED_PHDR_AUXV_FROM_SNAPSHOT_ONLY`.
[Host security run 41817901668](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41817901668)
also passed source-file corruption and root-directory symlink
rejection AFTER the snapshots were captured.

## Exact scope

The MIT ELF interpreter is deliberately a **nonfunctional placeholder**.
The proof enters the main `_start` directly; it **does not run**
a real ELF interpreter, resolve dynamic symbols or apply relocations.
No glibc, Wine, Windows PE, DXVK/VKD3D or game was executed.

A distinct Android original FEXCore MIT-only candidate compile mode
(`KERNIX_G2C_ANDROID_MIT_CANDIDATE_CI`) accepts only a fixed MIT
execution flag and canonical KERNIX app-private files directory.
The existing distro/glibc Android candidate is separate, and the
build-only mode must continue returning **126** for all inputs.

## Android native cross-link without shipping a runtime

[NDK run 41819015281](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41819015281)
**SUCCESS**, with two independent genuine original-FEXCore Android
ARM64/Bionic ELF candidates linked and audited:
the earlier distro-backed guest mode and now the separate
`KERNIX_G2C_ANDROID_MIT_CANDIDATE_CI` mode.
The MIT executable has `/system/bin/linker64`, Android
`libc.so`, actual original `libFEXCore.so`, exact MIT-only
app-private command flag, all three pinned MIT guest SHA-256
constants and an independently named Android success marker.
The workflow computes and retains the exact ELF SHA-256
and ABI text, then **deletes** the MIT candidate executable.
No candidate, MIT guest ELF, or glibc loader was packaged
into the signed v0.21 Android APK.

The MIT original-FEX candidate **builds/links for Android**;
it has **NOT executed x86 on an Android device**. This does not
prove real guest dynamic interpreter startup or game support.

**Device-release gate remains CLOSED.** Neither the MIT native FEX
candidate nor the three x86 MIT ELFs is shipped in v0.21. Android
source compiling/linking cannot establish an on-phone JIT pass.
Future steps: verify Android native candidate ABI, package only
SHA-pinned MIT-owned guest files/runner in a signed APK, supervise
one explicit user-initiated child with 8-second watchdog, and obtain
an actual Android ARM64 result before any game/Wine work.
