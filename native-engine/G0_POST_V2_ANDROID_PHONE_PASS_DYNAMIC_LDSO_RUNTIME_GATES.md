# KERNIX G0 — post Diagnostics v2 Android success: real loader runtime acceptance

Status 2026-11-06: signed Diagnostics v2 physical Android user screenshot **PASS**.
Full dynamic loader and glibc **NOT PROVEN**.

## Verified boundary

A user-uploaded REDMAGIC Android screenshot showed:
- G0_ANDROID_SOURCE_LDSO_RW_STATE_AFTER_HEAP_PASS=1
- EXIT_CODE=0
- FULL_LDSO_GLIBC_OR_WINE_GAME_PROVEN=0

Ordered native output confirms an original FEX guest ELF/AUXV process,
real guest x86 mmap/store/load/munmap and an authentic ld-linux callee
writable byte update/192-byte guest stack, plus W^X source restoration.
Saved as evidence/kernix-diagnostics-v2-original-ldso-rw-stack-after-heap-physical-android-user-screen-pass-20261106.json.
Screenshot evidence is app-reported, not an independent hardware trace.
Real Linux FEX CI #42163385087, Android/Bionic link #42166430049,
signed same-package Android v2 build #42166956055 all passed.
Do not re-test v1/v2 on phone.

## Co-locate original ELF/TLS admission with already functional FEX

Existing source-verified gates are:
- C3-D7H original PT_GNU_RELRO policy. Seal only after actual relocation.
- C3-D7I original DT_RELA/DT_RELR/JMPREL and PT_TLS metadata.
  Source parser only; it does not write relocations.
- C3-D7J original libc Variant-II PT_TLS initializer/TBSS model.
  Not a real glibc TCB/DTV and must not be installed as guest FS.
- C3-D7K/L original FEX FS/GS ABI and bounded TLS guest read model.
  Neither is authentic full glibc thread runtime.

A new candidate native-engine/android-host/tests/kernix_g0_original_fex_heap_loader_rw_with_elf_dynamic_tls_preflight_arm64.cpp
executes previously verified original FEX guest heap and early loader
RW-state while checking the real three ELF sources' dynamic
relocation/TLS metadata and model **in the same host process**.
Workflow .github/workflows/kernix-g0-original-fex-heap-ldso-rw-and-source-dynamic-tls-preflight-arm64.yml
is its real Linux ARM64 validation gate.

This admission test does NOT execute guest relocation writers,
install guest FS, initialize TCB/DTV, resolve IFUNC or seal RELRO.
A source-only verification PASS can NEVER be described as glibc ready.

## Next substantial functional runtime milestone

Use the original x86 ld-linux execution path to demonstrate one
genuine guest-source relocation write in the same original FEX process
after source-authenticated PT_INTERP handoff. Required proof:

1. Derive the relocation target and addend from the exact original
   PT_DYNAMIC / DT_RELA or DT_RELR records, with independent source
   SHA256 and loadBias checks, rather than injecting a synthetic write.
2. Compare real guest memory before and after authentic relocation
   execution; the new value must match the source-derived relocation
   expression and be non-trivial. Reject unknown types, wrong
   alignment and out-of-image or RX/foreign pointer destinations.
3. Preserve native per-page W^X, original file-backed RX bytes,
   source stack and host guard, and finite allowlisted guest syscalls.
   Record the first failure stage, actual RIP, source target,
   native errno or signal and cleanup.
4. Real guest TLS/TCB/DTV, FS base, symbol resolution, IFUNC/IRELATIVE
   and post-relocation RELRO each need independent execution evidence
   before claiming complete loader or glibc startup.
5. Source-pinned Linux AArch64 FEX execution PASS must precede an
   independent Android/Bionic cross-link PASS and a new versionCode>=3
   original-signed org.kernix.diagnostics APK, which remains PHONE
   PENDING until actually tested on REDMAGIC.

No arbitrary opcode-count tests, no new app IDs, no unsupported full
loader/Wine/Proton/PE/graphics/game claims. Preserve installed signed
Diagnostics v2, stable KERNIX v0.27, Wine prefixes and user games.
