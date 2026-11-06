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

## 2026-11-06 — genuine x86 guest-source RELATIVE store, **NOT original ld-linux relocation**

[Linux ARM64 real FEX CI #42170267640](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42170267640)
is **completed SUCCESS** (source commit
`fae56364e937c43ceb08c17398882a93744cf779`).
The source-pinned original x86 main ELF carries exactly 3
`R_X86_64_RELATIVE` entries; the new fail-closed source selector
`android-host/kernix_g0_source_relative_rela_guest_writer_gate.h`
selects one attested record inside the source-authenticated original
`DT_RELA`, validates symbol zero/type 8, source guest record bytes,
load-bias overflow bounds, original image RW PT_LOAD rights, and
requires a **nontrivial** source-derived expected value.

Authentic source data is then **read and written by real guest x86
machine code** (the explicit KERNIX-owned guest fixture
`android-guest/kernix_g0_fex_heap_elf_source_rela_relative_guest_writer_then_ldso_handoff.S`)
in the same genuine FEX process *after* guest mmap/store and *before*
guest munmap and the existing original ld-linux early callee entry.
Host code independently reads back the target qword, checks it equals
source `main loadBias + RELA r_addend`, checks real mutation, validates
unchanged original RELA info, and restores the exact prior qword under
native W^X. It then re-verifies the genuine bounded original ldso
RW/stack witness, source byte restoration and owned page cleanup.

The successful Linux stdout/stderr explicitly say:

- `KERNIX_G0_REAL_FEX_GUEST_X86_SOURCE_RELATIVE_RELA_STORE_AFTER_MMAP_VERIFIED_NOT_ORIGINAL_LDSO_RELOCATION`
- `KERNIX_G0_GUEST_SOURCE_RELA_RELATIVE_RW_QWORD_RESTORED_NO_LDSO_RELOCATION_CLAIM`
- `KERNIX_G0_REAL_X86_FIXTURE_RELATIVE_RELA_RW_LINUX_PASS_NOT_ORIGINAL_LDSO`

**Critical distinction:** this proves real translated x86-64 guest
relocation *arithmetic and writable-store semantics* using authentic
source RELA metadata. The writer is explicitly a trusted KERNIX x86
**test fixture**, not the original GNU `ld-linux`'s relocation
processing. It does not prove the real dynamic linker relocation
loop, symbol lookup, IFUNC, glibc TLS FS/TCB/DTV, post-relocation
RELRO, `_dl_start` completion, Wine, games or FPS.

Audit record:
`evidence/g0-source-main-elf-rela-relative-guest-x86-fixture-under-fex-after-mmap-linux-arm64-pass-20261106.json`.

Independent Android/Bionic build-only run
[#42170791040](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42170791040)
**must be checked separately for completion before any Bionic linkage
claim**. Even after a Bionic PASS, DO NOT distribute a new signed
Diagnostics v3 solely for the fixture milestone; the user's signed
Diagnostics v2 phone-observed original ldso RW gate stays closed and
unchanged. The next real substantive target is an original
`ld-linux`-executed relocation, not another synthetic proof counter.
