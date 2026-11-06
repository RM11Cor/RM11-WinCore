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

## Independent Android/Bionic ABI cross-link result: PASS, no handset execution

[#42170791040](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42170791040)
**completed SUCCESS** at pinned workflow commit
`09e4dee6be7ab736c3f248e9eb6451f42604d02b`.
Exact original source ELF guest fixture, FEXCore AArch64
`libFEXCore.so` and source-derived x86 RELATIVE writer C++ host
cross-linked to Android Bionic ARM64. The workflow checked exact
Linux runtime success #42170267640, upstream SHA-pinned Android
FEX source build #42157777076, native AArch64/Bionic ELF dependency
constraints and binary SHA256 and produced **only** the artifact:

`KERNIX-G0-Guest-X86-Original-ELF-RELA-RELATIVE-Writer-Bionic-BUILDONLY`

It emitted:
`KERNIX_G0_SOURCE_ELF_GUEST_RELATIVE_FIXTURE_WRITER_ANDROID_BIONIC_CROSSLINK_PASS_NOT_PHONE`.

This is not physical Android execution, not an APK and emphatically
not proof of the original GNU `ld-linux`'s dynamic relocation logic.
Recheck this exact distinction before any next-stage release.

Audit record:
`evidence/g0-source-relative-guest-fex-writer-android-bionic-crosslink-only-pass-20261106.json`.

The next gate remains actual original guest ld-linux dynamic
relocation control flow and semantic writes, plus independently
validated symbol/IFUNC/TLS prerequisites. Do not release Diagnostics
v3 solely for the KERNIX-owned fixture; preserve v2 and user data.

## 2026-11-06 — original GNU ld-linux genuine relocation outcome under FULL FEX Linux ARM64: PASS

[CI #42202141886](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42202141886)
PASSED twice under source-pinned upstream **FULL Linux FEX runtime**
(not the reduced embedded FEXCore Android runtime). Three original
source SHA256-locked GNU/Linux x86 ELF files — main, ld-linux, libc
— were staged without patching, and a separate guest x86_64 audit DSO
was loaded through original GNU `ld-linux --preload`.
Its constructor ran BEFORE the immutable guest application's `main`,
re-read the original main ELF `DT_RELA` table, independently checked
each of **three** source-authenticated `R_X86_64_RELATIVE`
entries against live runtime relocated qwords
`main_load_bias + original_r_addend`, and required every live value
to differ from the original file's unrelocated target qword.
Both x86 process instances then executed the original guest
`libc puts` import. An unchanged program with no audit preload
returned successfully without the audit witness. All three
conditions were independently required by CI; no artificial
KERNIX guest relocation-writer code was executed in this gate.

Evidence:
`evidence/g0-original-full-fex-gnu-ldso-main-relative-relocations-before-main-linux-arm64-pass-20261106.json`.
Source:
`android-guest/kernix_g0_full_fex_original_main_ldso_rela_runtime_witness.c`.
Observed marker:
`KERNIX_G0_GENUINE_ORIGINAL_GNU_LDSO_THREE_SOURCE_RELATIVE_RELOCATIONS_BEFORE_MAIN_FULL_FEX_ARM64_LINUX_PASS_NOT_ANDROID`.

**Boundary:** this proves the original main's actual post-linker
relocation state BEFORE main on FULL original FEX Linux AArch64,
not a trace of every GNU dynamic relocator internal instruction.
It neither runs GNU ld-linux relocation logic inside our
standalone FEXCore/Bionic host nor establishes Android device
support. The real porting gap includes guest
`arch_prctl(ARCH_SET_FS)`, complete original glibc TCB/DTV/TLS,
safe guest syscalls, symbol/IFUNC relocation processing and RELRO.

## Next same-process FEXCore FS syscall/guest TLS integration (in test)

Source:
`android-host/kernix_g0_source_owned_guest_fs_tls_runtime.h`,
`android-guest/kernix_g0_fex_guest_arch_set_fs_source_tls_relative_heap_ldso_handoff.S`
and
`android-host/tests/kernix_g0_original_fex_guest_arch_set_fs_tls_main_rela_ldso_after_heap_arm64.cpp`.
It extends the phone-verified same-session FEX bounded
ELF/heap/early-ldso path with original-source libc PT_TLS
initial data, an owned guest-only minimal TCB/DTV, actual x86
`arch_prctl` syscall `ARCH_SET_FS` updating **only**
FEX guest CPUState.fs_cached, and genuine guest x86 FS:0,
FS:8/DTV, FS:16 and FS:-136 memory loads.
It independently preserves the previously proven genuine
guest-authenticated RELATIVE fixture write, original early
ldso callee state, cleanup and W^X.

The first Linux integration
[#42203492261](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42203492261)
FAILED before the first guest syscall while installing new
FS-owned memory, a probable AArch64 kernel-selected high VMA outside
the x86 lower canonical address space. Fixed by using only an
**advisory non-MAP_FIXED** low-address hint, plus explicit first
failure diagnostics. The subsequent Linux real-FEX functional
run must be checked; this documentation does not assume success.

This is still bounded **minimal TCB/DTV**, not the real
complete glibc/NPTL TLS runtime. Do not issue a new Android
v3 diagnostic APK merely for this test or request re-running
the already phone-successful v2. Preserve user data.

## Same-process guest ARCH_SET_FS + original libc TLS FS/DTV + RELA/heap/early ldso: Linux PASS

[Real FEX Linux ARM64 #42204067582](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42204067582)
and
[the final diagnostic source rerun #42204101420](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42204101420)
both **completed SUCCESS**, the last from commit
`3d0eb367204454e8450e66735002e812402c0e40`.

After exact source main/ld-linux/libc ELF SHA validation and original
libc PT_TLS source model, the test allocated guest-only RW memory in
the authentic x86 lower canonical address space using an
**advisory non-MAP_FIXED** native VMA hint. It created a bounded
original-source libc 16-byte PT_TLS initializer and 136-byte
Variant II block, minimal guest-only x86 TCB first three pointers
and source-style 3-entry DTV.

Real x86 guest opcode stream in ONE original FEXCore session executed
Linux x86-64 `arch_prctl(158, ARCH_SET_FS=0x1002, guestFSBase)`.
The authenticated guest syscall adapter updated FEX guest
`CPUState.fs_cached` only, never native host TLS; the
actual guest next instructions read `FS:0`, `FS:8` + DTV[1],
`FS:-136` and `FS:16`, independently verified by native
guest-owned memory readback at the following guest mmap trap.
The same session then performed previously proven original x86 mmap,
a source-verified RELATIVE guest fixture store with rollback,
munmap, and original GNU ld-linux early callee RW/stack state
with source W^X restoration.

Authoritative Linux marker:
`KERNIX_G0_GUEST_ARCH_PRCTL_SET_FS_LIBC_TLS_RELATIVE_HEAP_ORIGINAL_LDSO_SAME_FEX_ARM64_LINUX_PASS_NOT_FULL_GLIBC`.
Audited machine evidence:
`evidence/g0-same-real-fex-guest-arch-set-fs-source-libc-tls-dtv-relative-heap-original-ldso-linux-arm64-pass-20261106.json`.

**Narrow proof only.** It proves a real FEX x86 Linux
`ARCH_SET_FS` syscall and bounded guest FS/DTV/TLS source-backed
reads in a coherent FEX heap/early ldso process. It is *not* the
complete original glibc `struct pthread`, all module dynamic TLS
allocation, resolver linkage, GNU ldso's own relocator loop or
complete original `_dl_start`. The latter real relocated main
outcomes were demonstrated separately on full upstream Linux FEX,
not inside this Bionic-style embedded FEXCore host.

[Android/Bionic crosslink-only #42204695544](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42204695544)
is the separate next CI gate. Keep it PENDING until independently
completed. The prior user-observed signed Diagnostics v2 and stable
KERNIX remain untouched; no APK v3 for a bounded FS fixture.

## Android/Bionic link-only result for bounded source-authenticated guest FS: PASS

[CI #42204695544](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42204695544)
**completed SUCCESS** on source workflow commit
`611a850b8ba625040901e21ffc74e9835f180cb4`.
This supersedes the preceding paragraph's historical
Android/Bionic *PENDING* status for the
`ARCH_SET_FS`/source glibc TLS/guest RELA/early-ldso
integrated Linux candidate.

The native Android NDK verified original upstream FEXCore source
and binary SHA256; rebuilt original source-dependent FEX headers;
assembled and audited **three** authentic x86 guest Linux syscall
instructions (`arch_prctl`, `mmap`, `munmap`); then compiled and
linked the exact Linux-functional combined guest runtime to
AArch64/Bionic ELF, verified `libFEXCore.so` and Android
`libc.so` dependencies instead of Linux x86/ARM GNU libc.
The job uploaded only the artifact
`KERNIX-G0-Guest-ARCH-SET-FS-Source-libc-TLS-RELA-LDSO-Bionic-BUILDONLY`
with source SHA/ABI evidence and no Android APK.
Exact marker:
`KERNIX_G0_GUEST_ARCH_SET_FS_LIBC_TLS_RELA_HEAP_LDSO_ANDROID_BIONIC_CROSSLINK_PASS_NOT_PHONE`.

Canonical evidence:
`evidence/g0-original-fex-guest-arch-set-fs-libc-tls-rela-ldso-linux-and-android-bionic-build-pass-device-notrun-20261106.json`.

**Phone status: NOT RUN. Full guest glibc TLS/ld-linux startup:
NOT PROVEN.** This is a bounded source-original guest FS/TLS
and early ldso entry integration gate, not a claim that
GNU `ld-linux` completed relocation/IFUNC/symbol lookup,
Linux guest syscall coverage, NPTL dynamic TLS, Wine/Proton
or games on the custom Android host.
Keep the user's already-validated signed
`org.kernix.diagnostics` v2 and original signing identity,
stable KERNIX v0.27 and game data unchanged. Avoid generating
or requesting another signed APK solely for partial features.
