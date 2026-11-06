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

## 2026-11-06 — genuine original GNU ld-linux post-relocation RELRO outcome on full FEX Linux

[CI #42209247099](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42209247099):
**SUCCESS**. Source-attested original GNU/Linux x86 main,
`ld-linux`, libc and full original upstream Linux FEX were used
without modifying source ELF bytes. A guest x86 audit DSO constructor,
running **after actual original dynamic-linker relocations and before
guest main()**, independently checked all three original
`R_X86_64_RELATIVE` runtime qwords, source-derived load bias and
addend, AND actual **native read-only page protections** on original
main `PT_GNU_RELRO` full pages from guest `/proc/self/maps`.
At least one real source-relative relocated target must lie in a
read-only RELRO page; both independent process runs passed, as did
the unchanged original application without audit preload.
No synthetic KERNIX fixture relocation or fake writable-page
permission result satisfies this gate.

The ELF `PT_GNU_RELRO` page rights after genuine GNU `ld-linux`
relocations are **now positively established on full FEX Linux**.
Audit:
`evidence/g0-genuine-original-gnu-ldlinux-source-rela-and-ptgnu-relro-native-readonly-before-main-full-fex-linux-arm64-20261106.json`.
This is still NOT proof of original loader relocation/RELRO under
embedded FEXCore on Android. Source `c3d7h` must continue to
**forbid sealing original PT_GNU_RELRO prior to authentic relocation
completion in the same guest process**.

## 2026-11-06 — native owned-anonymous guest Linux mprotect(10) bridge

[CI #42209981955](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42209981955):
**SUCCESS**, real Linux kernel native owner-held anonymous
`mprotect(PROT_READ)` and restoration to `PROT_READ|PROT_WRITE`,
with independent `/proc/self/maps` permission checks, actual
readback and clean `munmap`.
The existing guest-only `BoundedGuestAnonymousVM` (no parallel
allocator) now recognizes `kMprotect` but permits only **exact
owned whole anonymous guest VMA** and non-executable RO/RW.
It disallows source ELF, FEX code, host private, partial VMA,
forged trap, RX/RWX and native 16K / x86 4K subpage mismatches.
Existing authenticated mmap/munmap regression also passed.
Independent NDK/Bionic AArch64 compilation completed.

Evidence:
`evidence/g0-owned-guest-anonymous-mprotect-linux-native-android-bionic-buildonly-pass-20261106.json`.
This is **native syscall bridge proof**, not yet FEX JIT
x86 opcode execution, and not original ELF GNU_RELRO.

A NEW real same-FEX guest x86 integration source now issues
`syscall 10` on its authenticated anonymous mmap page
between source ELF guest fixture RELATIVE store and final
guest memory read/munmap; original guest FS/DTV/TLS and bounded
ld-linux early call path are kept in the SAME context.
Sources:
`android-guest/kernix_g0_fex_guest_arch_fs_anon_mprotect_relro_prereq_then_ldso.S`
and
`android-host/tests/kernix_g0_original_fex_guest_arch_fs_mprotect_ro_heap_main_rela_ldso_arm64.cpp`.
[Real Linux FEX CI #42210451230](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42210451230)
must be checked and marked functional PASS only after the actual
Linux ARM64 run succeeds. Do not publish a signed v3 APK merely
because an anonymous test VMA can be set read-only.

The remaining original-loader gate is source-original
`ld-linux` performing **its own relocations, IFUNC and
RELRO guest kernel syscalls** with the complete glibc/NPTL
guest process, safe ELF VM permissions, and no arbitrary host
memory forwarding in embedded FEXCore. Existing signed
`org.kernix.diagnostics` v2, stable KERNIX v0.27, game data
and installed prefixes remain unchanged.

## 2026-11-06 — authentic x86 Linux guest mprotect(10) under original FEXCore: functional PASS

After validating whole-owner anonymous-only RW/RO/RW guest
VM policy on native Linux + Android/Bionic compile-only
[#42209981955](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42209981955),
the new integrated source combined four **actual** guest x86 syscall
opcodes in one original SHA-pinned FEXCore AArch64 process:

`arch_prctl(158,ARCH_SET_FS)` ->
`mmap(9,MAP_PRIVATE|MAP_ANONYMOUS,PROT_READ|PROT_WRITE)` ->
original main ELF source `R_X86_64_RELATIVE` guest fixture
store -> `mprotect(10, exact-owned-guest-heap,4096,PROT_READ)` ->
guest x86 read from native `r--p` page ->
`munmap(11)` -> bounded **actual source-original early
ld-linux MOV/CALL/RW/stack**.

[Linux ARM64 real-FEX functional #42210451230](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42210451230)
**completed SUCCESS** on exact commit
`d1a5ec05675de5def59a56c26809e7f1597ad157`;
actual native child `EXIT_CODE=0`.
The FEX syscall callback checked the exact x86 Linux ABI
including R10 handling, tracked the same one owner-held VMA,
denied forged `mprotect` of original source ldso or host
memory, required native kernel rights `r--p` after guest
syscall and independently confirmed a subsequent real x86
load before safe unmap. Source-owned original ELF RX
and callee RW/stack bytes were restored W^X as before.
The result proves genuine **x86 syscall(10) under FEXCore**,
not merely a C++ native host call.

Audit:
`evidence/g0-genuine-guest-x86-mprotect-owned-anonymous-ro-same-FEX-fs-tls-relative-early-ldso-linux-arm64-pass-20261106.json`.
Marker:
`KERNIX_G0_GUEST_OWNED_ANON_X86_MPROTECT_RW_TO_RO_WITH_SOURCE_TLS_RELA_AND_EARLY_LDSO_SAME_FEX_LINUX_PASS_NOT_FULL_GLIBC`.

**Do not conflate** this owned-ANONYMOUS guest VMA
`mprotect` with actual GNU ld-linux original `PT_GNU_RELRO`
mprotect on source-mapped ELF after its own complete relocations.
The latter was proven separately with the Linux **full FEX**
real GNU dynamic-linker run #42209247099, NOT in our embedded
FEXCore/Bionic guest-loader engine.
Actual x86 `arch_prctl` bounded TCB/DTV and other
prerequisites are not a complete glibc NPTL runtime either.

Independent
[Android/Bionic crosslink #42211043612](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42211043612)
must be marked **PENDING until its exact job completes**;
no Android phone execution and no new
same-signed `org.kernix.diagnostics` versionCode>=3
is justified solely from the anonymous guest memory gate.
Stable KERNIX v0.27, signed Diagnostics v2 and games untouched.

## 2026-11-06 — exact guest x86 owned-anon mprotect Android/Bionic ABI: PASS (no handset)

[Crosslink CI #42211043612](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42211043612)
**completed SUCCESS** with exact SHA-pinned upstream original
FEXCore and Android/Bionic AArch64 native linkage. It consumed
previous **functional Linux FEXCore x86 syscall 10**
[#42210451230](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42210451230),
attested the four original guest x86 syscall opcode offsets
(ARCH_SET_FS, mmap, mprotect, munmap), checked SHA256
and produced only an ARM64 build-only artifact:
`KERNIX-G0-Guest-Real-X86-Anon-Mprotect-RO-Source-FS-RELA-LDSO-Bionic-BUILDONLY`.
Audit:
`evidence/g0-real-x86-mprotect-anonymous-ro-with-guest-fs-tls-early-ldso-bionic-buildonly-pass-20261106.json`.

No APK, no Android physical phone runtime, no original GNU
ld-linux relocation completion and no original ELF RELRO seal.
Previous in-document mention of pending crosslink is now
**superseded by this actual successful CI job**.

## New fail-closed original ELF PT_GNU_RELRO guest-syscall test: in progress

A source SHA-verified originally writable **full PT_GNU_RELRO page**
from the original x86 main PIE is selected ONLY from the native
PT_LOAD + source RELRO plan, and a real x86 guest syscall(10)
attempts to change its rights to read-only **before the original
GNU ld-linux has completed its own dynamic relocations**.
The shared `BoundedGuestAnonymousVM` syscall service MUST return
Linux guest `-EINVAL` and leave the source-original RELRO
page `rw-p`, with unchanged owner windows. Only then may
the next real x86 guest syscall(10) protect its own separate
anonymous page, verified native `r--p`, and continue
original pinned source early ldso entry. A restored guest
stack and no host-thread TLS change remain mandatory.

This is a **deliberate denial/safety test**; a PASS does NOT
prove original GNU ld-linux dynamic relocation or ELF RELRO
protection in the embedded Android engine. It prevents the
unsafe shortcut of sealing ELF before true linker completion.

Sources:
`android-guest/kernix_g0_fex_guest_original_relro_mprotect_denial_anon_ro_then_ldso.S`
and
`android-host/tests/kernix_g0_original_fex_real_source_relro_mprotect_denial_anon_ro_arm64.cpp`.

[Actual original Linux FEXCore test #42227759769](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42227759769)
must be checked before claiming runtime PASS; at authoring
time it is not yet verified. The prior signed
`org.kernix.diagnostics` v2 phone-success gate and user game
files are untouched, and no debug or rebranded APK should
be offered for the partial stage.

## 2026-11-06 — exact real-x86 early RELRO denial Bionic crosslink closed; authenticated getrandom in progress

Previous original source-main `PT_GNU_RELRO` true-page early
guest x86 mprotect denial (with the same guest's owner-held
anonymous page RO allowed) was verified on real FEX Linux
[#42227759769](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42227759769).
Its exact original upstream FEXCore AArch64 candidate also
**cross-linked successfully against Android Bionic** in
[CI #42228476954](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42228476954)
and uploaded only
`KERNIX-G0-Guest-Source-Original-GNU-RELRO-Mprotect-Denied-Bionic-BUILDONLY`.
This **supersedes** the in-progress status in the preceding
paragraph. No phone runtime, no signed Android APK, no complete
GNU linker relocation is implied.

The next required guest kernel service has been added to the
**same existing** `BoundedGuestAnonymousVM` handler,
not a parallel Winlator/Bannerlator runtime:
guest Linux x86 syscall `getrandom(318)` with a maximum
256-byte buffer. The guest can only request output into an
authenticated nonexecutable **writable** anonymous VMA owned
by the exact guest kernel. Requests with unknown destination,
a read-only buffer, an ELF/loader/JIT pointer, a bogus trap,
zero or overlarge length, or unsupported flags are rejected
without changing guest/host memory. The constant trusted host
`/dev/urandom` source is opened with `O_NOFOLLOW|O_CLOEXEC`,
validated as a character device, and read into isolated native
scratch. Only after complete successful reading does the
handler transfer entropy to the verified guest RW buffer.
This neither accepts arbitrary guest paths or fds nor forwards
Linux x86 syscall numbers unfiltered to Bionic.

[Native functional Linux and Android/Bionic compile-only #42231529147](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42231529147)
**completed SUCCESS**, with existing owned mmap/munmap and
mprotect regression PASS. Audit:
`evidence/g0-native-guest-owned-getrandom-kernel-entropy-linux-bionic-crosscompile-pass-20261106.json`.

The further *real FEX guest* integration is an exact
source-locked Linux AArch64 proof, using authentic x86 assembly
that calls `getrandom` **twice** into distinct 32-byte
buffers of its earlier native-owned `mmap`. The FEX syscall
callback authenticates RIP, original guest ELF/AUXV, x86
register ABI, FS/TLS, memory ownership and actual kernel
entropy source. Original main source `R_X86_64_RELATIVE`
fixture, actual guest source PT_GNU_RELRO premature denial,
owner-only native `mprotect`, `munmap`, and original bounded
GNU ld-linux early callee must all remain functional inside
the **same FEX session**.

[Real FEX functional test #42232208819](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42232208819)
is **not yet an established PASS** until independent
CI job completion, exit-zero and semantic-stage verification.
Source:
`android-guest/kernix_g0_fex_guest_owned_getrandom_then_original_relro_denial_ldso.S`
and
`android-host/tests/kernix_g0_original_fex_guest_getrandom_source_relro_denial_ldso_arm64.cpp`.

This improves kernel service coverage but does **not**
complete original GNU `ld-linux` in embedded FEXCore,
glibc NPTL, symbol version lookup, IFUNC, PE/Wine startup,
Android device runtime or game compatibility.
Leave user-screenshot-confirmed original-signed
`org.kernix.diagnostics` v2, stable KERNIX v0.27,
game files and installed prefixes untouched.

## 2026-11-06 — authentic x86 getrandom(318) *inside same FEX guest* PASS, Bionic independent gate

[Linux ARM64 real upstream FEXCore functional #42232208819](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42232208819)
**completed SUCCESS** on exact workflow source commit
`85212ed0020efc38d28d7095a749f17c4508e93a`.
A real source SHA256-verified original x86 ELF/AUXV, main,
interpreter, libc and source-authorized RELA guest fixture
were staged into the **same upstream FEXCore process** as
the user device's earlier signed Diagnostics v2 early loader
gate. New actual x86 guest opcodes invoked
`getrandom(318)` **twice** into disjoint 32-byte regions
within a previously authenticated guest-owned native
anonymous RW VMA. Genuine FEX CPU-state/syscall callback
authenticated the syscall RIP, Linux x86 RDI/RSI/RDX
arguments, active guest FS/TCB/DTV, exact VMA owner and
the trusted kernel entropy source. Both calls returned
exactly 32 bytes; independently read back kernel-provided
nontrivial nonidentical buffers. No guest-chosen file
descriptor or path was forwarded to host.

The same guest completed original-source REAL x86 mmap,
source-original guest `R_X86_64_RELATIVE` *fixture* write,
source main original GNU_RELRO premature `mprotect`
denial, legitimate owner-anonymous mprotect RO,
munmap, original source ld-linux bounded early MOV/CALL
and callee guest RW/stack state. All native W^X and
original SHA/file/stack restoration gates passed.

The marker
`KERNIX_G0_REAL_X86_GUEST_GETRANDOM_TWICE_TRUSTED_KERNEL_ENTROPY_WITH_SOURCE_ELF_FS_TLSDTV_RELRO_DENIAL_EARLY_LDSO_FEX_LINUX_ARM64_PASS_NOT_ANDROID`
was actually emitted after exit code 0 with ordered
source/guest semantic markers. Canonical audit:
`evidence/g0-real-original-fex-x86-two-getrandom-trusted-kernel-entropy-source-elffsgnu-relro-early-ldso-linux-arm64-pass-20261106.json`.

The earlier attempt #42232045294 was **CI failure only** due to
an invalid marker ordering assertion after the functional
guest process emitted all successful markers; repaired on
#42232208819. Do not conflate previous CI failure with
the engine functional result. Guest CPU state and original
ELF bytes remained unmodified outside their owned shadow
windows.

[Independent Android Bionic crosslink #42232979510](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42232979510)
is **PENDING at this documentation edit** and must not be
reported as PASS before checking the job's actual status,
ARM64/Bionic ELF deps and exact Linux evidence run match.

Most importantly, **full original GNU ld-linux relocations
under embedded FEXCore, full glibc/NPTL/IFUNC, guest
openat/file-backed mmap/ELF dependency loading, and Wine
remain unproven.** Success on Linux original full FEX
#42209247099 was an independent positive original loader
reference, not Android. Preserve original package identity
`org.kernix.diagnostics` v2, signing key, stable v0.27
and user game files; no new signed Diagnostics v3 release
for the limited entropy syscall milestone.
