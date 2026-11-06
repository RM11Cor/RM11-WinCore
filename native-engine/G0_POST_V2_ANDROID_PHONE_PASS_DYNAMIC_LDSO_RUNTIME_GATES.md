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

## Independent Android/Bionic cross-link of real guest x86 getrandom twice: PASS

[Android Bionic CI #42232979510](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42232979510)
**completed SUCCESS** on workflow commit
`9dd5189fa8a64a893ef2b4d564113196d5c941bb`,
verifying exact functional real original FEX Linux AArch64
[#42232208819](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42232208819)
and original Android reference FEXCore source/provenance.
Original guest seven syscall instructions were audited,
source-locked FEXCore native headers generated, and the
exact source functional under Linux was cross-linked
into an AArch64/Bionic ELF with native FEXCore
dependencies. Final artifact:
`KERNIX-G0-Original-FEX-X86-Getrandom-Twice-Source-RELRO-Denial-Bionic-BUILDONLY`.
No signed Android APK, handset execution or Wine startup
was attempted by this CI job. Exact marker:
`KERNIX_G0_REAL_X86_GETRANDOM_TWICE_SOURCE_ORIGINAL_GNU_RELRO_DENIAL_ANDROID_BIONIC_CROSSLINK_PASS_NOT_PHONE`.

Audit record:
`evidence/g0-real-x86-two-getrandom-original-fex-linux-and-android-bionic-buildonly-pass-20261106.json`.

The earlier in-document PENDING reference to
`#42232979510` is superseded by its actual success.
The precise bottleneck after this guest kernel syscall
milestone remains **original GNU ld-linux's own dynamic
loader work in the embedded FEXCore process**: safe
source-original guest openat/read-only file-backed ELF
mappings, symbol versioning / IFUNC / RELA / RELR processing,
complete NPTL TLS/TCB/DTV, and post-relocation source ELF
GNU_RELRO sealing. These must be tested as authentic guest
behavior, not by artificially patched result markers.
The full Linux upstream FEX runtime's success at relocating
original glibc sources is a reference baseline only.
Preserve existing user-screenshot-verified signed Diagnostics
v2 and the stable KERNIX v0.27 / game data, without a new
partial diagnostic APK.

## 2026-11-06 — source SHA256-verified original ELF guest file service: native PASS, x86 FEX integration pending

The original x86 GNU/Linux loader's next dependency is a
**safe guest file descriptor service**, not direct forwarding
of x86 syscall IDs/guest pointers to Android Bionic.
Reused existing verified **read-only anonymous snapshot**
infrastructure from
`android-host/kernix_g2c_native_readonly_guest_snapshots.h`.
New source
`android-host/kernix_g0_source_verified_guest_elf_fd_kernel.h`
binds only the exact SHA256-verified original triad:
`/bin/kernix-g2e-dynamic-guest`,
`/lib64/ld-linux-x86-64.so.2`, and
`/lib/x86_64-linux-gnu/libc.so.6`.
Trusted startup opens these through source-verified pinned
directory descriptors; the guest never supplies a host path
or receives a real host FD. Guest `openat(257)` only accepts
`AT_FDCWD`, source-exact path bytes from an authenticated guest
anonymous page and `O_RDONLY|O_CLOEXEC`.
It returns synthetic guest FDs 100..107. Guest
`read(0)`, `pread64(17)`, and `close(3)` are bounded
to these snapshots. Both read operations copy only into an
authenticated **guest-owned writable non-executable** VMA.
`pread64` preserves the guest FD cursor. No guest writable
FD, arbitrary relative path, traversal, symlink or host /lib
fallback is permitted.

[Native Linux real original GNU x86 ELF source and Android
Bionic ARM64 compile #42234542541](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42234542541)
**completed SUCCESS**. Real main, interpreter and libc bytes
were rehashed against fixed source SHA256 and captured into
private read-only snapshots. Adversarial checks verified
path/flags/FD/pointer rejection, source-disk post-snapshot
mutation isolation, invalidated source attestation failure,
true `pread64` vs sequential `read` behavior, native owner
mprotect read-only refusal, and clean close/unmap.
Older guest mmap/munmap, mprotect and true kernel
getrandom tests all regressed PASS.
The exact same C++ source compiled into Android
AArch64/Bionic object; **no Android on-device execution**.

Full source-integrated authentic x86 syscall stream has now
been authored with **eleven** actual Linux x86 syscall
instructions: `arch_prctl`, `mmap`,
`getrandom` twice, `openat`, `pread64`, `read`,
`close`, premature source-original GNU_RELRO
`mprotect` denied, anonymous page `mprotect` allowed,
then `munmap` and original bounded early GNU ld-linux.
It uses the **same** original SHA-locked source ELF and
original FEXCore test harness as earlier milestones, not a
parallel emulator or copied guest runtime.
[Functional full real FEX ARM64 CI #42235659220](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42235659220)
must be checked for exact exit=0 and all source guest
semantic markers before reporting any guest FEX runtime PASS.
The first compile run #42235570863 contained a CI-only
literal-NUL assertion corrected on #42235659220;
no assumptions about either result are allowed.

**Boundary:** This authentic immutable-file `openat/read`
subset is not the original loader's actual file-backed
`mmap`, shared-object search, full glibc symbol version
or IFUNC resolver, original `_dl_start`, real PT_GNU_RELRO
post-relocation enforcement, Bionic device runtime or
Wine/Proton/game compatibility. The next true runtime
milestone must be verified, then crosslinked to Bionic
without installing a new signed diagnostic APK merely for
a partial service. Leave user's signed
`org.kernix.diagnostics` v2, stable KERNIX v0.27 and
game files untouched.

## 2026-11-06 — actual guest ELF openat/pread64/read/close inside real FEX: Linux + Bionic link PASS

The already-existing fixed source-verified ELF snapshot service
`android-host/kernix_g0_source_verified_guest_elf_fd_kernel.h`
reuses G2C immutable anonymous PROT_READ SHA256 snapshots and the
original G0 owner-held guest anonymous RW allocator.
It provides ONLY original guest x86
`openat(257)`, `pread64(17)`, `read(0)`,
`close(3)` for three fixed SHA256-locked GNU x86 source
files (main, `ld-linux`, libc). No guest-provided file
path or guest FD is forwarded to native host open/read.
Trusted bootstrap source directories are traversed
componentwise with `O_NOFOLLOW` and rehashed into snapshots;
a synthetic guest FD100 is returned for the exact original
`/lib64/ld-linux-x86-64.so.2`.

Independent **real FEX Linux ARM64** runs
[#42235659220](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42235659220)
and
[#42235815181](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42235815181)
both **completed SUCCESS** on the original upstream
FEXCore source SHA
`02e24ca5c01ed0c864466ed573db347336f70170`.
Real translated guest x86 syscall instructions opened
the exact interpreter source and read its original
ELF header via independent `pread64` and `read`
into authenticated guest-owned RW buffers.
The guest observed unchanged seek position after `pread64`
and closed the synthetic FD, with no leaked host handles.
The **same bounded guest process** also passed guest FS/TCB
limited TLS reads, two real `getrandom` calls, one
source-authenticated main RELATIVE guest *fixture* write,
original GNU_RELRO early guest mprotect **DENIAL**,
owned anonymous-page RO, munmap, and authentic early
GNU ld-linux callee RW/stack and original source restoration.

Independent **Android/Bionic AArch64 link-only** runs
[#42236366354](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42236366354)
and
[#42236403748](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42236403748)
both **completed SUCCESS**, using exact source-locked
original FEXCore Android ELF and original GNU guest data,
with checked Android Bionic dependency linkage.
These artifacts are **BUILDONLY**, not handset-executed
Android APKs or signed releases.

Canonical machine-readable audit:
`evidence/g0-original-fex-real-x86-gnu-ldlinux-immutable-snapshot-openat-pread64-read-close-linux-arm64-pass-20261106.json`.

**Critical remaining limitation:** the actual complete original
GNU dynamic-linker `_dl_start`, library search,
file-backed guest ELF mappings, symbol-version resolution,
IFUNC/IRELATIVE, full glibc/NPTL TCB/DTV, post-relocation
ELF RELRO and Wine/Proton games are **NOT YET PROVEN**
under embedded Android FEXCore. This particular file
service is a strict three-file fixed-snapshot test, not
a general-purpose game file loader. Do NOT introduce arbitrary
native host filesystem forwarding to imitate completeness.
The user-confirmed original-signed
`org.kernix.diagnostics` v2 and stable v0.27 remain
unchanged. No v3 package was created for this milestone.

## 2026-11-06 — actual 11 guest x86 Linux syscalls and original source ELF file IO under real FEX: PASS; Android Bionic link PASS

[Original real upstream FEXCore ARM64 Linux #42235659220](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42235659220)
**completed SUCCESS** from exact commit
`d84272d6fe592116751b56c8865e7742c1bdbacf`.
The same SHA256 source-verified three original GNU/Linux x86
ELF binaries and original FEXCore CPU context executed an
**11-syscall actual x86 instruction stream**, adding four
NEW guest operations to earlier provenance/entropy/loader
tests: `openat(257)` the exact original
`/lib64/ld-linux-x86-64.so.2`, `pread64(17)`
the genuine source `ELF` header, `read(0)` the same
header while proving `pread` had NOT advanced the guest FD,
and `close(3)` the synthetic guest FD. Each offset was
authenticated against GNU-as machine bytes and original FEX
x86 guest RIP/CPUState. Original SHA snapshot and native
guest owned-writable output were independently verified.
Neither guest x86 pathname nor guest virtual FD was ever
passed to a native host path/open/FD read, and original source
ELF strings from guest RX shadow could never request an
unverified host path. The rest of the same guest executed
FS/TLS, two real x86 kernel getrandom calls, source-main
RELATIVE guest fixture write, original GNU_RELRO premature
mprotect denial, legitimate native owned-anonymous RO
protection, real munmap, and bounded original ld-linux
MOV/CALL/callee RW and stack restored W^X. There were no
native failure markers and the child exited 0.

The separate
[Android ARM64/Bionic ABI link-only CI #42236366354](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42236366354)
**completed SUCCESS**, from source commit
`dbb42e488aafe4b26e32bc288f82a142c08b16e0`.
It consumed the exact successful Linux evidence,
SHA-validated the official FEXCore Android original
upstream reference, compiled source-generated FEX headers,
assembled 11 authentic x86 syscall opcodes, cross-linked the
SAME Linux-functional C++ source for Android/Bionic AArch64,
and attested `/system/bin/linker64`, `libFEXCore.so` and
Bionic `libc.so` (not GNU libc). Artifact:
`KERNIX-G0-Original-FEX-X86-ELF-Openat-Pread-Read-Close-Bionic-BUILDONLY`;
there is NO new signed or installable APK in this build-only
artifact and NO physical-phone runtime proof.

Canonical evidence:
`evidence/g0-original-elf-snapshot-guest-openat-pread-read-close-linux-fex-and-android-bionic-pass-20261106.json`.
This replaces the preceding **PENDING** status for
`#42235659220` and proves the exact Android/Bionic
`#42236366354` crosslink gate succeeded.

**Critical next missing behavior**: original ELF source
`mmap` with guest file-backed offsets, correct source
PT_LOAD permission/ownership and W^X on both Android
native 4K and 16K host pages, followed by the GNU
`ld-linux` **actual full** relocation/symbol/IFUNC/TLS
and post-relocation original PT_GNU_RELRO work in the
embedded custom FEXCore process. Current source immutable
FD service is deliberately incomplete and cannot launch
arbitrary x86 ELF, Windows PE, Wine or Proton.
The previous full Linux upstream FEX positive genuine
GNU-relocation reference must not be relabeled as
Android guest-loader completion.

Keep user-proven already-signed
`org.kernix.diagnostics` v2 (same package/certificate),
stable KERNIX v0.27, prefixes and all installed games
untouched. No new partial signed v3 APK or forced phone
test until a materially new genuine original-loader
functional runtime step is proven.

## 2026-11-06 — original GNU ELF guest file mmap: true RO snapshot copy native kernel PASS, same FEX guest integration underway

Following original-x86 FEXCore source-verified
`openat/pread64/read/close` Linux runtime and independent
Android/Bionic AArch64 crosslink **PASS**, the same
`BoundedGuestAnonymousVM` was extended to materialize
only `MAP_PRIVATE|PROT_READ` source-pinned ELF **data**
for a synthetic guest FD. The file service
`SourceVerifiedGuestElfFDKernel` validates exact
guest Linux syscall `mmap(9)` with **R8=guest virtual FD**,
R9=source byte offset, not any native Linux/Bionic FD or
file path. The copy comes from the existing SHA256-attested
immutable anonymous source ELF snapshots. Native
`mmap(MAP_PRIVATE|MAP_ANONYMOUS,PROT_READ|PROT_WRITE)`
temporarily allocates a new **owner-tracked guest VMA**,
copies the trusted source bytes, then native
`mprotect(PROT_READ)` seals it before revealing any
address to x86. No host-file direct mapping, no
`MAP_FIXED`, no guest RW/RX/RWX executable file mapping,
no unowned interpreter/main/host/FEX JIT memory exposure.

The native host must be exactly 4K or 16K page-sized;
guest mapping length and offset must align to the
host-page granularity. On Android 16K host pages,
guest 4K file mapping is **strictly denied**, because
the correct software subpage permissions emulator
does not exist yet. This is a safety limitation, not
a performance-complete GNU ld-linux file mmap.

[Linux real-source native owner and Android/Bionic
AArch64 compile-only #42239605282](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42239605282)
**completed SUCCESS**. Verified the actual native kernel
mapping rights in `/proc/self/maps` as `r--p`,
exact original source bytes and SHA256,
source-file mutation cannot alter the mapped snapshot,
FD close preserves already-mapped guest-owned pages,
all guest memory write-upgrades and writes from
getrandom/pread64 are denied, and native guest
`munmap` cleanly releases the page. Original existing
guest mmap/mprotect/getrandom and source ELF FD
regressions also passed.

Source:
`android-host/kernix_g0_guest_owned_anonymous_vm_kernel.h`
and
`android-host/kernix_g0_source_verified_guest_elf_fd_kernel.h`.
Native test:
`android-host/tests/kernix_g0_original_source_elf_mmap_ro_snapshot_native_bionic_test.cpp`.
Canonical evidence:
`evidence/g0-source-elf-sha256-snapshot-guest-file-mmap-native-readonly-linux-and-bionic-buildonly-pass-20261106.json`.

New x86 guest assembly and FEXCore integration extends
the same source-locked FEX session to **13 real x86 Linux
syscall instructions**, adding native-readonly source ELF
file `mmap(9)`, actual x86 read from the resulting
`r--p` page, and `munmap(11)` before closing its
synthetic guest FD and reaching the prior FS/TLS,
source RELATIVE fixture, original-RELRO premature
denial and original bounded GNU ld-linux call.
[Real-FEX Linux ARM64 #42240746135](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42240746135)
is explicitly **UNPROVEN while CI is in progress**.
Do not report FEX guest opcode runtime PASS without
checking actual exit 0, correct source/kernel memory
permissions, and ordered semantic markers.

The file mmap is a DATA-ONLY bounded snapshot
implementation, not complete Linux ELF
`PT_LOAD` code mapping, shared-library discovery,
original GNU dynamic relocation/IFUNC/TLS completion
or post-linker genuine `PT_GNU_RELRO`.
No phone test, new same-signed Diagnostics APK,
Wine/Proton or game launch was claimed.
Preserve original signed Diagnostics v2, stable v0.27,
prefixes and game files.

## 2026-11-06 — exact original ELF64 PT_LOAD PF_RX source-snapshot native W^X PASS; authentic x86 guest gate underway

The previous 13-real-x86-syscall `PROT_READ` original
`ld-linux` ELF data snapshot was proven under source-pinned
FEXCore Linux ARM64 and subsequently independently cross-linked
against Android Bionic in
[CI #42241600150](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42241600150)
**SUCCESS**, with
`KERNIX-G0-Original-FEX-X86-ELF-Snapshot-File-Mmap-RO-Bionic-BUILDONLY`
artifact. This is NOT physical device execution.

The next guest service permits **only source-attested,
whole-host-native-page ELF64 PT_LOAD PF_R|PF_X non-PF_W pages** as
readable/executable RX on exact SHA256-verified main/ldlinux/libc
snapshots. The existing
`SourceVerifiedGuestElfFDKernel` revalidates the original
ELF64 header and each relevant PHDR
(`ELFCLASS64`, LSB, `EM_X86_64`, `ET_DYN/ET_EXEC`,
`e_phoff/e_phentsize/e_phnum`, proper `PT_LOAD`,
`p_filesz<=p_memsz`, native-host-aligned offset, and entire
source page strictly inside a source `PF_R|PF_X` non-writeable
segment), independently of any guest-supplied pathname or
synthetic virtual FD. Reject header, nonexec segment, outside
file, partial overlap, RW/RWX, `MAP_SHARED`, `MAP_FIXED`,
misaligned offsets and unsupported 4K x86 guest subpages
on 16K host kernel pages. No executable native mapping may
overlap any writable native host page.

The **same native owner-held VM allocator** copies original
immutable source-verified bytes first into non-executable
anonymous writable scratch, then native `mprotect`
converts the exact whole page to `PROT_READ|PROT_EXEC`
before revealing the guest address. The guest memory
rights tracker explicitly records read+execute and forbids
write. No original source ELF/JIT/Android host memory becomes
guest-writable or directly file-backed with a native FD.
Upgrade/downgrade `mprotect` on such source pages is
rejected and `munmap` remains exact owned-page only.

[Native original GNU ELF source Linux and Bionic compile
#42244231853](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42244231853)
**completed SUCCESS**. Real original source `PT_LOAD PF_R|PF_X`
file offsets were discovered from true ELF64 PHDRs.
Native `/proc/self/maps` showed `r-xp`; actual code bytes
matched independently-read original source bytes; write
attempts through original guest `pread64`, `getrandom`
and `mprotect` all failed, native guest file close preserved
the independent RX mapping, and exact guest-owned unmap
succeeded. Existing source data RO, guest virtual FDs and
anonymous mmap/mprotect/getrandom regression tests passed.
This test **compiled** with Android NDK/Bionic ARM64 but did
NOT execute on phone.

New original FEX guest test:
[real Linux ARM64 #42245358544](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42245358544)
is **PENDING**, not a verified runtime PASS at this edit.
It dynamically derives a genuine RX source page offset
from the SHA256-pinned source GNU `ld-linux` PHDRs and
assembles an x86 guest program using an original-authenticated
`--defsym` value rather than a guessed hardcoded constant.
Its actual x86 syscall stream has **15** entries in the same
upstream original FEXCore context. Two new x86 guest operations
request source ELF `mmap(9)` as native RX,
then perform a translated **x86 data load** of the original
RX source code bytes and `munmap(11)`. It must then
still complete all previously verified FS/TLS, true kernel
getrandom, source ELF IO, original guest RELA *fixture*,
early original-RELRO denial, legitimate guest heap
protection/unmap, bounded original source `ld-linux` MOV/CALL,
and native W^X cleanup gates. Actual original
`ld-linux` dynamic relocation and guest code execution
from this separately mapped RX page are explicitly
**not** claimed.

Canonical native evidence:
`evidence/g0-original-elf64-pf-rx-ptload-native-wx-snapshot-linux-bionic-compile-pass-20261106.json`.

**Still missing before games**: original complete GNU `ld-linux`
dependency search/relocation, IFUNC and NPTL TLS, executable
guest PT_LOAD lifecycle linked to the proper original
virtual addresses, host 16K guest 4K software subpage model,
safe original `PT_GNU_RELRO` after complete relocations,
Wine/Proton and any actual Windows game. Preserve the
original signed `org.kernix.diagnostics` v2, KERNIX v0.27,
other prefixes and all user game data.

## 2026-11-06 — real source ELF64 original PT_LOAD PF_R|PF_X, 15 guest syscalls and Android Bionic crosslink: PASS

The earlier pending native source RX and authentic real-FEX
gates **both closed**. [Real original FEXCore 15-guest-syscall
functional Linux ARM64 #42245358544](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42245358544)
**completed SUCCESS** from exact commit
`81da8e735823080d85effa70c0e0e08d76ab97ff`
(artifact
`KERNIX-G0-Original-FEX-Guest-ELF64-PTLOAD-RX-Native-WX-Linux-ARM64-only`).
An x86 guest assembled from GNU-as **actual x86 opcodes**
executed all 15 authenticated x86 Linux syscall traps
inside the same source-pinned original FEX ARM64 CPU context
and original main/ld-linux/libc SHA256-prepared guest windows.
The newly generated source `RX` mapping offset came from
the **real source GNU ld-linux ELF64 program headers**
(`PT_LOAD PF_R|PF_X`, full 4KB source-file page), not a
synthetic code section or hardcoded invented offset.
Original source bytes were anonymously copied into a new
owner-held guest mapping and native-sealed to
`PROT_READ|PROT_EXEC` (`r-xp`, not `rwxp`).
The FEX-translated x86 guest performed a real **data read**
of the genuine original code-page first qword and stored
it to a distinct authorized owned guest RW heap page;
the host compared the two before the exact guest
`munmap(11)`. A forged attempt to change that same
source RX page to RW was refused. All previous original
FS/TLS, entropy, virtual ELF file operations, source
RELATIVE fixture, original source premature RELRO denial,
native owned-anonymous protection and bounded original
`ld-linux` early callee tests remained functional.
The first candidate #42245276679 failed an exact Python
literal parsing check; corrected candidate
#42245358544 verified all ordered source/guest markers
and exit=0.

[Original FEX AArch64/Bionic native crosslink-only
#42246244003](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42246244003)
**completed SUCCESS** at exact workflow commit
`6b6bb57ec996b9aa611981392fd4f8a0c5034b75`
(artifact
`KERNIX-G0-Original-FEX-X86-ELF64-PTLOAD-RX-WX-Bionic-BUILDONLY`).
It independently verified the original source-Linux runtime
run, 15-entry x86 syscall machine code **byte-for-byte**
against the actual Linux functional artifact, official
source-pinned FEXCore Android sha256 proof, generated FEX
headers, AArch64 ELF machine and Bionic native linker and
library dependency closure. **No new APK was produced and
no physical REDMAGIC phone test was performed**.

Canonical unified audit:
`evidence/g0-original-x86-elf64-ptload-pf-rx-native-wx-real-fex-linux-and-bionic-linkonly-pass-20261106.json`.

**Important boundary:** A translated x86 guest **read of
original code bytes in native RX** is not execution of
original GNU `ld-linux` from that newly mapped page.
The narrowly bounded original `ld-linux` MOV/CALL callee
is a prior separately verified partial source test,
**not full original dynamic-linker self-relocation**.
Source `PT_LOAD` image layout, real virtual-address
placement/ASLR, symbol-version lookup, RELA/RELR,
full NPTL/DTV TLS/IFUNC and final original
`PT_GNU_RELRO` have not completed in the custom embedded
FEXCore process. Native 16KB host pages still reject
4KB guest subpage mappings; the exact per-subpage 4K/16K
write/execute policy must be implemented before broad
Android game runtime claims. Wine, Proton and any
Windows PC game have **not** launched from this path.

Continue using the existing signed
`org.kernix.diagnostics` v2 on the user's phone;
leave stable KERNIX v0.27, prefixes, signing secrets
and user game data untouched. No new phone test or
partial signed v3 release for this link-only milestone.
