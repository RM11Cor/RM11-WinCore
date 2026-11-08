# KERNIX G0 — original source main ELF: exact eight PT_GNU_RELRO relocation stores

**Scope:** source-authentic main GNU Linux x86-64 ELF SHA256
`9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412`,
source original FEX commit `02e24ca5c01ed0c864466ed573db347336f70170`.
Only this executable's **eight addresses on its aligned RELRO page** are considered.
An unrelated source main ninth dynamic relocation at `0x800004008` is outside this page.

## Non-promotable evidence classes

- A source ELF record and matching guest memory value prove **a final-state match**, not the writer.
- Native AArch64 GDB hardware access watchpoints and preceding `STLR` instructions with matching base/source register contents prove **an ARM64 JIT memory store** to that original slot. They do **not** prove the original x86 ld-linux instruction/source RIP, symbol binding order, or RELRO sealing.
- A **zero-to-zero** relocation is never proved by a zero snapshot. A genuine write watch must fire.
- A known early diagnostic fixture writes main `RELATIVE#0` before the runtime handoff. A native write there cannot automatically be attributed to unmodified original GNU ld-linux even when the destination is source-original.
- The existing G0 runtime intentionally stops at original x86 syscall `mprotect(10)`, returning host diagnostic exit 117. It is **not** a successful guest `mprotect(PROT_READ)`.
- No evidence below proves Wine/Proton, Android on-device game launch, DXVK/VKD3D, or real game FPS.

## Exact page target matrix

| Original main guest destination | Source ELF relocation | Observed native ARM64 FEX source-address hardware write | Original x86 GNU loader writer RIP independently attested | Genuine final-page RELRO seal |
| --- | --- | --- | --- | --- |
| `0x800003db8` | `RELATIVE#0` (+`0x1160`) | **Candidate** native `STLR` stores in run 42510226706; early harness fixture writes this slot, not original-loader provenance | **Yes, in the original one-FEX-process source trace**: after an authored early fixture write, original GNU ld-linux independently re-stored the *same value* using source guest x86 RIP `0x80100f91c` (`mov [rsi],rcx`), real AArch64 hardware access `STLR` and pinned original JIT source mapping. Source first fixture never counts. Run 42489056749, replay 42514856521 | No |
| `0x800003dc0` | `RELATIVE#1` (+`0x1120`) | Yes, true source-address ARM64 `STLR`, run 42508672243 | **Yes**, source original ld-linux guest x86 RIP `0x80100f91c`, `mov [rsi],rcx`, live original RELATIVE#1 source FEX ARM64 STLR hardware trap. Run 42489056749, replay 42514856521 | No |
| `0x800003fd0` | `puts` `JUMP_SLOT` | Yes, native ARM64 `STLR`, runs 42507522722 and 42513285101 | **Yes**, exact original GNU ld-linux writer x86 RIP `0x80100fb8b` with real FEX AArch64 STLR `puts` destination and libc export, runs 42489056749 and 42513285101, replay 42514856521 | No |
| `0x800003fd8` | `__libc_start_main` `GLOB_DAT` | Yes, native ARM64 `STLR`, runs 42507522722 and 42512834255 | **Yes**, exact original GNU ld-linux writer x86 RIP `0x80100fb8b` with real FEX AArch64 STLR `__libc_start_main`, runs 42489056749 and 42512834255, replay 42514856521 | No |
| `0x800003fe0` | weak `_ITM_deregisterTMCloneTable` `GLOB_DAT` | Yes, genuine zero-to-zero ARM64 `STLR`, run 42508672243 | **Yes**, original GNU ld-linux x86 RIP `0x80100fb8b`, real native source FEX STLR *zero-to-zero access watch* and source x86 opcode, one-FEX-process capture 42489056749, replay 42514856521 | No |
| `0x800003fe8` | weak `__gmon_start__` `GLOB_DAT` | Yes, source-address native `STLR` candidate, run 42510226706 and independent classification 42511128388 | **Yes**, original GNU ld-linux x86 RIP `0x80100fb8b`, real native source FEX STLR *zero-to-zero access watch* and source x86 opcode, one-FEX-process capture 42489056749, replay 42514856521 | No |
| `0x800003ff0` | weak `_ITM_registerTMCloneTable` `GLOB_DAT` | **Yes, source-address AArch64 zero-to-zero native hardware `STLR` candidate**, run 42511385251; source-guest writer RIP still unproven | **Yes**, original GNU ld-linux x86 RIP `0x80100fb8b`, real native source FEX STLR *zero-to-zero access watch* and source x86 opcode, one-FEX-process capture 42489056749, replay 42514856521 | No |
| `0x800003ff8` | weak `__cxa_finalize` `GLOB_DAT` (resolved source-libc target expected `0x8040472a0`) | **Yes, source-address AArch64 native hardware `STLR` candidate** reaching expected nonzero libc pointer, run 42511385251; GNU source guest RIP not proven | **Yes**, original GNU ld-linux x86 RIP `0x80100fb8b`, real source FEX ARM64 STLR to original GOT and libc export `0x8040472a0`, capture 42489056749, replay 42514856521 | No |

The parent source has two `RELATIVE`, five `GLOB_DAT` and one `JUMP_SLOT` inside the page. Source native x86 pre-mprotect values for eight slots were checked separately. **All eight distinct original source page addresses have native ARM64 JIT `STLR` candidate events across four bounded FEX diagnostic processes**, independently replayed by source-pinned 8-slot aggregate gate [#42511987660](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42511987660). This is *not* proof of all eight original x86 GNU ld-linux source writer instructions, nor same-process linker completion. Exact target matching, hardware store provenance, x86 guest writer provenance, and page protections are *separate* proof columns.


## Two independently proven original main targets with original GNU x86-64 writer RIPs (2026-11-08)

The source-pinned real Linux ARM64 FEX gate [#42512834255](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42512834255) **succeeded** and independently reconciled one original main strong `GLOB_DAT` store:

- Original source x86 GNU `ld-linux-x86-64.so.2` instruction `mov QWORD PTR [rax],r9` at source-derived guest RIP `0x80100fb8b` (`ld-linux` file offset `0xfb8b`), with original source bytes `4c 89 08`.
- Under the original source-pinned FEX ARM64 JIT, the watched native `stlr x13,[x4]` has register values `x4=0x800003fd8` and `x13=0x80402a200`. The source FEX host-to-guest JIT map, live native PC, original ldso SHA, x86 opcode and pinned x86-to-ARM64 register ownership were independently reconciled.
- A distinct source-original main `puts` `JUMP_SLOT` store, `0x800003fd0` ← `0x804087bc0`, was independently proven through the same original GNU ld-linux x86 opcode and JIT writer RIP by [#42513285101](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42513285101). The same source instruction `0x80100fb8b` can write different GOT slots in separate genuine FEX processes.
- An [independent two-receipt replay #42513682685](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42513682685) **succeeded**, verifying distinct original main addresses and relocation types `GLOB_DAT` and `JUMP_SLOT` with **14 adversarial false-proof mutations rejected**. These are **two** exact source-guest writer proofs out of eight original page destinations, in **separate bounded diagnostic runs**. Those earlier isolated diagnostic processes by themselves did not prove the other addresses; the later independent *single-process nine-writer replay* below does. In particular the `RELATIVE#0` diagnostic fixture must never count as original GNU ld-linux.
- Original GNU main `mprotect(10)` success remains **unproven**, and the page remains **not authentically sealed**. The Linux diagnostic is not a Windows/Proton/Android gameplay test.

## Independent complete 8/8 source-x86-writer replay — source-locked real GNU loader, 2026-11-08

The older original FEX Linux ARM64 [real hardware run #42489056749](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42489056749) proves **nine exact source-original GNU ld-linux x86 writer events in one FEX guest process**. The original main has **nine** dynamic relocation targets total: **eight inside original main \`PT_GNU_RELRO\`**, plus source \`RELATIVE#2\` at \`0x800004008\` **outside** the page. Each hardware watch has original GNU ldso source x86 bytes, a JIT PC-to-guest-RIP map, actual live native \`STLR\` destination/source registers and ordered traps. Three zero-valued weak GLOB_DAT stores have true hardware access events rather than only zero snapshots.

The deliberately authored early \`RELATIVE#0\` fixture was detected **before** original GNU ld-linux, and its first write was excluded. The genuine original dynamic loader then re-wrote \`RELATIVE#0\` *with the same value*, via authenticated original ld-linux x86 \`mov [rsi],rcx\`, measured with a separate native access watch. The [independent replay #42514856521](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42514856521) **succeeded** with **34 false-proof mutations rejected**; it cross-checks the previous genuine eight-store nonfixture source trace [#42514657143](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42514657143).

**This is 8/8 original GNU x86 writer events for the original main RELRO page, NOT complete dynamic linker state.** The one-process source inventory includes 1,237 original main/ldso/libc relocation targets. The original main nine stores do **not** establish closure of all other GNU ldso/libc RELR, RELA, JUMP_SLOT, IRELATIVE and IFUNC source writers. The next original x86 \`mprotect(10)\` on \`0x800003000\` remains **unexecuted/unsupported in the bounded embedded FEX diagnostic**. Original main \`PT_GNU_RELRO\` remains unsealed; no Android Bionic/Wine/Proton/game compatibility claimed.

## Original triad completion and safe RELRO sealing — still blocked

The [independent original GNU triad source-closure hold gate #42515110190](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42515110190) **succeeded** with **20 adversarial premature-RELRO-release mutations rejected**. It reconciles the real same-FEX-process nine main writer instructions against the original SHA-pinned **1,237 source relocation targets**:

| Original ELF module | Source relocation targets | Original GNU guest writer attestation in this one diagnostic process |
| --- | ---: | --- |
| Main executable | 9 | **9 exact guest x86 source writer events**, 8 inside the main RELRO page, 1 outside |
| Original GNU ld-linux | 14 | Source final states / RELR and RELA read-only inventory; individual original ldso writer RIPs and self IRELATIVE resolver unproven |
| Original GNU libc | 1,214 | Source final states and selected independent native evidence, **not** a complete original guest writer RIP/IFUNC execution audit |
| **Total** | **1,237** | No full-process closure proof |

The remaining 1,228 source destinations were **not individually attested as original GNU writer events in this same nine-main-store trace**, which does **not** establish that they were unexecuted. Specifically the original ldso IRELATIVE source-zero slot and all libc IFUNC executions remain unresolved to a sufficient end-to-end level. Main guest \`mprotect(10)\` at \`0x800003000\`, \`len=0x1000\`, \`PROT_READ\` is sourced and requested but **not genuinely executed** by the bounded embedded diagnostic. This page must not be marked read-only based only on source qword matches. Before granting it, prove closure of writes affecting **this original main page** (not original GNU ldso's later self-IRELATIVE), source-authenticated original VMA ownership, authentic guest syscall result, denied post-seal write, and correct 4KB/16KB page protection safety.

## Stage-correct original main mprotect(10) gate — native 4K / 16K preflight PASS, actual seal OPEN

[CI #42516102538](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42516102538) executed **three successful jobs**: C++17 policy tests on native Linux x86-64 and Linux ARM64, plus independent source-pinned native-x86-vs-FEX chronology replay. The tests reject **39 unauthorized/unaligned/aliased protection plans** and **18 false source chronology claims**. Files:

- Pure plan (no host syscall): `native-engine/android-host/kernix_g0_original_main_relro_stage_mprotect_plan.h`.
- C++ safety tests: `native-engine/android-host/tests/kernix_g0_original_main_relro_stage_mprotect_plan_test.cpp`.
- Pinned source differential classifier: `native-engine/ci/kernix_g0_original_main_relro_stage_order_preflight.py`.

**Correction to the too-broad full-triad seal prerequisite:** The original native-x86 GNU chronology is (a) 46 original libc IRELATIVE stores, (b) successful original libc `mprotect(10)`, (c) successful original **main** `mprotect(10)`, (d) original GNU ldso *own* IRELATIVE resolver and same-value zero store, (e) later original ldso protection. Source-original GNU embedded FEX on Linux ARM64 reaches (c) with guest RIP `0x801025db9`, source main guest page `0x800003000`, size `0x1000`, `PROT_READ`, but deliberately **does not execute this native kernel protection**. Insisting that all **1,237 main/ldso/libc** relocations, including *later* ldso self IRELATIVE, must be closed before main RELRO mprotect could deadlock correct GNU loader sequencing.

For the **original main page only**, precondition is its source-original relocation writes finished in the authentic stage, independently authenticated source GNU loader x86 syscall and PT_GNU_RELRO ownership, and a native page permission plan that cannot affect neighboring mappings. Later ldso self IRELATIVE and its own protection are distinct phases. The new plan **never calls host mprotect**, **never returns guest RAX=0**, and **never reports sealed original main RELRO**. On 4KiB native host pages, this is merely an *eligibility plan* pending actual live ownership and native syscall return. On 16KiB native host pages, ordinary 4KiB guest RELRO protection is **rejected** unless a future independently verified subpage isolation/protection technique can guarantee no collateral permissions changes. Do not round one 4KiB guest page to 16KiB and clobber adjacent guest RW/RX memory.

**Next executable gate:** in one bounded real original-FEX Linux ARM64 process on a supported native page layout, combine nine authenticated original-main dynamic writes with live source-original ELF page ownership, exact x86 syscall 10 guest trap, actual kernel mprotect success, read-only native VMA readback and a safe child process write-denial test. Only then may guest success be returned and execution proceed to source GNU ldso self IRELATIVE resolver `0x80101a8e0` and zero-store writer `0x80100fd60`. This gate remains OPEN, as do Android, host 16KiB, Wine/Proton and real game readiness.

## Actual isolated native kernel write-denial of the SHA-pinned source main ELF page — PASS, not guest FEX

The [independent x86-64 + ARM64 Linux jobs #42516492044](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42516492044) succeeded with the exact SHA256-locked original x86-64 main ELF file from the archived real FEX source bundle (`9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412`). In each kernel-run test `native-engine/android-host/tests/kernix_g0_source_elf_relro_owned_native_kernel_write_denial_linux.cpp`:

- Source ELF header, segment bounds, `PT_GNU_RELRO` and the eight original file-backed slots were checked; original qword values were matched and their known relocated guest values were staged on an exclusively owner-held anonymous native 4KiB surrogate mapping (no `MAP_FIXED`, no modification of original ELF).
- An actual Linux native kernel `mprotect(PROT_READ)` changed that 4KiB test-owned page to `r--p` and preserved the writable sibling 4KiB page as `rw-p`.
- A separate child process attempting to write the now-RO native page exited on **actual `SIGSEGV`**, while the parent verified all eight staged values and could still modify the sibling writable page.
- Both jobs ran on 4KiB native host-page Linux; the implementation refuses native 16KiB host pages rather than rounding a 4KiB x86 guest protection up to a larger host span.

This is **real kernel mprotect and real post-protect write denial on an isolated test-owned *surrogate* original-main ELF staging page**. It **does not** prove genuine FEX guest x86 syscall(10) ran or succeeded, original guest main PT_GNU_RELRO was sealed, original GNU loader continued to its own self IRELATIVE, Android phone 4K/16K memory mapping worked, or Windows games started. The next genuine guest gate remains open; replace only a source-owner-attested live guest VMA in a bounded real original FEX process and require actual authorized kernel success / denied writes before returning guest RAX=0.

## Genuine original GNU main RELRO guest x86 mprotect(10) running in FEX — Linux AArch64 4KiB PASS

**NEW source-authentic real guest execution**, not a host surrogate: [GitHub Actions #42517719335](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42517719335) **succeeded**. A separately compiled *opt-in experimental* source-pinned original FEXCore Linux ARM64 process loaded SHA-locked original Linux x86-64 main, original GNU ld-linux and libc. The original interpreter genuinely issued x86 syscall(10) from guest RIP `0x801025db9` with `rdi=0x800003000`, `rsi=0x1000`, `rdx=PROT_READ`. The existing original libc source RELRO range had already been protected by real native kernel `mprotect`. The new source main handler:

- Authenticated original source GNU loader syscall byte `0f05`, original-ELF RW VMA identity/PT_GNU_RELRO page, exact guest syscall and real 4KiB native host pages.
- Checked **all eight exact source-original main relocation qword values in this same FEX process**. These checks are **value matches**, not an independent, in-process per-store guest RIP tracing in this new run. Prior [source-locked hardware writer provenance run #42489056749](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42489056749) separately attested the guest writers.
- Issued real Linux native `mprotect(0x800003000,4096,PROT_READ)`, verified native `r--p`, ensured `0x800004000` stayed `rw-p`, and re-read all original page GOT/RELATIVE values.
- Forked a disposable child process (with default SIGSEGV handler) that attempted to write to the **actual original main live FEX-owned guest page**. The child exited on real kernel `SIGSEGV`. The parent updated original guest x86 `RAX=0` and RIP to the authenticated next x86 instruction **only after these native checks succeeded**.

Source under `native-engine/android-host/kernix_g0_original_main_relro_real_fex_guest_mprotect_seal.h` and **experimental compile macro only** `KERNIX_G0_EXPERIMENTAL_REAL_SOURCE_MAIN_RELRO_GUEST_MPROTECT10` in the existing bounded original FEX diagnostic. Stable engine launch and Android runtime are untouched. Kernel 4KiB support is proven in Linux ARM64 only; ordinary 16KiB native host pages are **rejected**.

**The x86 guest then resumed beyond main RELRO to the next GNU interpreter self-range protection request**, `0x801036000`. The existing main-only source audit correctly refused this *new* distinct request (`KERNIX_G0_REAL_NEXT_MAIN_RELRO_SOURCE_AUDIT_REJECT`, bounded stop exit 177), rather than silently granting protection to ld-linux. The [independent replay #42518571783](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42518571783) **succeeded** and rejected **18 corrupted evidence / false readiness cases**. The reference original native-x86 chronology proves GNU ldso's own self IRELATIVE resolver/store would normally run **after** original main protection and **before** this later ldso self protection. But this FEX run did **not** independently trace its actual original x86 self-IRELATIVE guest RIP `0x80101a8e0` nor the zero-to-zero source writer `0x80100fd60` targeting `0x801036360`. These remain **unproven under FEX**; never substitute the next syscall request for proof that a zero-to-zero guest store happened. Original full-process dynamic relocation closure, Linux guest program exit zero, native Android/16K, Wine/Proton and Windows games remain open.

**Next gate:** in one bounded source-pinned Linux ARM64 FEX process, place a real native hardware *access* watchpoint on GNU ldso's own `0x801036360` before original main protection, follow past the authenticated RO page, attest actual original GNU guest x86 self-resolver instruction and live original zero-to-zero `STLR` writer, and only then consider an individually authenticated original GNU ldso self `PT_GNU_RELRO` protection. Maintain page owner checks and no arbitrary guest mprotect dispatch.

## Original GNU ld-linux own IRELATIVE zero-to-zero **source x86 writer** under real FEX — Linux ARM64 hardware PASS

The [authentic original FEX ARM64 hardware GDB run #42519037018](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42519037018) captured a true **post-main-RELRO** source GNU ld-linux store to the original self-IRELATIVE `R_X86_64_IRELATIVE` target `0x801036360`, whose source resolver record points to `0x80101a8e0`. The FEX-native process had already printed the genuine original main source x86 guest `mprotect(10)` kernel success and the child post-seal write denial. An actual ARM64 hardware-access watchpoint on `0x801036360` then stopped at host PC `0xffffa4ce96a4` **after** native `STLR x4, [x19]` at `0xffffa4ce96a0`; live registers were exactly `x4=0` and `x19=0x801036360`. The guest slot was `0` both before and after, so a passive memory snapshot could not prove this write.

The **original pinned FEX JIT native-to-guest mapping** of the stopped native store has `guest_entry=0x80100fd60`, `guest_size=3`, and the corresponding exact original source ld-linux x86 instruction bytes at that guest RIP are `49 89 06` (`mov %rax,(%r14)`). The original source resolver code at guest RIP `0x80101a8e0` has source-equal live entry bytes `f3 0f 1e fa` (ENDBR64). Together with the hardware store and register proof this authenticates the **actual original GNU source x86 zero-to-zero writer instruction under FEX**, rather than merely a source code candidate or an unchanged zero qword.

The original long-running hardware workflow's *first* attempt reported failure because its Python event counter mistook GDB's `-location` text on an actual hardware stop for registration; it was **not** a runtime JIT/store failure. The [independent archived hardware classifier #42519965637](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42519965637) subsequently **succeeded**, requiring same-run ordering, SHA-verified exact original source, live `STLR` and registers, one-opcode guest RIP map, source guest RX opcode, and **20 deliberately falsified evidence rejections**. The original source capture includes the GDB log and bounded native hardware receipt.

**Strict boundaries:** The resolver's entry (`0x80101a8e0`) and return have **not been independently traced as guest execution events in this FEX run**, even though the later original writer is now proven. The original GNU ldso's own next source mprotect request at `0x801036000` is observed from separate uninterrupted real FEX continuation but **not executed/sealed**. The complete 1,237 source relocation triad, final guest process exit zero, 16KiB host Android memory ownership, Wine/Proton and PC games remain unproven. Next: pin exact original ldso `PT_GNU_RELRO` page and real source syscall arguments, then add narrowly authorized 4KiB self-page protection only after live original zero writer/owner authentication and test a denied write. Do not treat the current source instruction evidence as permission for a broad guest mprotect dispatcher.

## Release and next-stage gates

1. Keep the native ARM64 store matrix distinct from x86 guest writer RIP attribution. Every newly observed store must retain actual GDB hardware event, PC, disassembly, source-base register, source-value register, original source ELF hashes, and target ownership.
2. Keep the diagnostic fixture `RELATIVE#0` contamination explicit. Do not claim original GNU ld-linux writer without a tracked guest x86 RIP instruction tied to the trap.
3. After the remaining slots, prove genuine guest syscall `mprotect(10)` success with source-owned `PT_GNU_RELRO` ranges, valid host/guest 16K/4K permission policy, W^X, and actual write-denial tests before claiming a seal.
4. Keep game-memory first-failure triage independent: unknown guest VA reservations and black screens are not proof of physical RAM OOM, VRAM exhaustion, or a translation defect. Record causal first failing operation before choosing a patch.
5. Do not advance the Android Windows game release readiness gate merely because the underlying Linux source ELF linker reaches or passes this diagnostic milestone.

## Anchors

- Source `puts` + `__libc_start_main` native hardware proof: https://github.com/RM11Cor/RM11-WinCore/actions/runs/42507522722
- Source `RELATIVE#1` + `_ITM_deregisterTMCloneTable` native hardware proof: https://github.com/RM11Cor/RM11-WinCore/actions/runs/42508672243
- Source `RELATIVE#0` + `__gmon_start__` hardware capture: https://github.com/RM11Cor/RM11-WinCore/actions/runs/42510226706
- Independent classifier and 22 deliberate false-proof tests: https://github.com/RM11Cor/RM11-WinCore/actions/runs/42511128388
- Original GNU x86 `GLOB_DAT` writer proof: https://github.com/RM11Cor/RM11-WinCore/actions/runs/42512834255
- Original GNU x86 `puts JUMP_SLOT` writer proof: https://github.com/RM11Cor/RM11-WinCore/actions/runs/42513285101
- Independent two-slot cross-run guest RIP and fourteen negative controls: https://github.com/RM11Cor/RM11-WinCore/actions/runs/42513682685
- Source original final two slots ARM64 hardware watch and standalone 22 adversarial false-proof checks: https://github.com/RM11Cor/RM11-WinCore/actions/runs/42511385251
- Independent 8/8 cross-pair matrix: https://github.com/RM11Cor/RM11-WinCore/actions/runs/42511987660
- One source-locked FEX nine original loader writer events, eight within main RELRO: https://github.com/RM11Cor/RM11-WinCore/actions/runs/42489056749
- Independent 8/8 original GNU x86 writer replay and 34 adversarial negatives: https://github.com/RM11Cor/RM11-WinCore/actions/runs/42514856521
- Original 1237 triad source census vs nine main writers, 20 false mprotect/RELRO promotions blocked: https://github.com/RM11Cor/RM11-WinCore/actions/runs/42515110190
- Original-main stage-correct preflight, 39 native C++ negatives and 18 source chronology negatives: https://github.com/RM11Cor/RM11-WinCore/actions/runs/42516102538
- Real Linux x86-64 and ARM64 isolated SHA-pinned source ELF page mprotect/write-denial, not guest FEX: https://github.com/RM11Cor/RM11-WinCore/actions/runs/42516492044
- Real source original GNU x86 FEX guest main RELRO mprotect kernel + child SIGSEGV proof: https://github.com/RM11Cor/RM11-WinCore/actions/runs/42517719335
- Independent post-main next-ldso self mprotect source stage + 18 adversarial controls: https://github.com/RM11Cor/RM11-WinCore/actions/runs/42518571783
- Original FEX guest ldso zero-to-zero writer hardware trace: https://github.com/RM11Cor/RM11-WinCore/actions/runs/42519037018
- Independent source x86 RIP to native STLR classifier with 20 false-proof rejections: https://github.com/RM11Cor/RM11-WinCore/actions/runs/42519965637
- Game first failure ledger: `native-engine/evidence/kernix-game-memory-failure-regression-cases-2026-11-08.json`.
