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
| `0x800003db8` | `RELATIVE#0` (+`0x1160`) | **Candidate** native `STLR` stores in run 42510226706; early harness fixture writes this slot, not original-loader provenance | No | No |
| `0x800003dc0` | `RELATIVE#1` (+`0x1120`) | Yes, true source-address ARM64 `STLR`, run 42508672243 | No | No |
| `0x800003fd0` | `puts` `JUMP_SLOT` | Yes, native ARM64 `STLR`, runs 42507522722 and 42513285101 | **Yes, exact original GNU x86 writer `0x80100fb8b`**, native register target `0x800003fd0` and value `0x804087bc0` (run 42513285101) | No |
| `0x800003fd8` | `__libc_start_main` `GLOB_DAT` | Yes, native ARM64 `STLR`, runs 42507522722 and 42512834255 | **Yes, one exact original x86 GNU ld-linux writer at `0x80100fb8b`** (`mov [rax],r9`, source-locked guest JIT RIP map, real ARM64 hardware trap, run 42512834255) | No |
| `0x800003fe0` | weak `_ITM_deregisterTMCloneTable` `GLOB_DAT` | Yes, genuine zero-to-zero ARM64 `STLR`, run 42508672243 | No | No |
| `0x800003fe8` | weak `__gmon_start__` `GLOB_DAT` | Yes, source-address native `STLR` candidate, run 42510226706 and independent classification 42511128388 | No | No |
| `0x800003ff0` | weak `_ITM_registerTMCloneTable` `GLOB_DAT` | **Yes, source-address AArch64 zero-to-zero native hardware `STLR` candidate**, run 42511385251; source-guest writer RIP still unproven | No | No |
| `0x800003ff8` | weak `__cxa_finalize` `GLOB_DAT` (resolved source-libc target expected `0x8040472a0`) | **Yes, source-address AArch64 native hardware `STLR` candidate** reaching expected nonzero libc pointer, run 42511385251; GNU source guest RIP not proven | No | No |

The parent source has two `RELATIVE`, five `GLOB_DAT` and one `JUMP_SLOT` inside the page. Source native x86 pre-mprotect values for eight slots were checked separately. **All eight distinct original source page addresses have native ARM64 JIT `STLR` candidate events across four bounded FEX diagnostic processes**, independently replayed by source-pinned 8-slot aggregate gate [#42511987660](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42511987660). This is *not* proof of all eight original x86 GNU ld-linux source writer instructions, nor same-process linker completion. Exact target matching, hardware store provenance, x86 guest writer provenance, and page protections are *separate* proof columns.


## Two independently proven original main targets with original GNU x86-64 writer RIPs (2026-11-08)

The source-pinned real Linux ARM64 FEX gate [#42512834255](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42512834255) **succeeded** and independently reconciled one original main strong `GLOB_DAT` store:

- Original source x86 GNU `ld-linux-x86-64.so.2` instruction `mov QWORD PTR [rax],r9` at source-derived guest RIP `0x80100fb8b` (`ld-linux` file offset `0xfb8b`), with original source bytes `4c 89 08`.
- Under the original source-pinned FEX ARM64 JIT, the watched native `stlr x13,[x4]` has register values `x4=0x800003fd8` and `x13=0x80402a200`. The source FEX host-to-guest JIT map, live native PC, original ldso SHA, x86 opcode and pinned x86-to-ARM64 register ownership were independently reconciled.
- A distinct source-original main `puts` `JUMP_SLOT` store, `0x800003fd0` ← `0x804087bc0`, was independently proven through the same original GNU ld-linux x86 opcode and JIT writer RIP by [#42513285101](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42513285101). The same source instruction `0x80100fb8b` can write different GOT slots in separate genuine FEX processes.
- An [independent two-receipt replay #42513682685](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42513682685) **succeeded**, verifying distinct original main addresses and relocation types `GLOB_DAT` and `JUMP_SLOT` with **14 adversarial false-proof mutations rejected**. These are **two** exact source-guest writer proofs out of eight original page destinations, in **separate bounded diagnostic runs**. The other six addresses have **no independently established original GNU x86 guest writer RIP in this matrix**. In particular the `RELATIVE#0` diagnostic fixture must never count as original GNU ld-linux.
- Original GNU main `mprotect(10)` success remains **unproven**, and the page remains **not authentically sealed**. The Linux diagnostic is not a Windows/Proton/Android gameplay test.

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
- Game first failure ledger: `native-engine/evidence/kernix-game-memory-failure-regression-cases-2026-11-08.json`.
