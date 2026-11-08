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
| `0x800003fd0` | `puts` `JUMP_SLOT` | Yes, real ARM64 `STLR`, run 42507522722 | No | No |
| `0x800003fd8` | `__libc_start_main` `GLOB_DAT` | Yes, real ARM64 `STLR`, run 42507522722 | No | No |
| `0x800003fe0` | weak `_ITM_deregisterTMCloneTable` `GLOB_DAT` | Yes, genuine zero-to-zero ARM64 `STLR`, run 42508672243 | No | No |
| `0x800003fe8` | weak `__gmon_start__` `GLOB_DAT` | Yes, source-address native `STLR` candidate, run 42510226706 and independent classification 42511128388 | No | No |
| `0x800003ff0` | weak `_ITM_registerTMCloneTable` `GLOB_DAT` | **Unproven** at time of this matrix; isolated new hardware probe queued | No | No |
| `0x800003ff8` | weak `__cxa_finalize` `GLOB_DAT` (resolved source-libc target expected `0x8040472a0`) | **Unproven** at time of this matrix; isolated new hardware probe queued | No | No |

The parent source has two `RELATIVE`, five `GLOB_DAT` and one `JUMP_SLOT` inside the page. Source native x86 pre-mprotect values for eight slots were checked separately. Exact target matching, hardware store provenance, x86 guest writer provenance, and page protections are *separate* proof columns.

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
- Game first failure ledger: `native-engine/evidence/kernix-game-memory-failure-regression-cases-2026-11-08.json`.
