# KERNIX G0 — original GNU IFUNC141–144, four candidate native hardware writers

Date: 2026-11-10. Branch: `kernix-native-engine-v1`.

## Immutable prior evidence
- Original GNU x86 libc SHA-locked writer target source ledger: **55/147 independently native-writer-attested**, **92** needing independent Linux ARM64 native writer evidence. Proofs from [four original IFUNC137–140 independent ARM64 FEX hardware watches #42844416071](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42844416071) and [complete source ledger reconciliation #42844658528](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42844658528). Four targets were from four separate FEX guest processes; not one all-relocation process.

## New bounded IFUNC141–144 batch
1. Original immutable x86 libc DT_JMPREL `R_X86_64_IRELATIVE` source addresses at exact indices **141, 142, 143 and 144**. [Exact SHA256-pinned source-only watches #42848255406](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42848255406) **SUCCESS**, zero new native attestations by itself.
2. Genuine Linux AArch64 FEX hardware write watch runner [#42848623323](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42848623323), four separate GDB guest watch sessions, using one pinned FEX ARM64 compilation. Strict prior proof dependencies; raw logs are not yet independent attestations.
3. Independent source-to-native verifier [#42848697286](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42848697286): exact original ELF/source watch bytes, target addresses, original JIT store semantics, native register/watch hit, chronological GDB evidence, per-index receipts, and **40 intentionally corrupted logs rejected**.
4. Original 147-source reconciliation [#42848940520](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42848940520) requires independent native success and preserves all prior evidence. No new FEX execution is caused by source inventory.

**Certification policy:** Hold at **55/147** until genuine native watch, independent 40-negative-control proof, and 147-source ledger reconciliation all succeed. Only after all gates would this batch prove **59/147** distinct original writer target locations, leaving **88** pending: **85 non-IFUNC DT_RELA targets** plus original IFUNC source indices **85, 145 and 146**.

## Non-claims
This stage does not prove every relocation in one guest process, original guest CALL/C3 RET/stack READ for these new resolvers, completed GNU loader, Android/Bionic 16KiB-page operation, Wine/Proton, Vulkan/DX12, APK install, or playable Windows games.

## New source and CI files
- `native-engine/tools/kernix_g0_original_ifunc141_144_batch_source_only_native_writer_plans.py`
- `native-engine/tools/kernix_g0_ifunc141_144_native_fex_writer_batch.sh`
- `native-engine/tools/kernix_g0_original_ifunc141_144_four_writer_batch_independent_gate.py`
- `native-engine/tools/kernix_g0_original_libc_147_ledger59_after_twenty_native_batch.py`
- `.github/workflows/kernix-g0-original-ifunc141-144-source-batch-preflight.yml`
- `.github/workflows/kernix-g0-original-ifunc141-144-four-writer-batch-independent.yml`
- `.github/workflows/kernix-g0-original-libc-147-source-ledger59-cohorts.yml`
