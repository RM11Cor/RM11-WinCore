# KERNIX G0 — Original GNU IFUNC137–140 four native writer source cohort

Date: 2026-11-10. Branch `kernix-native-engine-v1`.

## Immutable prior baseline
- **51/147 individually independently certified original GNU relocation writer targets**, **96 pending** as of [IFUNC133–136 independent replay #42840714050](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42840714050) and [source cohort ledger #42841326547](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42841326547).
- The prior four writers are individually traced in **four separate FEX Linux AArch64 guest processes**, sharing a pinned FEX build. Do not claim all 147 completed in a single guest, or a new original CALL → C3 RET → stack read sequence from these writer-only watches.
- Android/Bionic, Wine/Proton, Vulkan, APK install and games are not demonstrated by these Linux native diagnostics.

## Bounded batch IFUNC137–140
- Original SHA-locked GNU x86 libc DT_JMPREL IRELATIVE source indices **137, 138, 139, 140**; each must have its own unique original target qword and address-specific GDB native watch.
- SHA-locked source preflight [#42843898968](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42843898968) succeeded. **Zero new native writer proofs** from this source-only step.
- Real FEX ARM64 raw writer-run workflow [#42844323231](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42844323231) is the strict hardware stage, including four separate GDB-target-watch executions and artifact collection.
- Independent verifier [#42844416071](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42844416071) validates exact ELF SHA, source watches, FEX JIT/store provenance, chronologically armed/hit hardware watches, 40 counterfeit negative controls, and individually unique original targets.
- The 147-source cohort reconciliation workflow, `.github/workflows/kernix-g0-original-libc-147-source-ledger55-cohorts.yml`, consumes only the **successful** independent verifier plus all prior immutable proofs, and must remain fail-closed.

## Promotion rule
Only after genuine FEX ARM64 hardware run, independent verifier, AND source ledger reconciliation all pass should original writer evidence be promoted to **55/147**, **92 remaining**. Until then keep **51/147**. The 55 target-writer subtotal is not evidence of one original guest resolving all IFUNC/CALL/RET, all source relocation types, or Android games.

## Implementation files
- `native-engine/tools/kernix_g0_original_ifunc137_140_batch_source_only_native_writer_plans.py`
- `.github/workflows/kernix-g0-original-ifunc137-140-source-batch-preflight.yml`
- `native-engine/tools/kernix_g0_ifunc137_140_native_fex_writer_batch.sh`
- `native-engine/tools/kernix_g0_original_ifunc137_140_four_writer_batch_independent_gate.py`
- `.github/workflows/kernix-g0-original-ifunc137-140-four-writer-batch-independent.yml`
- `native-engine/tools/kernix_g0_original_libc_147_ledger55_after_sixteen_native_batch.py`
- `.github/workflows/kernix-g0-original-libc-147-source-ledger55-cohorts.yml`
