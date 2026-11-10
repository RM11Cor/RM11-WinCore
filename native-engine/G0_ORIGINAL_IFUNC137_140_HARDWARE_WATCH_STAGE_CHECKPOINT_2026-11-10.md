# KERNIX G0 — Original GNU IFUNC137–140 independently completed native writer batch

Date: 2026-11-10. Branch `kernix-native-engine-v1`.

## Verified independent evidence chain

1. **Prior baseline:** 51/147 distinct original GNU relocation writer targets separately attested, with 96 pending, through [IFUNC133–136 independent replay #42840714050](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42840714050) and [47+4 source reconciliation #42841326547](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42841326547).
2. **Original SHA-locked source-only IFUNC137–140 watch plans:** [#42843898968](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42843898968) **SUCCESS**, four source-distinct ELF relocation target qwords and per-index GDB watches. This plan alone contributed **zero** native attestations.
3. **Real Linux ARM64 FEX original GNU writer hardware executions:** [#42844323231](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42844323231) **SUCCESS**, four distinct hardware watch sessions in **four separate FEX x86 guest processes**, sharing one source-pinned Linux AArch64 FEX build. Raw watch logs, copied source plans and debugger exits preserved in CI artifact. The prior large-workflow audit [#42844323018](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42844323018) **SUCCESS**; comments only were trimmed to remain within the GitHub Actions YAML size limit while retaining the existing execution stages.
4. **Independent anti-forgery source/native proof:** [#42844416071](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42844416071) **SUCCESS** with four separate source-sha/native-JIT/hardware-write receipts and **40 deliberately corrupted log cases rejected**. This establishes a **55/147** original GNU writer-location subtotal, without asserting same-guest relocation completion.
5. **Exact 147 original source relocation cohort ledger reconciliation:** [#42844658528](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42844658528) **SUCCESS**; no double-counted source targets, **55 individually independently certified original writer locations and 92 awaiting independent native writer evidence**. The inventory ledger produced **zero** new hardware executions by itself.

## Strict scope
- These are **original GNU x86 libc relocation writer hardware watches under Linux AArch64 FEX**. They do not demonstrate all relocations executed in one guest process or a full GNU loader startup. Four in this batch were separate FEX guest processes.
- No additional original same-process CALL → x86 C3 RET → native stack hardware READ proof is certified for IFUNC137–140 by the writer-only batch.
- G0/G1 whole-loader and guest memory correctness, Android/Bionic, Wine/Proton, Vulkan/DirectX, signed APK, game frame/input/FPS all remain separate unfulfilled release gates. Never claim an Android game is playable from these Linux CI runs.
- Remaining source targets: **85 non-IFUNC DT_RELA source records plus 7 IFUNC source indices (85 and 141–146)**, total **92**. Keep the earlier proof scope/compatibility policy intact.

## Next isolated step
Original GNU IFUNC **141–144** source-only candidate watch plans first, then actual ARM64 FEX writer sessions, independent negative-control source/native proof, and only then a distinct 147-source ledger reconciliation. Hold new promotion to **59/147** until every gate succeeds.

## Implemented files
- `native-engine/tools/kernix_g0_original_ifunc137_140_batch_source_only_native_writer_plans.py`
- `.github/workflows/kernix-g0-original-ifunc137-140-source-batch-preflight.yml`
- `native-engine/tools/kernix_g0_ifunc137_140_native_fex_writer_batch.sh`
- `native-engine/tools/kernix_g0_original_ifunc137_140_four_writer_batch_independent_gate.py`
- `.github/workflows/kernix-g0-original-ifunc137-140-four-writer-batch-independent.yml`
- `native-engine/tools/kernix_g0_original_libc_147_ledger55_after_sixteen_native_batch.py`
- `.github/workflows/kernix-g0-original-libc-147-source-ledger55-cohorts.yml`
