# KERNIX G0 — original GNU IFUNC145 and IFUNC146 final consecutive IRELATIVE target writers

Date: 2026-11-10, branch `kernix-native-engine-v1`.

## Certified prior baseline
- [Native GNU original libc relocation ledger 59/147](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42848940520) **SUCCESS**. IFUNC141–144 writer run [#42848623323](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42848623323) **SUCCESS**, independent 40-negative-case replay [#42848697286](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42848697286) **SUCCESS**.
- New source indices **145, 146** are the final two consecutive original GNU libc `DT_JMPREL` `R_X86_64_IRELATIVE` entries. Original GNU IFUNC source #85 is separate, and other source relocation types require their own proof.

## Current independently gated two-writer pipeline
- Original x86 GNU libc/ldso SHA-pinned [source-only #42853284818](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42853284818) **SUCCESS**, two individually distinct original target qwords and source-specific GDB hardware write watches; **0 new native proof from this preflight**.
- Actual [Linux AArch64 FEX real hardware writer runner #42854306040](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42854306040), two **separate** guest execution/watch sessions built from the same pinned FEX. Previous writer receipts through IFUNC141–144 mandatory.
- [Two-writer independent replay #42854380835](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42854380835), verifies ELF SHA, original source GDB byte correspondence, native FEX hardware target write, independent per-source receipts, and **20 tampered negative-case logs rejected**.
- [147-source cohort ledger61 #42853962764](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42853962764) is gated by actual independent two-writer proof and all prior unchanged evidence. It adds no hardware proof by itself.

## Promotion policy
**Current approved is 59/147 until all three new native and reconciliation workflows complete successfully.** On strict success, **61/147** distinct individual native-written source qwords, with **86** remaining: **85 non-IFUNC DT_RELA** and original IFUNC source **#85**. No 147 same-guest closure, no Linux loader fully demonstrated, no guest native CALL/C3 RET stack hardware READ for these two by writer-only checks, no Android/Bionic, Wine, Vulkan or game launch proof.

## New files
- `native-engine/tools/kernix_g0_original_ifunc145_146_two_source_only_native_writer_plans.py`
- `native-engine/tools/kernix_g0_ifunc145_146_native_fex_writer_batch.sh`
- `native-engine/tools/kernix_g0_original_ifunc145_146_two_writer_batch_independent_gate.py`
- `native-engine/tools/kernix_g0_original_libc_147_ledger61_after_twentytwo_native_batch.py`
- `.github/workflows/kernix-g0-original-ifunc145-146-source-batch-preflight.yml`
- `.github/workflows/kernix-g0-original-ifunc145-146-two-writer-batch-independent.yml`
- `.github/workflows/kernix-g0-original-libc-147-source-ledger61-cohorts.yml`


## Cardinality correction before independent evidence promotion
- The first two-target raw-run script inherited two strict `==4` guards from the earlier four-target runner. These checks would wrongly reject valid two-source results. Corrected both `source_candidates_derived_in_one_hash_verified_batch==2` and `len(seen)==2` at commit `0842d63134825dbac0763df6cb4fa361e5521ed3`.
- The **authoritative new raw run** is [#42854306040](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42854306040); the **authoritative new independent replay** is [#42854380835](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42854380835). The original raw run #42853612655 and independent run #42853758150 are **superseded by corrected code**; do not count or pin their results.
- Source 147 ledger script and workflow were re-pinned to **#42854380835**; its new CI run ID needs live re-verification. Keep **59/147** until all three authoritative gates succeed.


## Certified closure — final two consecutive IFUNC targets

- Corrected real pinned FEX Linux AArch64 native target writer execution [#42854306040](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42854306040) **COMPLETED SUCCESS**; both original IFUNC145/146 real hardware writer watches and artifact upload succeeded (source-only #42853284818 also completed SUCCESS).
- Corrected strict independent native writer verifier [#42854380835](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42854380835) **COMPLETED SUCCESS**; two distinct target receipts, 20 mutated/falsified hardware log controls rejected. Four previous IFUNC141–144 records are independently prerequisite-only, not double-counted.
- Original x86 GNU 147 source row reconciliation [#42854452518](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42854452518) **COMPLETED SUCCESS**; cumulative **61/147** individual independent original GNU Linux ARM64 FEX hardware writer target receipts, **86** still awaiting independent evidence (**85 non-IFUNC DT_RELA and one IFUNC, source index 85**).
- The first superseded raw runner #42853612655 failed from an inherited incorrect four-source `==4` count for a two-source batch; the corrected independent proof and 61-row ledger are explicitly pinned to the corrected run IDs instead. Never use a failed/superseded run as native proof.

## Next isolated original source target
Original GNU libc **IFUNC #85**, unlike the previous consecutive #102–146 source targets, is a distinct non-`DT_JMPREL` IFUNC in the original 147 relocation source records. Examine the immutable x86 source relocation table/type and its resolver and target QWORD before constructing an independent address-specific Linux ARM64 FEX native hardware writer watch. No native proof nor single-guest CALL/C3 RET stack hardware read is presumed for #85.
