# KERNIX G0 — original GNU IFUNC145 and IFUNC146 final consecutive IRELATIVE target writers

Date: 2026-11-10, branch `kernix-native-engine-v1`.

## Certified prior baseline
- [Native GNU original libc relocation ledger 59/147](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42848940520) **SUCCESS**. IFUNC141–144 writer run [#42848623323](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42848623323) **SUCCESS**, independent 40-negative-case replay [#42848697286](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42848697286) **SUCCESS**.
- New source indices **145, 146** are the final two consecutive original GNU libc `DT_JMPREL` `R_X86_64_IRELATIVE` entries. Original GNU IFUNC source #85 is separate, and other source relocation types require their own proof.

## Current independently gated two-writer pipeline
- Original x86 GNU libc/ldso SHA-pinned [source-only #42853284818](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42853284818) **SUCCESS**, two individually distinct original target qwords and source-specific GDB hardware write watches; **0 new native proof from this preflight**.
- Actual [Linux AArch64 FEX real hardware writer runner #42853612655](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42853612655), two **separate** guest execution/watch sessions built from the same pinned FEX. Previous writer receipts through IFUNC141–144 mandatory.
- [Two-writer independent replay #42853758150](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42853758150), verifies ELF SHA, original source GDB byte correspondence, native FEX hardware target write, independent per-source receipts, and **20 tampered negative-case logs rejected**.
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
