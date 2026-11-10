# KERNIX G0 — source-locked original GNU libc IFUNC85 DT_RELA ZERO relocation

Date: 2026-11-10; branch `kernix-native-engine-v1`.

## Last fully independent native writer stage

**61/147** original GNU source relocation target **hardware writers separately attested**; **86** original source targets remain pending. These are distinct source-target writer observations under **Linux AArch64 FEX**, not full one-guest relocation completion, full loader, Android/Bionic, Wine/Proton, Vulkan or playable PC games.

Evidence chain:
- Corrected original IFUNC145 and IFUNC146 genuine native ARM64 watch [#42854306040](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42854306040), **SUCCESS**.
- Exact two independent hardware source writer proofs and **20 falsified native-log controls rejected** [#42854380835](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42854380835), **SUCCESS**.
- All original 147 GNU relocation source-row reconciliation [#42854452518](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42854452518), **SUCCESS**. Exactly 61 independently witnessed writer locations, 86 pending (one original IFUNC index 85, and 85 non-IFUNC DT_RELA source rows).

## Original x86 source-only IFUNC85 evidence

- [Original IFUNC85 SHA-pinned DT_RELA ZERO-qword source preflight #42856900787](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42856900787), **SUCCESS** after JSON trailing-newline serialization correction [commit 0d7c7e18](https://github.com/RM11Cor/RM11-WinCore/commit/0d7c7e18bad604c77d0f8eb0fb6f2141f6731c20).
- The earlier source preflight #42856728202 **failed due to malformed trailing JSON**, not wrong ELF source; it is superseded and never counted as evidence.
- Original GNU x86 libc source relocation `index=85`, **`DT_RELA` ordinal 85**, type **`R_X86_64_IRELATIVE` (37)**, symbol zero, and **original target qword = 0x0**. Distinct from the 45 subsequent `DT_JMPREL` IFUNC entries (source indices 102–146), which have nonzero original target qwords.
- Exactly one source candidate-specific GDB **write** watch script was generated with original SHA-locked resolver, guest target, source file offsets, initial value and previous 61-writer proof prerequisite. The source plan is **NOT a native hardware proof**.
- `native-engine/android-host/tests/kernix_g0_original_fex_full_ptload_source_executable_range_arm64.cpp` contains exactly one `++RealOriginalLdsoLibcCloses;` marker around line 3704 in this snapshot. Source comments describe the original 147 targets before relocation, but this alone does **not** prove which GDB arm time precedes the authentic `DT_RELA` writer in a live guest.
- Before any new ledger promotion, execute FEX ARM64 on the exact original source and verify **zero-at-arm, live native hardware write, chronological after-arm hit, original source JIT/write provenance**, with independent anti-tamper negative controls. Investigate a different x86 loader instruction/source path if this `DT_RELA` writer is not the same as `DT_JMPREL` `STORE`; never infer it is.

## Next native stage

**IFUNC85** is the last single GNU IRELATIVE source target needing independent native writer proof. It must be handled in one source-locked isolated runtime gate, with its own independently proven native receipt and original full-source 147 ledger reconciliation. If and only if successful, the writer subtotal can become **62/147**, with the remaining **85 non-IFUNC DT_RELA** writer targets. No unexecuted source-only plan may increase the 61/147 baseline.

Relevant files:
- `native-engine/tools/kernix_g0_original_ifunc85_dt_rela_zero_writer_source_plan.py`
- `.github/workflows/kernix-g0-original-ifunc85-dt-rela-zero-source-preflight.yml`
