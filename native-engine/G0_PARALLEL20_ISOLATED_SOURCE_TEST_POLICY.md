# KERNIX G0 — twenty individual original GNU relocation tests in parallel

**Branch:** `kernix-native-engine-v1`. **Date:** 2026-11-11.

## Agreed concurrency contract

Run **twenty distinct original GNU relocation source targets concurrently**,
with one independent test task, FEX Linux ARM64 process, GDB native hardware
WATCH/AWATCH capture and individually downloadable artifact per source index.
A failed source target must **not** cancel or contaminate the other 19.
Do **not** run original source indices one by one when this independent
batch is appropriate.

The first pilot covers original `DT_RELA[65..84]`:

- Genuine original GNU libc/ldso source files are SHA-pinned and must
  be reconciled against the existing original 147-source writer ledger.
- Compile **one** original pinned FEXCore on ARM64 in the preparation
  job, package it with the compiled authentic guest driver and 20 source
  scripts; do not rebuild the whole FEX source 20 times.
- Use an ARM64 GitHub Actions **matrix of 20 independent jobs** with
  `fail-fast: false` and `max-parallel: 20`. GitHub can queue jobs if
  fewer runners are available; maximum concurrency is a limit, not an
  invented guarantee of 20 simultaneously executing CPUs.
- Per-job original source **index** is immutable. Each tests exactly
  one original source target with its own genuine GDB WATCH and AWATCH
  real native FEX guest processes, original CPU register and JIT
  provenance, and a per-index `index-raw-result.json`.
- Every artifact must retain its original index, pass/fail state,
  GDB exit codes, LLVM/FEX/native instruction evidence, SHA256 trace
  hashes, source relocation type, guest destination and optional known
  source-defined symbol candidate. Do not silently drop failures.
- Original `DT_RELA74` and `DT_RELA75` reference undefined
  `_rtld_global` in libc: the original dynamic loader supplies a
  resolution. Never fabricate a libc source-definition candidate
  for these; independent full interposition and resolution semantics
  remain **open** even if a genuine native hardware write is captured.
- `R_X86_64_64` relocations must use signed source addends when
  evaluating a known symbol candidate. `R_X86_64_GLOB_DAT` is distinct.
  Preserve all source-relative type metadata for diagnostics.
- The aggregate runs **even on failed, queued, cancelled or incomplete
  individual jobs**, reporting each original index and all absent
  artifacts. It never advertises an independent certification merely
  from raw GDB evidence.

## Immutable release-gate distinction

1. **G0 original individual source writer certification:** **147/147**
   already independently proven before this pilot. This concurrent
   20-source regression/fault-localization batch **does not add 20 new
   distinct relocation sources** or change that previously certified count.
2. **G0-L3 process-level writer integration:** **8/147** observed in
   one separately independently audited ARM64 FEX Linux process
   (run `43074639291`). **Twenty separate processes running at the
   same time do not prove twenty relocations in the same process.**
3. **Full original dynamic loader process relocation closure, TLS/IFUNC/
   RELR/RELRO, Android/Bionic, Wine/Proton, DXVK/VKD3D/Turnip and real
   games remain release-gated** until their own live native and device
   evidence proves completion.

## Tooling and run

- Source plan: `native-engine/tools/kernix_g0_parallel20_original_gnu_source_plan.py`.
- Individual FEX case: `native-engine/tools/kernix_g0_parallel20_individual_native_fex_case.py`.
- SHA source-only CI: `.github/workflows/kernix-g0-parallel20-original-gnu-rela65-84-source-plan.yml`.
- Shared-compile + 20-job Linux ARM64 matrix + fail-closed
  aggregation: `.github/workflows/kernix-g0-parallel20-separate-fex-arm64-native-cases.yml`.
- First source validation: Actions `43077670076` **passed**.
- First 20-job workflow: Actions `43078736764`. Evaluate
  outputs before reporting any per-index native runtime result.

**Next process-integration tests must still use one actual FEX host inferior
with sequential watchpoint windows**, not aggregate isolated processes.
