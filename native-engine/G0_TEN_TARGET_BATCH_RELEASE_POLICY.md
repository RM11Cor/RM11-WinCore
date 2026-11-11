# KERNIX G0: ten original GNU source targets per native experiment batch

**Status:** independent 93/147 original GNU libc source-target hardware writers
certified before this batching change. Remaining 54 non-IFUNC original
`DT_RELA[31..84]` targets (not 54 tests sharing one process).

## Batch schedule

| Batch | Original source indices | Targets |
|---|---|---:|
| A | DT_RELA[31..40] | 10 |
| B | DT_RELA[41..50] | 10 |
| C | DT_RELA[51..60] | 10 |
| D | DT_RELA[61..70] | 10 |
| E | DT_RELA[71..80] | 10 |
| F | DT_RELA[81..84] | 4 |

These are original SHA-pinned Linux/GNU ELF relocation source indices, *not*
Android software components. Index 35 and index 36 are `R_X86_64_64` even
though surrounding targets are often `R_X86_64_GLOB_DAT`. Never copy a
relocation type or file-backed qword assumption from another index. A source
target may be in the genuine writable `PT_LOAD` BSS, which must be checked
via `p_memsz` independently of `p_filesz`.

## Parallel execution with failure isolation

1. Read the unchanged GNU `libc.so.6` and `ld-linux-x86-64.so.2`, check
   original source SHA256 and all 147 original relocation records, and prove
   every selected source target is distinct and absent from the certified ledger.
   Source parsing produces **zero** native writer attestations.
2. Build the original SHA-pinned FEXCore **once** per batch on genuine Linux
   ARM64. Preserve the original GNU guest ELF, exact FEX JIT source provenance,
   and the original GDB hardware watchpoint, not a synthetic replacement.
3. Schedule all ten targets in a single batch. Cap concurrent GDB/FEX guest
   processes at four per ARM64 runner to avoid memory exhaustion. For each
   target, execute an individual **WATCH** run and a separate **AWATCH** run,
   with its own GDB script, exit status, log, CPU registers, original x86
   loader source bytes, destination qword and SHA256 record.
4. The raw pass only records observations. A **separate independent verifier**
   validates each target's authentic source tuple, original qword, native
   `stlr` target address/value registers, original guest x86 instruction,
   JIT source block and event chronology, then rejects 16 falsified logs for
   **that same target**. If any condition fails, quarantine **only** that
   source index. Do not grant that target a native hardware writer proof.
5. Reconcile the original all-147 source ledger from the exact prior certified
   ledger and the new independently verified per-target receipts. Increase the
   certified count by exactly the size of the disjoint successfully verified
   target set. Leave failed indexes pending; do **not** replay or revoke
   independent siblings or infer evidence from source-only metadata.
6. A subsequently corrected failed target is re-tested and independently
   audited against the then-current certified index set; refuse duplicates.

## Release gates and nonclaims

- A successful GitHub Actions **build** or source test is not a native writer.
- A raw source watchpoint **without** independent audit is not a certified writer.
- A failing source index may not block preserving true evidence from the other
  nine, and may not be falsely labeled passed.
- Do not infer full symbol preemption/versioning from an ELF symbol definition
  candidate, particularly for undefined dynamic symbols such as
  `__libc_enable_secure`.
- Do not count one guest process executing all 147 from ten separate guest
  test processes. Do not claim a real Android/Bionic/Wine/Proton/Windows-game
  boot, CPU-feature detection, video rendering or FPS results from Linux/GNU
  relocation tests.
- Keep `full_GLOB_DAT_dynamic_symbol_scope_preemption_and_versioning_proven`,
  `all_147_same_guest_native_execution_proven` and
  `Android_Bionic_Wine_Proton_games_proven` false until separately demonstrated.

## Initial implementation, batch A

- Original source type/symbol plans:
  `native-engine/tools/kernix_g0_original_globdat_batch31_40_source_after93.py`
- Shared-build, bounded-parallel real ARM64 native runner:
  `native-engine/tools/kernix_g0_original_batch31_40_native_parallel_raw.py`
- Per-target independent audited native receipts and 16 negative controls:
  `native-engine/tools/kernix_g0_original_batch31_40_native_independent_gate.py`
- Conditional original 147-source ledger:
  `native-engine/tools/kernix_g0_original_147_ledger_after_batch31_40.py`

Future batch workflows may reuse this four-stage design while pinning the
correct source index range and current independently certified ledger.
