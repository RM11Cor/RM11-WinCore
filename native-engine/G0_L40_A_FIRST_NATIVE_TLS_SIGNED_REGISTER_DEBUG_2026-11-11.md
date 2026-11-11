# KERNIX G0-L40-A — first native multi-type FEX run: TLS signed register debugger fix

Date: 2026-11-11. Branch: `kernix-native-engine-v1`.

## Original immutable GNU evidence, not a game claim

- Source-only genuine 40-original DT_RELA ELF index0..39 type-check:
  GitHub Actions **#43081973549 SUCCESS**, actual types:
  3 `R_X86_64_64`, 22 `R_X86_64_GLOB_DAT`, 15 `R_X86_64_TPOFF64`.
- First source GDB 10x4 same-inferior Windows plan CI **#43083506794 SUCCESS**.
- First actual FEX Linux ARM64 same-inferior test **#43083778403 FAILURE**
  on **source index1** in GDB's *type-specific evidence predicate*;
  that test's full raw GDB, signed CPU register and per-index partial
  evidence were preserved in GitHub artifact **13885797769**.
- Initial host FEX inferior PID **5545**; first real source index0
  `R_X86_64_64` was observed at original target `0x8041ffc68`,
  actual `stlr x13, [x4]`, candidate `0x80420b680`,
  source JIT `4c8908`.
- Actual index1 `R_X86_64_TPOFF64` native store **also occurred**:
  native `stlr x4, [x10]` at PC `0xffffa4cdceb0`, target x10
  `0x804202d80`, exact guest written qword
  `0xffffffffffffffb0` = signed **-80**. Original GNU loader x86
  JIT source `488906`, original entry `0x801010014`, 3 x86 bytes,
  2 translated native instructions.
- Root cause of failed test was **GDB register display/sign
  interpretation**, not evidence of incorrect FEX TLS translation:
  `gdb.parse_and_eval("$x4")` evaluated the live register as Python
  integer **-80** / `hex(-80)="-0x50"`; reading the exact original
  guest qword yields **unsigned** integer 18446744073709551536.
  Those values have **identical low 64 bits** but a naive equality
  comparison rejected the genuine hardware store.
- All subsequent original indices `2..39` in this failed run
  are **UNOBSERVED**, NOT proven bad and NOT proven good inside
  this same process. The previous 147/147 *separate individual* ledger
  and previous 8/147 independently audited same-process integration
  checkpoint remain intact.

## Exact source correction

- GDB source callback now checks
  `(regs[store_reg] & ((1<<64)-1)) == after`,
  which preserves exact unsigned 64-bit hardware register semantics.
- Independent audit applies the same signed-to-uint64 mask when
  comparing recorded live source value register to the actual guest
  qword. The 60 negative forged-event controls remain mandatory.
- Corrected source-only original GNU plan GitHub Actions
  **#43084791837 SUCCESS**.
- Corrected true native ARM64 FEX GDB run
  **#43084908004** uses the corrected source script and is
  **NOT certified** until its actual outcome and independent audit pass.
- Corrected independent gate will be checked against only corrected
  source and run artifacts, not against failed first-run GDB evidence.

## Release discipline

A single real `TPOFF64` bit-pattern mismatch in our debugger test
must not be mislabeled a FEX translation engine failure, and a fixed
predicate cannot be counted as a passed 40-in-one-process test until
**all actual original 40 native stores are observed in one FEX pid**
and each log passes independent validation.

Do not infer full TLS thread-allocation semantics, complete original
GNU libc/ldso dynamic loader closure, Android/Bionic compatibility,
Wine/Proton, GPU frames or heavy-game readiness.
