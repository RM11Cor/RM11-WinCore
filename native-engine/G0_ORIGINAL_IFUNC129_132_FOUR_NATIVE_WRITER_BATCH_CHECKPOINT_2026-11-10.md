# KERNIX G0 — original GNU IFUNC129–132 FEX hardware writer batch release gates

Date: 2026-11-10. Branch: `kernix-native-engine-v1`.

## Proven baseline

- **47/147 distinct original GNU x86 libc source relocation writer targets have independently verified Linux ARM64 FEX hardware write witnesses as of completed IFUNC129–132 independent replay**, from completed previous four-target real run [#42831198323](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42831198323) and separate 40-corruption independent replay [#42832626066](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42832626066).
- Original all-147 source type-cohort coverage and 43-source native evidence reconciliation [#42833131438](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42833131438) **SUCCESS**, showing 104 original source relocation targets without independently attested native writer receipts. Source classification alone contributes **zero** native proofs.
- Previous IFUNC125–128 four hardware writers were **four separate FEX guest processes** sharing one FEX build, not four writers proven inside one guest process. No new full guest CALL → C3 RET → hardware stack READ was certified by that writer-only batch.

## SHA-pinned source-only candidate batch #129–#132

[Original source preflight #42835389440](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42835389440) **SUCCESS**, exact original GNU source SHA locked and source-only watch plans independently checked.

| index | original DT_JMPREL ordinal | guest resolver | guest target qword | original source qword | original resolver aliases |
|---|---:|---|---|---|---|
| 129 | 43 | `0x8040ca7a0` | `0x804202c38` | `0x28150` | `[113,129]` |
| 130 | 44 | `0x8040b4150` | `0x804202c30` | `0x28140` | `[130]` |
| 131 | 45 | `0x8040b2460` | `0x804202c28` | `0x28130` | `[131]` |
| 132 | 46 | `0x8040ca740` | `0x804202c20` | `0x28120` | `[132]` |

All four are original `R_X86_64_IRELATIVE` source relocations with different target qword addresses; source resolver aliases **must not** merge writer target proofs.

## Fail-closed native release gates

1. [Original ARM64 FEX GNU writer hardware run #42835817002](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42835817002) **SUCCEEDED** and is the dedicated four-probe batch stage inside the existing source-pinned native FEX build. Each original source hardware write watch produces a raw `.log` and `.exit` in a separate FEX guest process. A shared compiler/build job is **not** a same-guest write proof.
2. [Independent new four-target replay #42836109827](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42836109827) **SUCCEEDED**, separately certifying all four source SHA byte-identical watches, native `stlr x4,[x19]` target/provenance, registers, JIT, chronological GDB watch arm/hit, and 40 intentionally corrupted native logs rejected. All four passed, independently certifying **43 + 4 = 47/147** distinct original source target writer hardware receipts.
3. [Updated original 147-source cohorts report #42836456962](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42836456962) **SUCCEEDED** after independent replay #42836109827; all original GNU source types/indices reconcile to **47/147 writer-proven, 100 still pending**. The source inventory report itself performed **zero** new native executions.
4. Even when all above succeed, separate original CALL/C3 RET/native stack hardware READ proof for IFUNC129–132, all remaining original relocation source indices, and Android/Bionic/16KiB-page, Wine/Proton/Vulkan/game compatibility are **unproven** until each genuine required release gate succeeds. Do not infer them from Linux GNU writer-only watchpoints.

**Release gate status: IFUNC129–132 original native GNU writer hardware batch independently certified, ledger 47/147; source 147-cohort proof reconciliation succeeded; CALL/C3 RET/stack READ and Android remain separate.**
