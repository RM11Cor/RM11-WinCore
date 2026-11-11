# KERNIX G0-L40 stages A and B — eighty distinct original GNU source writers

Date: 2026-11-11; branch `kernix-native-engine-v1`.

## Confirmed independent native evidence (not a finished original dynamic loader)

| Stage | Original GNU DT_RELA indices | Actual Linux ARM64 FEX inferior PID | Raw hardware | Independent gate |
| --- | --- | --- | --- | --- |
| A | 0..39 | **5044** | [#43084908004](https://github.com/RM11Cor/RM11-WinCore/actions/runs/43084908004) SUCCESS | [#43085088606](https://github.com/RM11Cor/RM11-WinCore/actions/runs/43085088606) SUCCESS; 60 forged controls rejected |
| B | 40..79 | **2813** | [#43091425606](https://github.com/RM11Cor/RM11-WinCore/actions/runs/43091425606) SUCCESS | [#43091554154](https://github.com/RM11Cor/RM11-WinCore/actions/runs/43091554154) SUCCESS; 60 forged controls rejected |

**Total staged coverage: 80 distinct original GNU DT_RELA source writer targets**, none counted twice. Each 40-target stage was independently observed in its OWN single real Linux ARM64 FEX inferior process. **80 are NOT proven together inside one Linux process**; the largest separately independently proven one-inferior stage remains 40.

All 147 distinct original GNU source writer targets were independently proven in the earlier *individual* writer ledger, before stages A and B. The stage-level integration receipt is an additional, different metric, not 80 newly discovered ELF relocations.

## Actual original type mixture

- Stage A: **3** `R_X86_64_64`, **22** `R_X86_64_GLOB_DAT`, **15** `R_X86_64_TPOFF64`.
- Stage B: **5** `R_X86_64_64`, **34** `R_X86_64_GLOB_DAT`, **1** `R_X86_64_TPOFF64`.
- Combined stage A+B: **8** absolute 64-bit relocations, **56** `GLOB_DAT`, **16** TLS `TPOFF64`, all based on SHA-locked original GNU ELF relocation tables and symbol/addend data.

## Stage B hardware monitoring correction

The first stage-B hardware run [#43086670321](https://github.com/RM11Cor/RM11-WinCore/actions/runs/43086670321) stopped with 4 native stores, `DT_RELA40..43`, when `DT_RELA44` already contained a nonzero value **before the second 4-target watch window was armed**. This was a WATCH ARMING GAP, **not proven incorrect FEX x86-to-ARM64 translation**. The raw and independent gate intentionally refused the 40/40 claim. Previous source44 native proof had required **AWATCH** for `_rtld_global_ro`.

The subsequent strategy arms a maximum of four native GDB hardware watchpoints at a time, including `DT_RELA44` **AWATCH from process start**, and rolls one watched slot after *every* genuine original native hardware store **while the SAME inferior remains stopped**. This prevents the first-stage re-arm gap. The exact source script and SHA parity passed [#43089818250](https://github.com/RM11Cor/RM11-WinCore/actions/runs/43089818250).

The corrected raw run [#43091425606](https://github.com/RM11Cor/RM11-WinCore/actions/runs/43091425606) reused the exact SHA256-pinned real Linux ARM64 FEX native host/guest runtime compiled and individually tested earlier in [#43078736764](https://github.com/RM11Cor/RM11-WinCore/actions/runs/43078736764). Reusing the identical compiled guest was a build optimization **only**, not synthetic evidence. GDB observed all original source indices `[40,41,...,79]` with their matching true qwords, original x86 JIT source, AArch64 `stlr` opcode and CPU registers in original OS PID **2813**. TLS `DT_RELA63` used the correct signed qword bit pattern, not a naive signed Python integer comparison.

Independent gate [#43091554154](https://github.com/RM11Cor/RM11-WinCore/actions/runs/43091554154) independently rebuilt original source, attested true same FEX PID and forty individual native STORE events, and rejected **60 deliberately falsified source/PID/arming events**. The original source44 first-window early AWATCH and exact rolling witness chronology were audited separately from the raw workflow.

## Remaining required stages and separate release gates

- **C** original source `80..119` (40 targets), type-specific genuine GNU ELF SHA source metadata, true same-FEX-PID hardware events and an independent anti-forgery audit.
- **D** original source `120..146` (27 targets), same conditions.
- Independent *four-stage coverage* does **not** prove full 147-target dynamic ELF loader closure **in one guest process**. That still needs actual GNU `DT_RELA`, `DT_JMPREL` semantics, `RELR`, IFUNC/PLT, symbol version/preemption, TLS layout, executable memory permissions, RELRO and subsequent library initialization in real native end-to-end evidence.
- Android Bionic and page-size/CPU/RAM identity acceptance and Wine/Proton Windows guest startup are separate gates **not yet passed**. Vulkan/Turnip/DXVK/VKD3D and actual game frames/FPS are further separate gates.

**Current counters**: `individual_147=147/147`; `distinct_40_stage_integration_sources=80/147`; `largest_single_same_pid_stage=40`; `full_147_one_guest_process_proven=false`; `Android_games_proven=false`.
