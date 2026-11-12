# KERNIX G0-L40-C — five authentic GNU GLOB_DAT native stores in one FEX PID

**Date:** 2026-11-12  
**Branch:** `kernix-native-engine-v1`  
**Release status:** **G0 stage C remains OPEN.** Linux ARM64 FEX diagnostic only.

## First accepted C native store window

- Source 80..83 initial native run: [GitHub Actions #43156324557](https://github.com/RM11Cor/RM11-WinCore/actions/runs/43156324557) **SUCCESS**. Four distinct original GNU `R_X86_64_GLOB_DAT` qword targets were actually trapped by ARM64 GDB hardware writepoints within one FEX inferior PID 2957. Independent 28-forgery audit **SUCCESS**.
- One-inferior rolling **five** test: [GitHub Actions #43157219154](https://github.com/RM11Cor/RM11-WinCore/actions/runs/43157219154) **SUCCESS**. All original **source indices 80, 81, 82, 83, 84** were trapped within **the same native Linux ARM64 FEX inferior PID 2817**. After four distinct actual stores, GDB removed the four watchpoints and armed source84 before its store. All five observed a native `stlr x13, [x4]` mapped to exact original x86 source `4c8908` and expected original source target/value. Source84 writer target `0x804202fd8` contained `0x8040ad500`.
- The independent same-process audit recomputed the SHA-pinned original GNU source and successfully **rejected 44 false-evidence controls**: 28 for the first four and 16 for the fifth. Raw genuine GDB trace and report are archived as artifacts of the successful Actions run.
- Initial five-source attempt [#43157080400](https://github.com/RM11Cor/RM11-WinCore/actions/runs/43157080400) **FAILED** in preflight GDB Python-block parsing (a consuming end-line regex), **before FEX execution**. The source-parser fix in commit `730c0b4e82db835922959f1da81cd3879718da7f` and subsequent original native rerun **succeeded**. This failure was not an x86 translation regression.

## Accounting: original GNU relocation source 0..146

| Staged native hardware proof window | Original source ordinal indices | Status |
| --- | --- | --- |
| A | 0..39 | 40/40 in one FEX PID, independent audit SUCCESS [#43085088606](https://github.com/RM11Cor/RM11-WinCore/actions/runs/43085088606) |
| B | 40..79 | 40/40 in a different FEX PID, independent audit SUCCESS [#43091554154](https://github.com/RM11Cor/RM11-WinCore/actions/runs/43091554154) |
| C | 80..119 | **5/40** true original hardware writers together one FEX PID (80..84); remaining **35 original indices** not yet proven in a single-stage C writer window |
| D | 120..146 | **0/27** together in the planned fourth stage |

**Stage windows physically attested: 85/147.** The previously certified **147/147 individual** GNU source writer receipts are separate historical proof and are NOT an all-147-one-process loader result. Stage A/B/C process IDs differ. This is not evidence of successful GNU interpreter relocation closure or Android gameplay.

## What source85 does and does not show

- The original GNU `R_X86_64_IRELATIVE` **#85** has original on-disk target qword **zero** and remains zero in the previous source80..119 one-FEX-PID pre-main-RELRO rejection snapshot. This **does not** prove the resolver returned zero, was ever called, or made a zero-to-zero store.
- SHA-pinned ELF source [#43156579389](https://github.com/RM11Cor/RM11-WinCore/actions/runs/43156579389) **SUCCESS** established source candidate x86 resolver entry **`0x8040c8570`** in the executable original GNU libc `PT_LOAD`; twelve forged source claims were rejected. This is **source-level address evidence only**, NOT native resolver entry/return execution.
- Future source85 native instrumentation must separately attest actual resolver entry and return and actual native memory-store provenance (including any zero-to-zero write); it must not substitute a source candidate for runtime evidence.

## RELRO fail-closed boundary

Earlier original FEX process tried `mprotect(0x801036000)` for original GNU **ld-linux self-RELRO**, while a gate expected main ELF RELRO `0x800003000`. The policy correctly rejected an unproved owner. Never bypass a main-vs-ldso owner/VMA/protection check to create artificial success. Original GNU main, ldso and libc closure remain distinct future gates.

## Next isolated steps

1. After five source80..84 real stores in the **same FEX inferior**, instrument original #85 IRELATIVE resolver entry, real return and hardware zero-to-zero write, without relying on unchanged qword snapshots.
2. Independently audit the original 16 JMPREL `JUMP_SLOT` sources 86..101 for actual eager/lazy trigger provenance and 18 JMPREL IRELATIVE sources 102..119. Keep maximum of four simultaneous ARM64 hardware watchpoints by rolling them in a single FEX PID.
3. Certify stage C only after **40/40** source indices are attested with the requisite relocation-type-specific execution evidence and main/ldso RELRO safety. Then stage D 120..146, separately.
4. Full real ELF interpreter transition, Android Bionic/Wine/Proton bridge, graphics, games and real device tests all remain **OPEN**, regardless of green native source execution checks.
