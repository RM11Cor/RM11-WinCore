# KERNIX G0 — first GNU non-IFUNC DT_RELA0 _res real independent native writer and exact ledger63

Date: 2026-11-10. Branch strictly `kernix-native-engine-v1`.

## Newly closed independent original x86 source writer

Original SHA-pinned GNU libc DT_RELA source **index 0**, `R_X86_64_64`, symbol **`_res`**, original symbol index **2726**, addend zero, original target **`0x8041ffc68`**, initial qword **`0x0`**. ELF original definition of `_res` resides in libc BSS and yields source mapped candidate **`0x80420b680`**.

- [Original source-only ELF and watch plan #42865785661](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42865785661), **SUCCESS**, 0 new native attestations from source.
- [Real Linux ARM64 pinned FEX native source watch #42866554787](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42866554787), **SUCCESS as raw diagnostic**. One observed hardware watch target QWORD change from `0x0` to `0x80420b680`; AArch64 native instruction **`stlr x13, [x4]`**. Raw workflow success alone did not certify.
- [Second real separate Linux ARM64 FEX x86 source JIT/native writer #42869138108](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42869138108), **SUCCESS**. Authentic native register `x4=0x8041ffc68`, `x13=0x80420b680`, source JIT x86 original loader entry `0x80100fb8b`, source 3-byte opcode **`4c 89 08`** (`mov qword ptr [rax],r9`), native two-instruction translation with **`stlr x13, [x4]`** and matching original GNU immutable SHA bytes.
- [Independent dual-native-run raw provenance checker #42870381335](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42870381335), **SUCCESS** after fixing source-specific prior-62 metadata key from a prior IFUNC stage. Old #42869973926 **FAILED due to wrong metadata key** and is superseded, not evidence.
- [Strict original GNU source-to-native independent writer #42870979057](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42870979057), **SUCCESS** with **14 falsified hardware or original x86 source-JIT traces rejected**; one genuinely attested source-specific new original relocation target writer. The proof does **not** claim complete `R_X86_64_64` dynamic symbol preemption/versioned lookup rules.
- [Full 147 original GNU relocation source ledger #42871443481](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42871443481), **SUCCESS**. Totals: **63/147** original individual Linux ARM64 FEX source target hardware writer receipts, **84** original GNU non-IFUNC DT_RELA source targets still awaiting independent hardware writer evidence (**source indices 1..84**); original IFUNC source writer cohort fully closed (46/46); source inventory itself added zero runtime proof.

## Current release gate and non-claims

Exact source target writer count **63/147** is a per-source-index **individual** proof count, not one original GNU x86 guest process running all 147 relocations. It does **not** prove entire GNU dynamic loader execution, full symbol lookup/interposition and versioning, all hardware guest CALL/C3 RET/stack READ, Android 16 / Bionic / 16 KiB pages, Wine/Proton, DXVK/VKD3D, Turnip, installed signed APK or launchable Windows games.

[Original 85 non-IFUNC source type audit #42865597210](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42865597210) verified **8 `R_X86_64_64`**, **16 `R_X86_64_TPOFF64`**, **61 `R_X86_64_GLOB_DAT`**. After certifying `R_X86_64_64` source #0, the remaining 84 sources include **7 R64**, **16 TPOFF64** and **61 GLOB_DAT**. Keep these symbol/TLS semantics separate.

## Next isolated task

Read exact original `DT_RELA` **source index 1** from immutable x86 libc and remaining ledger63, establish its actual relocation type/symbol/target before selecting the correct original loader/JIT watch. No source-only plan increases 63/147; each new source row requires its own independent actual FEX AArch64 hardware writer receipt, mutation-resistant verification and 147-row reconciliation.
