# KERNIX G0 — 62/147 independently native writer certified; first remaining GNU DT_RELA0 _res native raw stage

Date 2026-11-10. Work only on `kernix-native-engine-v1`.

## Fully established prior original GNU x86 writer evidence
- **62/147** distinct original GNU x86 libc relocation writer target qwords independently attested by real **Linux AArch64 FEX** hardware, **85** original source targets awaiting independent evidence. This is NOT 147 in one x86 guest, a complete loader, Android/Bionic, Wine/Proton/Vulkan, signed APK, games or FPS.
- GNU original IFUNC85 `DT_RELA` zero-to-zero actual FEX JIT native `STLR x4,[x19]` independently attested by [#42864516665](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42864516665), 12 counterfeit-log mutations rejected. A separate original-source native verifier [#42864962732](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42864962732) also **SUCCESS** with independent additional checks. Exact all 147 source row [ledger62 #42864875847](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42864875847) **SUCCESS**, with zero double-counting and zero native attestations from source inventory itself.
- Writer evidence for each IFUNC (46 total) does not mean the same x86 guest executed all 46, or same-guest CALL/C3 RET/stack READ in every case.

## Remaining original non-IFUNC `DT_RELA` source types
- [Exact original 85 immutable SHA-pinned source inventory #42865597210](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42865597210) **SUCCESS**: exactly **8 `R_X86_64_64`**, **16 `R_X86_64_TPOFF64`**, **61 `R_X86_64_GLOB_DAT`**, no other pending source type. All 85 pending are original source indices **0..84**, initial target qwords zero and distinct.
- No per-target GNU symbol lookup, TLS model, guest source JIT writer execution, host-native write or same-process success is inferred from this classification.

## First unproven `DT_RELA` source index 0
- [First source-only preflight #42865785661](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42865785661) **SUCCESS** using exact original x86 libc source bytes; source relocation `index=0`, `DT_RELA` ordinal 0, type **`R_X86_64_64`**, symbol `2726`, `_res` (global OBJECT, original GNU libc BSS), zero signed addend, original GNU guest target **`0x8041ffc68`**, unchanged original target QWORD **`0x0`**.
- Source-defined `_res` symbol mapped-address candidate **`0x80420b680`** is NOT proof of the actual GNU loader-resolved value. Symbol interposition/version lookup and original guest store remain separate release gates.
- Source-specific original FEX arm/watch plan and a SHA-locked two-step native runner `native-engine/tools/kernix_g0_original_dt_rela0_res_real_fex_native_writer_raw.sh` are integrated into the main native Linux ARM64 workflow. The raw candidate is NOT a writer certification and does not change **62/147**.

## New native run and false-positive controls
- [Workflow audit #42866554654](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42866554654) **SUCCESS**, following removal of duplicate concurrently committed native download/run and upload-glob stages from earlier audit [#42866287819](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42866287819) **FAILURE**. That audit failure was duplicate YAML entries, not a translator failure.
- Authoritative deduplicated native **RAW** run [#42866554787](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42866554787) started. Recheck its GitHub conclusion and the last `Run original GNU DT_RELA0 ...` step first. If it succeeds, inspect GDB `old=0` at arm, exact target watchpoint hit count, new native qword and `STLR` instruction address/registers, then independently validate GNU x86 R64 source writer semantics and symbol resolution before any additional target count.
- A workflow `success` that only archives a raw log is **not** independent writer proof. If the original loader never reaches index 0 on this execution, diagnose source order or an earlier breakpoint; do not invent a hit.
- **Never update count 63/147** without a separate genuine original source-to-native ARM64 hardware writer receipt, anti-tamper negative cases, and exact original 147-source ledger reconciliation (currently 62/147).
