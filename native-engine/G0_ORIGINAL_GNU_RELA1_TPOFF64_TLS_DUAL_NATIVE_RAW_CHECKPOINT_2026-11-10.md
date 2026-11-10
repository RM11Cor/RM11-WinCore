# KERNIX G0 — next original GNU non-IFUNC `DT_RELA` #1 TLS/TPOFF64, native raw watch and awatch

Date: 2026-11-10. All repository work on **`kernix-native-engine-v1`** only.

## Previous independently certified exact original source GNU writer target count
- **63/147** distinct GNU original libc x86 relocation source writer target locations separately attested by Linux AArch64 FEX native hardware, **84 pending** original non-IFUNC `DT_RELA` indices **1..84**. No original 147 relocation closure in one guest or Android/Wine/game/APK proof.
- [One independently verified original R_X86_64_64 `_res` writer #42870979057](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42870979057), **SUCCESS**, 14 falsified FEX GNU-source/native hardware records rejected.
- [Full unchanged original SHA-locked 147-source ledger63 #42871443481](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42871443481) **SUCCESS**, exactly 63 unique source targets, 84 pending; ledger inventory itself added zero writer proofs.
- [Original checkpoint for `DT_RELA` #0](https://github.com/RM11Cor/RM11-WinCore/blob/kernix-native-engine-v1/native-engine/G0_ORIGINAL_GNU_RELA0_RES_INDEPENDENT_WRITER_LEDGER63_CHECKPOINT_2026-11-10.md).

## Genuine immutable GNU `DT_RELA` index1 classification, different from R64 and IFUNC
- [SHA-pinned original GNU x86 ELF source-only #42872523133](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42872523133) **SUCCESS** after removing the invalid pre-assumption that every relocation must have nonzero `r_sym`. Older first preflight #42872109035 failed safely on that assumption; no native evidence claimed.
- Original source `index=1`, `DT_RELA` ordinal **1**, type **`R_X86_64_TPOFF64`** (type 18), `r_sym=0`, **signed addend +56**, original `r_offset=0x202d80`, original guest target **`0x804202d80`**, immutable original 64-bit target QWORD **`0x0`**. ELF dynsym STN_UNDEF index0 is not a source symbol definition.
- `TPOFF64` requires the actual original GNU loader's TLS/module/thread-pointer related runtime semantics, not the `R_X86_64_64` source symbol/BSS formula. Source plan has **zero new FEX hardware writer attestations**.

## New actual native FEX ARM64 fail-closed diagnostic
- `native-engine/tools/kernix_g0_original_dtrela1_tls_tpoff64_fex_native_raw_probe.sh` runs **two separate original Linux x86 GNU guest executions under real Linux AArch64 FEX**: a target-specific GDB hardware **`watch`** for changed QWORD and a distinct GDB hardware **`awatch`** for READ/WRITE access, each with native registers and original FEX x86 guest JIT source trace if a hit occurs.
- Archive/check raw logs and their SHA256, actual original guest address, live arm ordering, post-arm hardware hits, x86 JIT source bytes and AArch64 STLR or other native instruction before any independent proof. An `awatch` alone cannot distinguish READ from WRITE; an unchanged-value store might not trigger a `watch`.
- [Duplicate stage/artifact workflow audit #42873144197](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42873144197) **SUCCESS**.
- Authoritative source-pinned main actual ARM64 FEX raw run [#42873144268](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42873144268) started after one source-only preflight and prior63 ledger, writes raw diagnostics **without claiming TLS runtime semantics or new independent writer evidence**.

**Strict next gate:** Check the genuine GDB `watch` and `awatch` logs for native target data, the correct decoded x86 GNU loader source/JIT, the x86 TLS computation and register values, and independently reject tampered logs. Only then run all-147 original source ledger reconciliation. Until these independent checks succeed, **63/147 certified, 84 pending**. No signed APK/game success is implied.
