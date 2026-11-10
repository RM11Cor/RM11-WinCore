# KERNIX G0 — original GNU IFUNC133–136: source-pass, ARM64 native watch evidence pending

Date: 2026-11-10. Branch: `kernix-native-engine-v1`.

## Exact starting point
- Prior original GNU relocation writer **independently certified: 47/147**, with **100/147 not independently native-writer-certified**. This is **Linux AArch64 FEX hardware-writer evidence**, not all-relocations-in-one-guest, guest CALL/C3 RET/stack READ, Android/Bionic, Wine, Proton, Vulkan, APK, or actual game execution.
- The prior independently authenticated four-target writer proof for original IFUNC129–132 is [CI #42836109827](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42836109827); the reconciled original 147-source ledger is [CI #42836456962](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42836456962).

## New bounded batch
- **IFUNC133, 134, 135, 136** are selected from immutable SHA256-pinned original GNU libc x86 DT_JMPREL IRELATIVE records; each has its own source-derived writer target and a distinct source-only GDB hardware-watch file.
- The strict source-only plan CI [#42839698903](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42839698903) **succeeded**. Its source-plan output contributes **zero new native writer proofs** and must not increment 47.
- New source generator: `native-engine/tools/kernix_g0_original_ifunc133_136_batch_source_only_native_writer_plans.py`.
- New real hardware watch runner: `native-engine/tools/kernix_g0_ifunc133_136_native_fex_writer_batch.sh`. Its four source-target watches each run in a **separate FEX guest process**, sharing one pinned ARM64 FEX build. A raw watch hit remains **unverified** until independent evidence replay.
- The existing pinned ARM64 native FEX host workflow was extended only at the end with this separate batch, downloading the exact source-only plan artifact plus the prior 47-target independent proof. Runtime [CI #42840553440](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42840553440) was **in progress** when this checkpoint was written. An initial too-large YAML workflow revision [#42840308311](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42840308311) was rejected **before any job**; a reduced-size revision was accepted and started native FEX compilation.
- Independent byte-checking replay gate: `native-engine/tools/kernix_g0_original_ifunc133_136_four_writer_batch_independent_gate.py` plus [CI #42840714050](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42840714050), which waits for the genuine runtime to complete successfully and then requires exactly **four** individually attested native writers with **40** forged-log negative controls rejected.

## Immutable promotion condition
**Keep 47/147** until both the real FEX batch AND the independent four-writer verifier complete successfully. Only then promote the genuine original target-writer subtotal to **51/147 (96 still pending)** in a separate source ledger-reconciliation step. Never promote based on source plans, raw logs alone, or a successful build. Original guest CALL → C3 RET → hardware stack READ and Android/Wine/game success are separate unresolved release gates.
