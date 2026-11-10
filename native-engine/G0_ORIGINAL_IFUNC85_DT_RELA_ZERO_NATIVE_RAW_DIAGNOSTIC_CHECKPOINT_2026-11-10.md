# KERNIX G0 — original GNU IFUNC85 DT_RELA zero target, actual ARM64 FEX native diagnostic

Date: 2026-11-10. Branch: `kernix-native-engine-v1`.

## Previous immutable independently attested release gate
- Independently verified Linux ARM64 FEX GNU libc writer target count **61/147**, **86 pending** (DT_RELA IRELATIVE index 85 plus 85 non-IFUNC DT_RELA). Previous [two genuine IFUNC145–146 native writers #42854306040](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42854306040), [independent 20 tamper rejections #42854380835](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42854380835) and [all-147 source ledger #42854452518](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42854452518) **success**.
- No one-guest whole-loader or x86 return/stack-read assertion for new index #85; no Android/Bionic/Wine/game proof.

## Isolated index 85 source-only finding
- [Exact SHA-pinned GNU x86 libc and ldso source plan #42859432302](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42859432302) **success**. Original ELF source index #85 is unique `DT_RELA` ordinal 85, `R_X86_64_IRELATIVE`, symbol zero and zero original qword. Previous JMPREL IFUNC sources #102–146 are separate and nonzero.
- Fixed GDB source plan to emit authentic multiline GDB commands and valid `printf` newline escapes. Earlier generated raw plan run #42858598344 included malformed `printf` escapes; it is not authoritative for a hardware-watch claim. The latest source-only run #42859432302 is authoritative.
- The native runtime diagnostic script `native-engine/tools/kernix_g0_original_ifunc85_dt_rela_zero_fex_arm64_raw_diagnostic.sh` checks SHA256 source, previous 61-proof, original qword zero, exact GDB watch instructions; executes genuine FEX ARM64 and archives a GDB raw log, process exit and a **NOT-INDEPENDENT** summary. A raw log never promotes the ledger by itself.
- [Corrected main native run #42859559977](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42859559977) started; [main workflow audit #42859559840](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42859559840) **success**. Earlier main diagnostic run #42858968884 was pinned to older, malformed printf GDB source and is superseded.

## Next exact gate
1. Inspect the **corrected main raw diagnostic** outcome and GDB source watch. Confirm actual guest qword **0 at hardware-watch arming**, actual observed write after arming, and native PC/store provenance compatible with the immutable original x86 loader/IFUNC resolver. The source plan itself warns the arm point might be after the DT_RELA relocation; do not interpret no hit as proof of a translator bug.
2. If the raw write is proven, run an independent verifier with deliberate negative log mutations. Reconcile all original 147 indices independently, forbid double-count, then (and only then) promote to **62/147**. If write is not observed, diagnose alternate earlier original-loader breakpoint/order without claiming success.
3. 85 remaining non-IFUNC DT_RELA target writers remain separate release gates after any conditional IFUNC85 promotion.

Only branch `kernix-native-engine-v1` is used.
