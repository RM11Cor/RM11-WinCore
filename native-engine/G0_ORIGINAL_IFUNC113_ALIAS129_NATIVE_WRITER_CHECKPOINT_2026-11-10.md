# KERNIX G0 — IFUNC113 original GNU x86 alias [113,129] source-hardware checkpoint

**Date:** 2026-11-10. **Branch:** `kernix-native-engine-v1`. **Certified baseline:** 27 unique original libc native relocation writers / 147 (not 28 yet).

## Previous gate independently closed
- Original IFUNC112 same real Linux ARM64 FEX process CALL→resolver JIT→source x86 C3 RET→native hardware guest stack READ→original GNU WRITE independently certified in [#42753565278](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42753565278). No new target is credited for the post-hoc RETURN proof.
- Previous genuine original source binaries remain unchanged; libc SHA256 `7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906`, original GNU x86 ld-linux SHA256 `cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae`.

## IFUNC113 source facts, not yet live native proof
SHA-locked source preflight [#42753831032](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42753831032) succeeded, deriving these directly from original x86 ELF:

- Original libc relocation source index **113**, `DT_JMPREL` ordinal **27**, `R_X86_64_IRELATIVE`.
- Original x86 resolver guest RIP **`0x8040ca7a0`**.
- Its **own** original relocation destination guest address **`0x804202ce8`**, original qword **`0x282b0`**.
- Source resolver alias group **`[113,129]`**: the two source entries reuse the same resolver code address but have separately owned relocation target slots. **Never count an alias resolver as a second unique writer, and never substitute a #129 destination for #113.**
- A native hardware `watch` GDB plan is byte-for-byte tied to the independently audited SHA source plan and previous certified IFUNC112 full-return evidence.

## Real FEX Linux ARM64 and independent verification
- Genuine isolated original ARM64 FEX hardware WRITE trial: [#42754004173](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42754004173).
- Strict independent replay of that exact run, original ELF and source GDB bytes, including ten modified GDB-log rejection controls: [#42754148740](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42754148740).
- Source-only original x86 `C3 RET` inventory is gated on a **successfully independently attested #113 hardware writer / 28 unique target slots**, and must **not** be treated as hardware read or a completed return proof. Source workflow: `.github/workflows/kernix-g0-original-ifunc113-source-ret-candidates-preflight.yml`.

**At this checkpoint creation:** do not claim IFUNC113 writer success or increase 27/147 until the real ARM64 run and independent replay both pass. Even 28/147 would not close full 147 x86 libc relocations, Android Bionic/16KiB, GPU, Wine/Proton, APK, or actual Windows game execution.


## Native IFUNC113 retry after fail-closed source argument mismatch

Initial genuine Linux ARM64 FEX wrapper [#42754004173](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42754004173) **failed before reaching the IFUNC113 GDB trace**: the wrapper called `kernix_g0_original_libc_ifunc113_source_distinct_hw_watch_plan.py dist . 112` while this source-only generator strictly requires `index == 113`. The generated SHA-pinned source preflight for `113` itself had already passed. The two initially chained replay/source RET jobs also failed closed because no new hardware evidence was successfully produced; those failures do not prove an actual FEX translation fault.

Corrected wrapper now invokes `... dist . 113` in [commit 7c9a7bf](https://github.com/RM11Cor/RM11-WinCore/commit/7c9a7bf66142e1f5b06605741069aefbf2d92ea4). The original x86 ELF, source provenance and separate alias `[113,129]` requirement remain unchanged. 

- **Corrected genuine ARM64 FEX writer trial:** [#42754665975](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42754665975).
- **Strict independent target-source-native writer replay pinned to this corrected trial:** [#42754712379](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42754712379).
- **IFUNC113 true source x86 C3 RET candidate preflight pinned to that independent proof:** [#42754744045](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42754744045). A separate stale source-only receipt incorrectly carried writer ledger 27 instead of expected post-certification 28; the source-only output was corrected, without modifying runtime evidence.

**Do not credit the 28th unique writer until both corrected real ARM64 FEX hardware log and independent strict replay succeed.** The follow-on source-RET disassembly is not itself a native FEX RET/stack hardware READ proof, even if it passes. No Android/Wine/Proton/APK or Windows game execution is implied.
