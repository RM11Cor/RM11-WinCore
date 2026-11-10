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


## Independent IFUNC113 original native writer certified: 28/147

The corrected real Linux ARM64 FEX source-pinned writer experiment [#42754665975](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42754665975) **succeeded**, including its new hardware write watch against original source IFUNC113 destination `0x804202ce8`. [Strict independent native FEX HW writer replay #42754712379](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42754712379) also **succeeded**, verified original GNU x86 ELF source SHA, the actual AArch64 JIT `stlr x4, [x19]` hardware write, exact source target/resolver `0x8040ca7a0`, and negative controls. The source resolver is shared with IFUNC129, but the destination target for index 113 is distinct and independently counted only once. **The accepted ledger increases from 27/147 to 28/147**, not 29/147.

[Original GNU x86 source RET candidates #42754744045](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42754744045) independently passed after writer certification and discovered only three genuine bounded `C3 RET` candidate source addresses: `0x8040ca7c7`, `0x8040ca83d`, `0x8040ca84f`. This is a **source-only** inventory. [Same-process FEX hardware READ source plan preflight #42755357541](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42755357541) **succeeded** and creates a source-locked GDB plan for dynamically selecting the actually executed RET while observing original GNU source CALL, hardware stack READ and target WRITE. No runtime RET success is claimed by those two source-only passes.

### Open IFUNC113 full-return control-flow acceptance
- Actual new ARM64 one-FEX-process CALL→x86 source C3 RET→native stack hardware READ→GNU STORE execution: [#42755497932](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42755497932).
- Independent strict replay of immutable original GNU ELF and one authentic native log, with ten negative controls and rejection of authentic *other source* IFUNC112 native return log: [#42755697387](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42755697387).

**Full RET/stack-READ chain remains OPEN until both above runs succeed**, and certifying it must not increase the already authenticated 28/147 writer ledger. Remaining relocation closure, Android 16KiB/Bionic, Vulkan/Wine/Proton, APK and actual Windows game FPS remain independently unproven.
