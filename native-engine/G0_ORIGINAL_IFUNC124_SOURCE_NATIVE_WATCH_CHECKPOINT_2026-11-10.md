# KERNIX G0 — original GNU libc IFUNC124 source and native writer evidence gates

Date 2026-11-10. Branch `kernix-native-engine-v1`.

**Independently proven distinct original GNU x86 libc FEX ARM64 hardware writer targets: 39/147 after IFUNC124 independently passing native hardware writer replay.** The ledger is about genuine individual original source IFUNC relocation writes, not Android game support or completion of the total 147 relocations.

## Source prerequisite #123 — independently CLOSED

- Original 7 C3 source RET candidates: [#42819920083](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42819920083) **success**.
- Real one-FEX-process original `CALL → chosen C3 RET → native stack hardware READ → GNU WRITE`: [#42820534110](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42820534110) **success**. Actual guest x86 `C3 RET` at `0x8040cb7e5`, native stack READ, GNU target `0x804202c80`.
- Strict independent source/JIT/ten tamper controls and authentic wrong-IFUNC122 rejection: [#42821008866](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42821008866) **success**. The RETURN chain adds **zero** new distinct writer counts.

## SHA-pinned original source IFUNC124

- [Original x86 source-only relocation/GDB hardware writer preflight #42821680098](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42821680098) **succeeded**.
- Source ELF `R_X86_64_IRELATIVE` original relocation index **124**, `DT_JMPREL` table ordinal **38**.
- Original source resolver guest RIP **`0x8040b2ed0`**, original source alias group **[124]**.
- New source target RW/NX guest qword **`0x804202c78`**, unmodified original qword **`0x281d0`**.
- Immutable libc SHA256 `7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906`, ldso SHA256 `cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae`.
- This x86/GDB watch is **source only**, not execution evidence. Never raise ledger based solely on an ELF inventory or successful build.

## Independent real FEX ARM64 native writer release gates

1. [Original same Linux/FEX native ARM64 guest hardware target write trial #42821903368](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42821903368) **SUCCEEDED**, requiring source byte-identical IFUNC124 GDB plan, genuine native AArch64 `stlr x4,[x19]` write, original target/new value, original source GNU writer/JIT and independently closed #123.
2. [Strict separate native IFUNC124 writer independent replay #42822070400](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42822070400) **SUCCEEDED** and independently checks genuine run/source, rejects ten authentic tampered native logs and authentic wrong-source #123 log, validates unique IFUNC124 target `0x804202c78` and prior ledger 38. Both #42821903368 and #42822070400 succeeded, independently certifying **38 → 39/147**.
3. The full original #124 source `CALL → C3 RET → hardware stack READ → GNU store` chain is a **separate runtime and independent-replay gate**, adds **zero** more distinct writer targets after #39.

## IFUNC124 original x86 C3 RET complete native chain (separate gate)

- Original GNU source-only bounded disassembly [#42822295717](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42822295717) **SUCCEEDED**; exactly **two** source x86 `C3 RET` candidate RIPs `0x8040b2f25` and `0x8040b2f3f` (source-only, not executed yet).
- Exact original source candidates, original x86 byte checks, target `0x804202c78`, and real FEX GDB hardware stack-read plan [#42823327804](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42823327804) **SUCCEEDED** in a preflight-only test.
- Initial real one-process trial [#42823450324](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42823450324) **FAILED CLOSED before the C3 return native runtime**: shell source validation correctly knew 2 candidates but a copied stale source uniqueness assertion incorrectly demanded 7. No genuine FEX return hardware chain was certified from this attempt. Fixed the separate script without changing immutable ELF or writer proof. **Corrected real ARM64 FEX CALL → chosen C3 RET → stack HW READ → GNU WRITE native trial:** [#42824560711](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42824560711) **SUCCEEDED**.
- Initial independent replay [#42823803904](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42823803904) failed closed because its upstream native run failed. Replay [#42824787796](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42824787796) then failed closed on a copied IFUNC123 resolver-alias source assertion, corrected to independently decoded `[124]` without relaxing the negative controls. **Corrected source/JIT/register/stack independent replay [#42827886594](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42827886594) SUCCEEDED**, rejecting all ten tampered hardware logs and the genuine other-IFUNC123 trace. **Full original IFUNC124 CALL→source C3 RET→hardware stack READ→GNU WRITE is independently CLOSED.**
- The independent writer target counter remains **39/147**, whether the separate RET verification succeeds or fails; no second counting of the same GNU source relocation target.

- New [original IFUNC122–124 source-to-native copy/paste regression #42824736239](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42824736239) **SUCCEEDED**, rejecting all **24 intentionally corrupted** writer and C3 RET source counts, stale target qwords, native watchpoints and ledger handoffs. This is a static safeguard, **not** runtime execution proof.

No Android Bionic/16KiB-page, Wine/Proton, DXVK/VKD3D/Vulkan, APK release, Windows games, real game FPS, or global original 147/147 closure is established by these GNU Linux/FEX-only tests.
