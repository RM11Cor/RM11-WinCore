# KERNIX G0 — original GNU libc IFUNC123 immutable source and ARM64 writer evidence gates

Date: 2026-11-10. GitHub branch: `kernix-native-engine-v1`.

**38/147 independently certified distinct GNU original libc x86 IFUNC/native FEX ARM64 hardware writer targets** after successful IFUNC123 independent hardware writer proof. This ledger is not a count of all native ELF relocations, Android Windows game support, or IFUNC CALL/RET proofs.

## Prerequisite #122 fully closed in authentic one-FEX guest process

- Source-only original C3 instruction scan: [#42816402203](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42816402203) **success**, **41 genuine original x86 source C3 RET candidates**, none selected by source-only evidence.
- Original real FEX ARM64 native `CALL → dynamically selected source C3 RET → native stack hardware READ → GNU WRITE`: [#42817333967](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42817333967) **success**, selected guest RIP `0x8040b41e4` in one process.
- Strict separate source/JIT/ten forged hardware-log rejection and authentic wrong-IFUNC proof: [#42818106673](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42818106673) **success**.
- #122 distinct GNU writer was independently certified as **37th** by [#42816271722](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42816271722), and its subsequent CALL/RET closure added zero further distinct relocation target counts.

## Source-derived IFUNC123: genuine original x86 ELF; source only

- [Original GNU SHA-pinned source relocation and watch preflight #42818680553](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42818680553) **success**.
- `R_X86_64_IRELATIVE` original source relocation **123**, `DT_JMPREL` ordinal **37**.
- Source resolver guest RIP **`0x8040cb7b0`**, alias group **[123]**.
- Unique original source RW/NX target guest qword **`0x804202c80`**, original old qword **`0x281e0`**.
- Source SHA256 libc `7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906`, ldso `cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae`.
- Source-only GDB hardware watch is a **plan**, not a native writer or CALL/RET witness; no ledger increment.

## Release gates for #38 native writer target

1. [Genuine ARM64 FEX same original GNU guest source/target hardware writer #42818984408](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42818984408) **SUCCEEDED** with authentic hardware watch, old and new qword, original source/GNU writer/JIT native AArch64 `stlr x4,[x19]`, and closed independent #122 upstream. Source GDB must be byte-identical to preflight.
2. [Corrected strict independent IFUNC123 hardware writer replay #42819636745](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42819636745) **SUCCEEDED**, pinned to genuine native #42818984408 and source #42818680553. An earlier run [#42819349576](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42819349576) failed closed on a stale #122 hardware watch-slot check. The corrected replay verifies the **new** target `0x804202c80`, old qword `0x281e0`, native AArch64 `stlr x4,[x19]`, 10 forged-native-log rejections, genuine wrong-source #122 rejection, original ELF SHA and byte-identical source plan. **38th distinct original native writer target is independently certified.**
3. [Original #123 source C3 RET disassembly workflow](https://github.com/RM11Cor/RM11-WinCore/actions/workflows/kernix-g0-original-ifunc123-source-ret-candidates-preflight.yml) is strictly pinned to successful independent writer [#42819636745](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42819636745); successful source C3 scan is **not** real native C3 RET stack READ evidence.
4. `CALL → source-selected C3 RET → real stack hardware READ → GNU writer` for IFUNC123 will require an additional genuinely native and independent proof, adding **zero** additional distinct target counts after #38.

## Original IFUNC123 C3 RET source scan and separate genuine return-address proof

- Source-only [original GNU x86 C3 RET disassembly #42819920083](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42819920083) **SUCCEEDED** and found **seven** original `C3` guest RIP candidates: `0x8040cb7e5`, `0x8040cb811`, `0x8040cb827`, `0x8040cb87e`, `0x8040cb8d3`, `0x8040cb935`, `0x8040cb9b2`. Each is an original x86 source opcode **candidate only**; none is a real FEX execution witness until its native JIT is observed.
- [Source-pinned 7-C3-RET one-process ARM64 FEX hardware stack-read plan preflight #42820252890](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42820252890) **SUCCEEDED** after independently certified writer #38. Source-generated GDB script and full source candidate list must be byte-identical at runtime; GDB source watch plan is **not** native proof.
- [Real ARM64 FEX original GNU one-guest `CALL → dynamically chosen x86 C3 RET → stack hardware READ → GNU WRITE` trial #42820534110](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42820534110). Required runtime witness is saved in `original-libc-IFUNC123-one-FEX-CALL-7-source-RET-native-stack-HW-READ-and-GNU-WRITE.log` and companion `.exit` via modular `native-engine/tools/kernix_g0_ifunc123_native_fex_call_ret_watch.sh`.
- [Strict independent original IFUNC123 native one-process return-chain replay](https://github.com/RM11Cor/RM11-WinCore/actions/workflows/kernix-g0-original-ifunc123-dynamic-ret-one-guest-independent-replay.yml). Exact initial instance [#42820905662](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42820905662) was followed by a correction to ensure **only the seven original IFUNC123 C3 candidates** are accepted (not IFUNC122's prior 41); verifier also rejects ten deliberately modified native hardware logs and the genuine wrong-source IFUNC122 full native RET trace. Must succeed after upstream native run before claiming full #123 closure.
- **Do not call original IFUNC123 full CALL/RET hardware chain closed until the native run and corrected separate independent replay both succeed**. Even once closed, **38/147 remains unchanged** because the 38th writer target is already certified independently.

**38/147 distinct GNU/FEX native writer targets independently proven**, but do **not** claim full #123 CALL/RET closure, 147/147 closure, Android Bionic/16KiB page support, Wine/Proton, DXVK/VKD3D, APK or Windows game launch/FPS before separate proper evidence exists.
