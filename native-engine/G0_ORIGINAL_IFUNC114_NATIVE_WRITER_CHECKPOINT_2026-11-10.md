# KERNIX G0 — original libc IFUNC114 source and native writer gate

**Date:** 2026-11-10. **Branch:** `kernix-native-engine-v1`. **Independently certified prior writer ledger: 28 / 147** (IFUNC114 not yet certified).

## Previous original IFUNC113 full proof CLOSED
- [Real original Linux ARM64 FEX CALL → source resolver → x86 C3 RET → native stack hardware READ → original GNU store #42755497932](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42755497932): success.
- [Independent replay #42755697387](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42755697387): success, including ten tampered log controls and cross-source rejection.
- This proves full control-flow of the already counted index 113 writer; total remains 28/147.

## IFUNC114 immutable original x86 source preflight succeeded
[Source-only original GNU x86 ELF relocation/watch plan #42756230746](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42756230746) succeeded and derived:
- Source relocation index **114**, original `DT_JMPREL` ordinal **28**, `R_X86_64_IRELATIVE`.
- Exact original x86-64 resolver guest RIP **`0x8040b2f40`**.
- Original dedicated RW relocation target guest address **`0x804202cd8`**, original 8-byte qword **`0x28290`**.
- Resolver alias indices **`[114]`**: distinct source resolver, no IFUNC resolver alias group for 114.
- Original libc SHA256 `7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906`, GNU ld-linux SHA256 `cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae`.
- No new native writer is credited by source preflight alone.

## Writer proof gates launched
- [Real ARM64 Linux FEX IFUNC114 source-locked GNU hardware WRITE run #42756429959](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42756429959) — genuine native observation required.
- [Strict independent replay #42756565659](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42756565659), requiring the exact real run, matching source GDB bytes and original ELF SHA, original destination, native JIT `stlr x4,[x19]`, 10 tampered-log rejections, and rejection of wrong IFUNC113 native trace.
- Subsequent source-only original x86 C3 RET inventory is gated on the above independently authenticated **29th** distinct hardware writer; this source disassembly is not native RET execution proof.

**Fail closed:** preserve ledger at **28/147** until the new real FEX and independent replay both pass. Do not infer all 147 relocations, Android Bionic/16KiB, Wine/Proton, Vulkan, an APK or game/FPS readiness from these Linux ARM64 experiments.
