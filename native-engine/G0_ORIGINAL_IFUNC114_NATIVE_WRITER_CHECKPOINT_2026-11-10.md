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


## Independent IFUNC114 native writer certified at 29/147, return-stack proof pending

- [Authentic Linux ARM64 FEX writer #42756429959](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42756429959) **succeeded** for source IFUNC114 real GNU hardware WRITE into its immutable original `0x804202cd8` relocation slot.
- [Independent original ELF/GNU writer proof #42756565659](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42756565659) **succeeded** against the authentic source x86 and native ARM64 JIT trace and tampered evidence controls. Distinct original libc relocation writer ledger formally advances **28 → 29 / 147**. No other source alias is credited.
- [Source-only bounded original C3 RET candidates #42756704274](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42756704274) **succeeded**; the three actual original x86 `c3` candidate guest RIPs are **`0x8040b2f77`**, **`0x8040b2fa1`**, **`0x8040b2fb7`** from source resolver bounded `0xb2f40..0xb2fc0`.
- [IFUNC114 original source-locked single-FEX hardware stack-read/RET/GNU writer plan preflight #42774844681](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42774844681) **succeeded** and rechecked the previously attested native writer output and exact GDB plan on immutable GNU libc/ldso source. This does **not** independently attest runtime native stack READ.
- **Latest same-process genuine ARM64 FEX CALL→selected native C3 RET→HW stack READ→post-return GNU writer** [#42774970600](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42774970600).
- **Strict independent native chain replay** [#42775146707](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42775146707), requiring exact source bytes, ten corrupted logs rejected and previous source IFUNC113 authentic trace rejected.

**Current release gate:** accept 29/147 distinct writers on the already successful independent write evidence, but do not claim full IFUNC114 RET/stack READ closure until the latter two real native full-chain jobs both succeed. Even full return proof adds **0** new source writer slots. Complete all 147 original GNU libc dynamic relocations, Android Bionic and 16KiB page ABI, graphics, Wine/Proton, APK, and Windows game FPS are still open.
