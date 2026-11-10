# KERNIX G0 — original GNU libc IFUNC116 SHA-locked source and native writer gates

Date: 2026-11-10. Branch: `kernix-native-engine-v1`. **Current independently authenticated distinct original libc writer ledger: 30 / 147**.

## Previous IFUNC115 full native CALL/RET proof closed
- [Linux ARM64 FEX original GNU x86 CALL → one of 12 authentic C3 RET instructions → native guest-stack hardware READ → original GNU writer, real run #42777033772](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42777033772): succeeded.
- [Source-pinned independent full-return validation with deliberately altered native logs #42777146919](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42777146919): succeeded.
- The prior IFUNC115 30th hardware writer was independently certified by [#42776000011](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42776000011); its later full-return validation adds **zero** new source targets.

## IFUNC116 genuine source-only GNU x86 ELF preflight
[IFUNC116 source SHA audit and generated target-specific hardware watch #42777504617](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42777504617) succeeded, strictly requiring the prior IFUNC115 complete independent hardware chain.

- Original ELF source relocation index **116**, table `DT_JMPREL` ordinal **30**, type `R_X86_64_IRELATIVE`.
- Original guest resolver RIP **`0x8040b4fc0`**.
- **Separate** original relocation target qword address **`0x804202cc8`**, initial source qword **`0x28270`**.
- Original resolver alias indices `[116]` (no alias with another IFUNC source entry).
- GNU x86 libc SHA256 `7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906`; original GNU ldso SHA256 `cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae`.
- Source-only GDB watchpoint is NOT a native runtime or independent writer result and MUST remain at 30/147 until further evidence.

## Native hardware and independent validation gates
- New original ARM64 Linux FEX genuine source GNU hardware WRITE trial [#42777889476](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42777889476).
- Strict independently pinned exact target, ELF hash, genuine AArch64 source-store, original writer-result and negative controls [#42777995913](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42777995913).
- [Duplicate source/ARM64 native stage and upload path audit #42777889430](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42777889430) independently succeeded before accepting the new native workflow. This is CI hygiene, not native runtime evidence.

**Gate remains OPEN:** until genuine real ARM64 FEX run and independent proof both succeed, do not increment 30→31; even then native C3 RET/hardware guest stack READ would remain a separate proof requirement. 147-relocation closure, Android 16KiB/Bionic, Vulkan/Wine/Proton integration, ready APK and game FPS remain unproven by these Linux FEX source tests.


## 31st distinct original libc writer independently certified

The first strict independent replay [#42777995913](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42777995913) **failed closed** at an incorrect previous-source target constant copied from IFUNC114 (`0x804202cd8`), not the authenticated IFUNC115 source target (`0x804202cd0`). The real native writer test [#42777889476](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42777889476) **succeeded**. Corrected the previous independently certified source target in both the validator and workflow, retaining immutable original GNU x86 ELF hashes and the IFUNC116 actual source destination `0x804202cc8`.

[Corrected original-source independent ARM64 hardware writer replay #42778683056](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42778683056) **succeeded** including source target/JIT and forged-evidence negative controls. The accepted original libc *distinct target writer* ledger advances **30/147 → 31/147** exactly once. This does not establish IFUNC116 original `CALL→C3 RET→hardware stack READ→GNU WRITE` in one FEX process.

[Source-only original x86 IFUNC116 bounded C3 RET candidate disassembly #42778782538](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42778782538) is pinned to the corrected independent run, not the failed original replay. Source-only plans and source analysis add zero target writers and do not prove runtime return or Android/Wine/Proton/game readiness.


## Source-locked five-C3-RET full original IFUNC116 Linux ARM64 FEX chain — independent gate open

After the **31st distinct original libc GNU native writer** was independently certified by [#42778683056](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42778683056), [original source C3 RET inventory #42778782538](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42778782538) succeeded with exactly five original x86 opcode `c3` source candidate guest RIPs: `0x8040b4fe7`, `0x8040b5087`, `0x8040b509e`, `0x8040b5153`, `0x8040b5188`; source resolver bound `0xb4fc0..0xb5190`. Source disassembly is NOT a return-stack runtime proof.

[Independent preflight #42778949084](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42778949084) **succeeded**: strict byte-identical original GNU x86 source and one-FEX dynamic GDB hardware `awatch` CALL stack write, native JIT selected C3 RET, `rwatch` guest stack READ, caller resume and original GNU native writer STORE. It does not count additional distinct target slots.

- Original native Linux ARM64 FEX *one process* full-chain authentic run: [#42779074021](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42779074021).
- Source SHA-pinned **independent** full-chain replay with original source/JIT, ten corrupted native logs rejected and authentic wrong IFUNC115 source log rejection: [#42779274210](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42779274210). The replay requires the genuine run to complete with `conclusion=success`; all events must be from its single original FEX invocation.
- [Next original IFUNC117 source-only gate #42779482023](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42779482023) depends on successful independent IFUNC116 complete CALL/RET/stack-read proof and must **fail closed** otherwise; it only derives source resolver, alias group and unique target; it does not certify a writer.

**Accepted writer ledger remains 31/147** until a new **distinct** source target gets native hardware attestation in a later step. IFUNC116 same-process native full-return proof and next IFUNC117 source gate may not be claimed successful until their actual GitHub results are individually checked. Android 16KiB/Bionic, Wine/Proton/Vulkan, signed APK and Windows game performance remain unproven.
