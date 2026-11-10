# KERNIX G0 — IFUNC119 immutable source and distinct native writer checkpoint

Date: 2026-11-10. Branch `kernix-native-engine-v1`. **Certified distinct original GNU x86 libc native ARM64 FEX writer ledger: 34/147 following successful independent IFUNC119 hardware writer proof.**

## Required previous native closure: original IFUNC118

- Same-process genuine original ELF FEX ARM64 `CALL → source C3 RET → native guest stack HW READ → GNU store`: [runtime #42802029061](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42802029061) **success**.
- Full negative-controls and independent attestation: [#42803837688](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42803837688) **success**.
- IFUNC118 itself was writer #33; RET closure adds zero new targets.

## Original GNU x86 source-derived IFUNC119 (NOT a native execution claim)

- Independent source-only native watch preflight: [#42804196731](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42804196731) **success**.
- Immutable original libc `sha256:7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906`; original ld-linux `sha256:cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae`.
- Original source relocation **index 119**, `DT_JMPREL` ordinal **33**, `R_X86_64_IRELATIVE`.
- Guest resolver RIP **`0x8040d8d70`**, source resolver alias indices **[119, 138]**. **Shared resolver is not shared target**: the native watch and count MUST identify index 119 relocation qword.
- Guest relocation target **`0x804202ca0`**, initial unmodified qword **`0x28220`**.
- Generated native write-only plan and GDB `watch -location` are source-only; **do not** claim any new native writer from the source preflight.

## Independent native release gates

1. [Real FEX Linux ARM64 native guest hardware write run #42804984459](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42804984459) **SUCCEEDED**: actual JIT GNU writer `stlr x4,[x19]`, exact source target before/after values, original ELF bytes, preserved alias and x86 GNU provenance required.
2. [Independent IFUNC119 strict hardware writer replay #42805378255](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42805378255) **SUCCEEDED**: first run **success**, exact immutable source plan parity, previous independently certified IFUNC118 full proof, ten deliberately corrupted real-log controls rejected, and wrong-IFUNC log rejection.
3. Both succeeded: distinct writer ledger **33 → 34 / 147**. This is a unique target write, not a CALL/RET proof. IFUNC119 CALL/RET/stack hardware READ remains a **separate gate** to close after source-only C3 RET disassembly and a genuine same-process ARM64 FEX witness, adding zero more targets.
4. Original 147 whole source target closure, Android Bionic/16KiB page support, Vulkan/DXVK/VKD3D, Wine/Proton, APK release and games/FPS remain **unproven** by this test.

## IFUNC119 complete original CALL/C3 RET/stack hardware READ separate release gate

- [Source-only genuine original x86 disassembly #42806073278](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42806073278) **SUCCEEDED** and identified three source `C3` return candidates: guest RIPs `0x8040d8d94`, `0x8040d8dcf`, and `0x8040d8dec`. These are candidates, **not** native runtime witnesses.
- [Source-pinned one-FEX-guest dynamic native hardware return watch preflight #42806372152](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42806372152) **SUCCEEDED**, checking these three source instructions, original stack slot `0x80300f9b8`, original target `0x804202ca0`, and certified 34th distinct source writer. Preflight explicitly has `actual_native_hardware_RET_read_and_same_process_writer_proven=false`.
- Original [FEX ARM64 native dynamic return run #42806593627](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42806593627): genuine one-process `CALL→source-selected C3 RET→stack HW READ→GNU WRITE` witness required; the runner's source plan is byte-compared against preflight. The hardware step is implemented in `native-engine/tools/kernix_g0_ifunc119_native_fex_call_ret_watch.sh`, to stay below GitHub's 500 KB workflow limit.
- [Strict independent replay #42806836752](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42806836752): waits on the exact native run, verifies original source/JIT/registers and all native events in order, rejects ten corrupted original native logs and the authentic wrong-source IFUNC118 native log.
- **Do not mark IFUNC119 full CALL/RET hardware chain closed** until the independent replay succeeds. Once closed, do not increment distinct writer count again: **34/147 remains 34/147**.

The workflow evidence upload uses compact artifact globs for original IFUNC102–107 because the full ARM64 workflow had exceeded GitHub's 500 KB size limit. The duplicate-stage/path audit [#42804984735](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42804984735) passed after the change.
