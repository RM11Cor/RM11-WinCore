# KERNIX G0 — original GNU libc IFUNC120 immutable source and native writer checkpoint

Date 2026-11-10. Branch `kernix-native-engine-v1`. **Independently certified distinct original x86 GNU libc FEX native ARM64 hardware writer ledger: 35/147** after the new IFUNC120 writer independent proof.

## Prerequisite original IFUNC119 complete one-guest CALL→C3 RET→stack HW READ→GNU store

- Real ARM64 native original Linux/FEX guest [#42806593627](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42806593627) **succeeded**.
- Full separate strict source/real-JIT/ten tamper controls/wrong IFUNC log independent replay [#42808274602](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42808274602) **succeeded** after fixing stale source index/alias expectations.
- Previously certified new distinct 34th target for IFUNC119: independent source-locked writer replay [#42805378255](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42805378255) **succeeded**. Subsequent CALL/RET proof adds zero targets.

## Source-only original GNU IFUNC120

- [Immutable original x86 source preflight #42808521213](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42808521213) **succeeded**.
- ELF original relocation **index 120**, table `DT_JMPREL` ordinal **34**, `R_X86_64_IRELATIVE`.
- **Original source resolver guest RIP `0x8040b4da0`**, unique alias indices `[120]`.
- **Original target guest qword `0x804202c98`**, original unmodified `0x28210`.
- Same SHA256-pinned libc `7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906`; ldso `cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae`.
- The source GDB `watch` plan only identifies a distinct candidate. It **does not** raise the genuine native writer ledger.

## Genuine ARM64 native release gates

1. [Original same Linux/FEX native hardware watch workflow #42808851777](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42808851777) **SUCCEEDED**. Implements source-byte-identical IFUNC120 GDB hardware writer observation with `native-engine/tools/kernix_g0_ifunc120_native_fex_writer_watch.sh`, independent prerequisite #119 closure, source target/old qword/alias, native AArch64 `stlr x4,[x19]` provenance.
2. [Strict separate IFUNC120 source/native writer replay #42809179351](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42809179351) **SUCCEEDED**. Fail-closed on incomplete native run, wrong original ELF, prior IFUNC119 proof, source target or new pointer, ten corrupted authentic logs, and wrong-source IFUNC119 native log.
3. Both release gates succeeded: **distinct original writer ledger increased 34 → 35 /147**. Do not count a source-only GDB plan or a successful build as runtime evidence. The IFUNC120 full `CALL → C3 RET → HW stack READ → GNU store` requires a further independent separate proof and adds **zero** new target counts.

## Original x86 IFUNC120 C3 RET source preflight

- [GNU x86 immutable source C3 RET disassembly preflight #42809480342](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42809480342) **SUCCEEDED** after independently certified writer #35.
- Bounded source resolver disassembly `0xb4da0` through `0xb4e40` yielded **one** original x86 `C3 RET` guest RIP: **`0x8040b4de2`**.
- This is a source instruction only, NOT a real same-process FEX native stack READ. No new unique target from closing the future RET provenance chain.

## Complete IFUNC120 original CALL → C3 RET → stack hardware READ → GNU WRITE (separate)

- [One original x86 C3 RET native hardware watch source plan preflight #42809939802](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42809939802) **SUCCEEDED**. The exact x86 `C3` return guest RIP is `0x8040b4de2`; original guest stack slot is `0x80300f9b8`; target is `0x804202c98`; writer ledger prerequisite is 35.
- [Genuine original Linux/FEX ARM64 one-process CALL/C3 RET/stack HW READ/GNU write native runtime #42810158874](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42810158874) is a **separate required runtime evidence gate**; source-preflight-generated GDB plan is byte-compared before execution. The native watch runs in `native-engine/tools/kernix_g0_ifunc120_native_fex_call_ret_watch.sh`.
- [Independent native hardware evidence replay #42810465289](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42810465289) is the **final** fail-closed gate: unchanged source, true AArch64 JIT, native GDB hardware reads, genuine source stack CALL/RET and GNU writer in order, ten corrupted original logs rejected, plus authentic wrong-source IFUNC119 log rejected.
- **Do NOT certify original IFUNC120 full RETURN chain unless the final independent replay succeeds**. Even then, the independent distinct target count remains **35/147**, because IFUNC120 write is already the 35th distinct target and verifying the same relocation's return provenance adds zero new targets.

Neither the 147/147 original source target closure nor Android Bionic/16KiB pages, Vulkan/DXVK/VKD3D, Wine/Proton, APK release, or game/FPS success is established by these limited GNU Linux host/native tests.
