# KERNIX G0 — original GNU libc IFUNC117 distinct writer checkpoint

Date: 2026-11-10. Branch: `kernix-native-engine-v1`. **Accepted independently certified distinct original GNU libc native writer ledger: 31/147.**

## Prerequisite IFUNC116 independently CLOSED
- [Genuine Linux ARM64 original FEX one-guest source GNU `CALL → resolver → C3 RET → native hardware guest-stack READ → original GNU writer` #42779074021](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42779074021): **success**.
- [Strict source SHA-pinned independent same-process C3 RET, hardware READ and target WRITE attestation #42779959981](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42779959981): **success**, including deliberately corrupted native log rejection and independent wrong-source IFUNC115 trace rejection. The first replay failed due a copied filename `twelve-source-RET` instead of genuine five-source `RET`; it was corrected without altering original source or JIT trace.
- Previously certified IFUNC116's distinct writer #31 by [#42778683056](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42778683056). Full CALL/RET chain adds **zero** distinct relocation targets.

## SHA-locked source-only IFUNC117 successful preflight
[Original unmodified GNU x86 source-only relocation/watch candidate #42779996841](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42779996841) **succeeded**, strictly dependent on IFUNC116's above full native independent proof.

- Source relocation index **117**, `DT_JMPREL` ordinal **31**, `R_X86_64_IRELATIVE`.
- Original resolver guest RIP **`0x8040ca850`**.
- Unique distinct relocation destination guest qword address **`0x804202cb8`**, original old qword **`0x28250`**.
- Source resolver alias group **`[117]`** (not shared with other source IFUNC entries).
- SHA256 GNU x86 libc `7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906`; ldso `cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae`.
- The source-only watchpoint and any disassembly plan are **not** native execution.

## Native IFUNC117 evidence gates
- [Genuine one-original-ELF Linux ARM64 FEX native hardware WRITE trial #42780147618](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42780147618), uniquely observing real GNU writer into `0x804202cb8`.
- [Separate strict independent ARM64 native store/JIT and immutable original x86 ELF replay #42780281282](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42780281282), with ten altered-log negative controls, source index/target and wrong-source IFUNC116 provenance rejection.
- The next source-only original IFUNC117 bounded true `C3 RET` candidate preflight is `.github/workflows/kernix-g0-original-ifunc117-source-ret-candidates-preflight.yml`, **fail-closed** on the independently attested native **32nd** writer.

**Do not advance ledger 31→32 until both genuine native hardware writer and separate independent replay succeed.** Even a 32nd distinct writer would not prove IFUNC117 full CALL→C3 RET→native hardware stack READ chain or all 147 relocations, Android 16KiB/Bionic memory ABI, graphics, Wine/Proton, APK, games or FPS. 
