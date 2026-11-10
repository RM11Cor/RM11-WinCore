# KERNIX G0 — source-locked original GNU libc IFUNC115 writer checkpoint

Date: 2026-11-10. Branch: `kernix-native-engine-v1`. Accepted independent original GNU libc writer ledger **29 / 147**, no new IFUNC115 writer credited yet.

## Exact prior independent IFUNC114 closure

- [Original FEX ARM64 one-guest GNU x86 CALL→source C3 RET→native stack hardware READ→post-return original GNU store #42774970600](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42774970600) **succeeded**.
- [Strict independent same-source genuine native hardware RETURN/READ/WRITE attestation #42775146707](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42775146707) **succeeded** including ten deliberately corrupted-log rejections and real wrong-source reject. RETURN proof adds **zero** distinct relocation writers; prior writer #29 stays separately certified.

## Original source IFUNC115 derived SHA256 provenance

[Original x86 immutable ELF source-only preflight #42775536103](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42775536103) succeeded, strictly requiring the independently certified IFUNC114 complete chain before starting. Source facts:

- `R_X86_64_IRELATIVE`, original libc source index **115**, `DT_JMPREL` table ordinal **29**.
- Original x86 guest resolver `0x8041375e0`, unique alias group **[115]**.
- Original target relocated guest qword slot `0x804202cd0`, unmodified initial qword `0x28280`.
- SHA-pinned source libc `7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906` and GNU ld-linux `cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae`.
- Source-only GDB hardware WRITE watch was independently preflighted and must be byte-identical to the real ARM64 runner's generated GDB script.

## New hardware writer gates

- Genuine source-locked original Linux ARM64 FEX native writer run [#42775875845](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42775875845), targeting exactly `0x804202cd0`.
- Strict independent original GNU x86 ELF/hash and native AArch64 `stlr x4,[x19]` writer proof with ten altered logs and other-source IFUNC114 log rejection [#42776000011](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42776000011). This replay pins the exact genuine run ID, original source-only receipt, and prior full IFUNC114 proof. Only if **both** succeed may ledger increment **29 → 30**.
- Subsequent original x86 source-only C3 RET disassembly is gated on [#42776000011](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42776000011) and cannot itself prove native C3 RET, stack READ, or gameplay. Workflow: `.github/workflows/kernix-g0-original-ifunc115-source-ret-candidates-preflight.yml`.

**All-147 relocation closure, original x86 Linux ELF dynamics as a whole, real Android/Bionic 16KiB pages, graphics, Wine/Proton, APK and actual games/FPS remain independent release gates.** Fail closed and do not count source plans as hardware results.


## Confirmed writer #30 and genuine IFUNC115 return-chain native proof work

Source-locked real original GNU Linux ARM64 FEX hardware WRITE [#42775875845](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42775875845) **succeeded**. Strict independently pinned native hardware writer proof with source ELF hashes, original guest target and ten altered-log controls [#42776000011](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42776000011) **succeeded**. This independently authenticates a 30th *distinct* source relocation destination; update the accepted ledger **29/147 → 30/147**. Repeated validation of the same target must not increase the ledger again.

[Source-only IFUNC115 original true x86 C3 RET disassembly #42776113078](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42776113078) **succeeded**, identifying exactly 12 bounded source `C3 RET` candidates: `0x80413763d`, `0x804137654`, `0x804137689`, `0x8041376a4`, `0x8041376cc`, `0x8041376d4`, `0x804137796`, `0x8041378e0`, `0x804137af8`, `0x804137c6f`, `0x804137d42`, `0x804137db2`. This is source disassembly only; it **does not** establish runtime RET or hardware stack READ.

[Source-pinned 12-RET one-guest stack-READ GDB plan #42776804091](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42776804091) **succeeded**. The next real dynamic hardware proof chain has been wired:
- [Real Linux ARM64 FEX same-process GNU CALL → source C3 RET → hardware stack READ → GNU WRITE #42777033772](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42777033772).
- [Strict independent replay, exact source and corrupted-log negative controls #42777146919](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42777146919).

**Full IFUNC115 RETURN/stack-READ proof is OPEN until both above runs pass**; its success would add **zero** further writers, keeping **30/147**. Original 147-relocation closure, Android, graphics, Wine/Proton and APK/game performance have not been demonstrated by these Linux tests.

A separate [source-only native IFUNC stage duplicate audit #42777034114](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42777034114) succeeded after removal of accidental duplicate IFUNC115 real run stages. The audit is CI hygiene, not a native hardware proof.
