# KERNIX G0 — original GNU libc IFUNC122 source and native evidence checkpoint

Date 2026-11-10. Branch `kernix-native-engine-v1`.

**Certified original GNU x86 libc distinct native FEX ARM64 relocation writer targets: 36/147 until IFUNC122 independent replay succeeds.** The counter tracks distinct GNU x86 source relocation write targets; it is not a count of fully supported Windows games.

## Prerequisite original IFUNC121 full chain — independently CLOSED

- Genuine one-FEX-process ARM64 runtime original `CALL → source C3 RET → stack hardware READ → GNU store`: [#42813450427](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42813450427) **success**.
- Independent immutable-source/JIT/hardware evidence replay, ten native-log negative controls and authentic wrong-IFUNC rejection: [#42813668725](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42813668725) **success**.
- The distinct #36 source native writer target was certified earlier by [#42812939550](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42812939550); later CALL/RET evidence added zero new distinct targets.

## Original GNU libc IFUNC122 immutable x86 source-only inventory

- [Source-derived exact relocation preflight #42814842533](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42814842533) **success**.
- Original `R_X86_64_IRELATIVE` source relocation index **122**, `DT_JMPREL` ordinal **36**.
- Source resolver guest RIP **`0x8040b41c0`**, genuine resolver alias indices **[122]**.
- New distinct source target qword **`0x804202c88`**, original unmodified qword **`0x281f0`**.
- SHA256-pinned original libc `7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906`, ldso `cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae`.
- Exact native writer watch is only a **source-only candidate**. It does not prove original hardware execution by itself.

## Required separate ARM64 FEX hardware evidence gates

1. [Real Linux/FEX ARM64 original IFUNC122 GNU writer hardware trial #42815181950](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42815181950), with source-byte-identical GDB plan, original GNU `stlr x4,[x19]` native provenance, pinned prior IFUNC121 full closure.
2. [Independent original IFUNC122 hardware writer replay #42815454335](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42815454335), requiring native run success, unchanged original ELF source, original target/value and alias parity, ten tampered live native logs rejected and wrong-IFUNC121 native log rejected.
3. **Only upon both successes** is a **37/147** distinct native writer target certified. Source-only plans or a successful compilation are not writer hardware witnesses.
4. Original IFUNC122 `CALL → source C3 RET → hardware stack READ → GNU WRITE` needs a separate full source-disassembly/native/independent RETURN proof, adding **zero** further distinct targets.
5. Static nonduplicate-stage and index-scoped artifact archive audit [#42815181918](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42815181918) **success**. Per-index archive patterns replace redundant explicit artifact filenames without dropping any archived witness.

This limited GNU Linux/FEX evidence does **not** establish 147/147 relocation closure, Android Bionic/16KiB pages, Wine/Proton, Vulkan/DXVK/VKD3D, APK release or actual Windows game performance.
