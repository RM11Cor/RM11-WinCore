# KERNIX G0-L3 checkpoint — eight genuine GNU source writes in ONE FEX ARM64 inferior

Date: 2026-11-11. Branch: `kernix-native-engine-v1`.

**Independently passed 8 original source relocation targets in ONE Linux ARM64
FEX process**. This is a NEW, distinct integration metric. The canonical
individual GNU source writer ledger remains **147/147**, already certified.
This new result does not imply 147 relocations executed together, or a
fully working dynamic interpreter, Wine, Android guest or real game.

## Immutable pinned native evidence

- GNU source plan from original SHA-pinned libc and loader original guest
  ELF: Actions **#43073764555**, with independent source comparison to
  both prior source cohorts `DT_RELA[71..80]` and `[81..84]`. No native
  process-level result was claimed by the source-only plan.
- Raw Linux ARM64 FEX/GDB hardware observation: Actions **#43074056890**.
  Eight independent native `stlr x13,[x4]` traps were observed in one
  Linux FEX inferior **PID 5031**, in strict original source order.
- Independent proof: Actions **#43074639291**. Original GNU source metadata
  and the raw GDB trace SHA were re-verified separately, with **32
  forged-events negative controls rejected**, including window rearm
  before completion, different inferior PID, false native registers,
  corrupted actual store, mismatched original guest JIT and symbol
  values. Result recorded with all further release gate claims false.

## Real source write order

| Original GNU relocation | Symbol | Guest write target | Observed native write qword |
|---|---|---|---|
| DT_RELA77 | `h_errlist` | `0x804202f98` | `0x804201700` |
| DT_RELA78 | `__environ` | `0x804202fa0` | `0x80420ad58` |
| DT_RELA79 | `argp_err_exit_status` | `0x804202fa8` | `0x8042032e8` |
| DT_RELA80 | `svc_pollfd` | `0x804202fb0` | `0x804211808` |
| DT_RELA81 | `__progname_full` | `0x804202fb8` | `0x804204378` |
| DT_RELA82 | `argp_program_version_hook` | `0x804202fc0` | `0x80420b2b8` |
| DT_RELA83 | `optarg` | `0x804202fc8` | `0x80420a4e0` |
| DT_RELA84 | `malloc` | `0x804202fd8` | `0x8040ad500` |

Both watchpoint windows used the **same** FEX Linux ARM64 process PID 5031:
initial hardware watchpoint window [77,78,79,80], stopped and rearmed
[81,82,83,84] before continuing that *same* inferior, with a maximum
four simultaneously armed GDB hardware watchpoints. Each of eight native
writer hits recorded the original x86 loader source instruction
`4c 89 08`, original FEX JIT guest block at `0x80100fb8b`, native
CPU `x4` original GNU target and `x13` real written value, and the
actual AArch64 `stlr` instruction PC chronology.

## What is not established

- 8/147 in one FEX inferior is **not** 147/147 in one FEX inferior.
- No general ELF symbol interposition/version scope, loader self-RELRO,
  all RELR, IFUNC, signed TLS, all required syscalls and dynamic
  dependency closure have been proven in this single process.
- This is Linux ARM64 CI; **not** the Android/REDMAGIC Bionic device.
  No Wine, Proton, DirectX, Vulkan, GPU frames or game FPS proven.

## Recommended next experiment

Move to 10 original contiguous targets in one FEX guest process using
re-armed windows of no more than four hardware watchpoints, while
preserving all original per-relocation types and signed ELF addends.
Do not assume nearby source index 75 (`R_X86_64_64`) uses the same
semantics as all eight GLOB_DAT entries. Capture the actual live write,
CPU register provenance and original ELF relocation type, and only
then independently attest. Keep all original runtime/device release
gates closed until their actual native results pass.
