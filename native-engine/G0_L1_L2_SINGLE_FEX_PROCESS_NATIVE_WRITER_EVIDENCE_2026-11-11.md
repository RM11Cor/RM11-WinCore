# KERNIX G0-L1/L2 — same native FEX process original GNU writer evidence

**Status:** 147/147 ORIGINAL GNU ELF relocation source indices have distinct
native ARM64 FEX writer evidence, separately proven in earlier G0 runs.
**New runtime-level checkpoint:** Four genuine original GNU relocation
destinations were written by authentic x86 loader-translated native AArch64
`stlr x13, [x4]` in **one** Linux ARM64 FEX host inferior process. This
is *not* proof all 147 relocations ran in one process.

## Independently verified native observations

| Gate | Source indices | True Linux ARM64 FEX process | Evidence |
|---|---|---|---|
| G0-L1 raw | 81, 82 | PID 5055 | Actions #43070211078 |
| G0-L1 independent | 81, 82 | PID 5055 | Actions **#43071199839**, 16 forged CPU/JIT/PID logs rejected |
| G0-L2 raw | 81, 82, 83, 84 | PID 4993 | Actions #43072263520 |
| G0-L2 independent | 81, 82, 83, 84 | PID 4993 | Actions **#43072888167**, 24 forged CPU/JIT/PID logs rejected |

All four original libc `R_X86_64_GLOB_DAT` entries came from SHA-pinned
original GNU source ELF, not fabricated slots:

| Original source | Symbol | Guest target | Real written qword |
|---|---|---|---|
| DT_RELA81 | `__progname_full` | `0x804202fb8` | `0x804204378` |
| DT_RELA82 | `argp_program_version_hook` | `0x804202fc0` | `0x80420b2b8` |
| DT_RELA83 | `optarg` | `0x804202fc8` | `0x80420a4e0` |
| DT_RELA84 | `malloc` | `0x804202fd8` | `0x8040ad500` |

Each source event recorded original guest x86 instruction bytes `4c 89 08`,
FEX JIT entry `0x80100fb8b`, authentic native `stlr x13, [x4]`,
same inferior PID and true native value in x13 and destination in x4.
All target qwords were observed zero before the loader write section.

## No false extrapolation

- Four same-process stores are **4/147 of the next PROCESS-level gate**.
  They do not imply that the other 143 original sources were executed,
  nor that all other relocation types, IFUNC, TLS, RELR, loader self-relocs,
  symbol visibility or RELRO work in this process.
- Linux ARM64 GitHub Actions is not the user's Android/REDMAGIC device,
  and no Wine/Proton PE image, game, graphics path, Vulkan swapchain or FPS
  is demonstrated.
- Release labels `all_147_same_guest_native_execution_proven`,
  `full_original_libc_147_process_relocation_closure_proven`, and
  `Android_Bionic_Wine_Proton_games_proven` remain **false**.

## Next independent gate

Expand to eight **real GNU GLOB_DAT** slots `DT_RELA77..84` using
two successive windows of four genuine GDB hardware watchpoints in a
*single uninterrupted* ARM64 FEX inferior. AArch64 hardware watchpoint
capacity must not be assumed beyond four. The GDB callback only stops at
a window boundary, and re-arm must occur while the same inferior remains
paused, before the next GNU source store executes. Record exactly one
unchanged pid across both windows, all original target before/after
qwords, the original JIT+ARM64 register provenance, then independently
reject forged evidence. Any failure stays a failure; it does not
invalidate the already certified four-source L2 gate.
