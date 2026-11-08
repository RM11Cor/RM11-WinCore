# KERNIX G0 — original GNU ld-linux self-IRELATIVE writer in real FEX ARM64

**Date:** 2026-11-08. **Branch:** `kernix-native-engine-v1`.
**Status:** original ldso self `IRELATIVE` **zero-to-zero writer exact x86 RIP PROVEN** after real original-main guest `mprotect(10)`; original ldso resolver entry/return independently **OPEN**, original ldso own `PT_GNU_RELRO` guest protection **OPEN**, Linux guest main exit zero **OPEN**, Android/Wine/Proton/games **OPEN**.

## Authentic source, not invented kernel output

- Original FEXCore upstream pinned commit: `02e24ca5c01ed0c864466ed573db347336f70170`.
- Original x86 GNU `ld-linux-x86-64.so.2` SHA256: `cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae`.
- Source original `R_X86_64_IRELATIVE` exact relocation tuple: target ELF VA `0x36360` (guest `0x801036360`); original resolver source VA `0x1a8e0` (guest `0x80101a8e0`); initial file-backed 64-bit qword `0`.
- Source original GNU x86 writer at guest RIP **`0x80100fd60`**, file offset `0xfd60`, exact ELF bytes **`49 89 06`**, decoded as **`mov QWORD PTR [r14], rax`**.

## Live actual Linux ARM64 FEX process

[Full real original FEX ARM64 GDB hardware capture #42519037018](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42519037018) (artifact `KERNIX-G0-Original-GNU-Ldso-IRELATIVE-After-Real-FEX-Main-Seal-ARM64-ONLY`) contains:

1. Source-locked real Linux x86 GNU `mprotect(10)` for main executable at RIP `0x801025db9`, protecting original main source guest page `0x800003000`, real native return/readback `r--p`, real post-protection child `SIGSEGV` write denial and guest `RAX=0` only afterward.
2. Native real AArch64 **hardware access watchpoint** on original GNU ldso target `0x801036360`, armed **before original FEX starts**. GDB printed a registration receipt and then a **separate actual native hardware stop after** the main page was protected. Both events must be disambiguated.
3. Native post-access host PC `0xffffa4ce96a4`, previous native instruction at `0xffffa4ce96a0`: **`stlr x4, [x19]`**, live `x4=0`, live `x19=0x801036360`, target qword **zero both before and after**. Source FEX fixed x86 register map **RAX→x4, R14→x19**.
4. Real FEX JIT header: `guest_entry=0x80100fd60`, `guest_size=3`, `count=2`, `data_offset=0x28`, `writer_host_pc=0xffffa4ce96a0`. Compressed RIP map begins `80 01 80 02` corresponding to source FEX host 4-byte and 8-byte offsets mapped to same guest x86 instruction. Source/live guest bytes at `0x80100fd60` exactly `49 89 06`.
5. These observations establish **execution of an original GNU ld-linux guest x86 zero-to-zero STORE**, not merely file-load zero, snapshot zero, or compiling a guest instruction without executing it. The hardware capture job's first post-processing parser returned a failure because it expected no duplicated GDB registration/stop and no duplicated zero readbacks; its **raw native hardware trace itself is positive**.

[Independent source ELF SHA and AArch64 hardware/JIT x86-RIP replay #42519842062](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42519842062) **SUCCEEDED**, checked the archived true hardware trace against the exact original ELF file from the archived triad, and rejected **18 deliberately corrupted claims**, including fake native `STLR`, wrong source opcode, fake guest RIP, wrong native registers, bad RIP map, and false protection/game readiness.

## Source-exact original GNU ldso self PT_GNU_RELRO **two 4KiB pages**, not one

The [independent original x86 ELF GNU ldso source PHT + IRELATIVE audit #42520531165](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42520531165) **succeeded** and confirmed that source SHA-pinned original `PT_GNU_RELRO` spans two **complete** 4KiB Linux native guest pages:

- Guest first page: `0x801036000` through `0x801036fff`.
- Guest second page: `0x801037000` through `0x801037fff`.
- Total intended original GNU ld-linux self protection request: start `0x801036000`, **length `0x2000` (8KiB)**, `PROT_READ`. The original self IRELATIVE slot `0x801036360` is on the first page.
- This source-only PHT audit is NOT a genuine original FEX guest syscall argument or result: those must be authenticated at the live trap. The older single-page `0x1000` assumption **failed correctly** against original ELF metadata and MUST NOT be used to seal the original interpreter.
- The separate opt-in native Linux AArch64 original FEX experiment in `native-engine/android-host/kernix_g0_original_ldso_self_relro_real_fex_guest_mprotect_8k.h` rejects host 16KiB kernel pages, unauthenticated original x86 syscall, mismatched two-page original ELF source PHT, foreign native VMAs, and adjacent-page rights changes. No user APK/Wine/game activation is implied.

## Never promote partial execution into runtime readiness

The source original resolver RIP `0x80101a8e0` is present as executable original ELF bytes, but that source byte presence alone and even execution of the later original writer **do not independently trace entry and return from the resolver**. The later original GNU ldso self-`mprotect(10)` request on `0x801036000` is visible after source main sealing in the [real original FEX main RELRO success run #42517719335](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42517719335), but the existing main-only source diagnostic guard correctly rejects that *different* requested original loader page; no authentic original ldso self-`PT_GNU_RELRO` protection has yet been granted.

Next: independently authenticate the original resolver call/return guest RIP, the source-original interpreter self `PT_GNU_RELRO` **two-page (8KiB)** span and writable native ownership, then test a **separately compiled and strictly pinned original ldso guest `mprotect(10)`** with native read-only permission and safe post-seal child write denial. Never round a 4KiB guest request to a potentially unsafe 16KiB host page. Keep original GNU ldso/libc full dynamic relocation closure, Windows runtime and real Android games gated until genuinely tested.
