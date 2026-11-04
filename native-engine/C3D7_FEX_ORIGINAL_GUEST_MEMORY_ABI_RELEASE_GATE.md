# KERNIX G2-E/C3-D7 — Actual original FEXCore guest-memory ABI gate

Status: DESIGN/RESEARCH ONLY — no source-tested runtime, signed APK or phone execution yet. Branch: kernix-native-engine-v1.

## Observed facts

- C3-D6 R1 failed on Android with errno 12 before any native original guest page reserved. High forced Linux guest addresses may exceed Android ARM64 user VA reachability; this was not conclusively diagnosed by R1's broad error classification.
- C3-D6 R2 succeeded on REDMAGIC Android 16 with 4KiB native pages, original 609 Linux data pages in a kernel-chosen nonexecutable read-only compact window, with original logical guest VA metadata maintained by KERNIX. All pages released. See evidence/g2e-c3d6r2-android-device-observed-pass.json.
- No FEX executed in C3-D6 R2: FEX_EXECUTED=0. The KERNIX host-only lookup does NOT become an FEX JIT memory translation API.
- Source-pinned original FEX AArch64 on Linux proved a separate 41-byte x86 SYSCALL fixture (C3-D5), but that fixture is not the original dynamic Linux ELF guest.

## FEX address translation blocker

Official FEXCore IR documentation https://github.com/FEX-Emu/FEX/blob/main/FEXCore/docs/IR.md describes guest IR Load/Store translation by adding a VM memory base to guest virtual addresses. A 609-page compact host staging window plus sparse table is not automatically compatible with one additive FEX memory base. The pinned original upstream FEX commit 02e24ca5c01ed0c864466ed573db347336f70170 must be source-audited for the precise frontend instruction-fetch, JIT data load/store, syscall guest pointers, signal, page permissions and memory-base ABI; current docs alone cannot attest pinned behavior.

Possible real approaches (none approved yet): reachable original guest VAs with ownership-safe mappings; one demonstrably valid linear memory-base offset; or audited source-level sparse translation / full guest relocation with equivalent fetch, data, stack and syscall semantics. Do not claim that a sparse table solves FEX memory accesses.

## Mandatory C3-D7 release gates

- Pin FEX commit and compile-time ABI. Identify actual guest instruction fetch, data load/store, FEX guest memory base, signal and syscall pointer translation call-sites.
- Establish native Android address space bounds non-destructively; never force MAP_FIXED over existing mappings.
- Prove one coherent identity or non-identity guest mapping that satisfies code fetch, writes, stack, relocations, TLS, and syscall pointers. Enforce W^X and resource cleanup.
- On Linux ARM64 first, actually execute a bounded x86 fixture with source-pinned FEX reading and writing through the selected memory contract; observe genuine CpuStateFrame RIP and results.
- Only after Linux source proof, build a separately signed opt-in bounded Android child with real FEX and verify on-device non-identity guest fetch/load/store; reject if incompatible or unauthorized. Preserve baseline KERNIX v0.27.
- Only then attempt original guest Linux ld-linux/glibc startup, Wine/Proton and Windows games. No synthetic success marker substitutes for actual guest execution.

Stage verdict: C3-D6 R2 Android guest DATA staging PASS, FEX original memory ownership/guest execution NOT PROVEN. Do not re-run data-only tests unless debugging.
