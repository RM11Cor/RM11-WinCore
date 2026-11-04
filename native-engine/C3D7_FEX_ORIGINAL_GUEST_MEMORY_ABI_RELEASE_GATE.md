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

## First source-pinned upstream audit (not a runtime proof)

- Confirmed directly from immutable upstream FEX commit 02e24ca5c01ed0c864466ed573db347336f70170, FEXCore/docs/IR.md: IR Load/Store guest address translation is expressed by adding the VM memory base to the 64-bit guest address. This source commit matches KERNIX previously compiled original Linux ARM64 FEXCore proof.
- Confirmed in exactly that commit's FEXCore/Source/Interface/Core/JIT/JIT.cpp line 928: AArch64 JIT allocates X1 as MemBase. MemoryOps.cpp lines 704-719 lower LoadMem via GenerateMemOperand and ARM64 native ldr instructions; this does not call KERNIX R2's sparse ReadOnlyNativePageForGuestVA() lookup.
- Therefore C3-D7 must not pass a KERNIX compact guest page pointer table directly into unmodified source-pinned FEXCore assuming full guest address compatibility. Memory-base and IR/JIT data path require a coherent tested strategy. Further investigation needed for instruction byte fetch, signals, JIT W^X and dynamic linker page semantics.
- Upstream immutable sources: https://github.com/FEX-Emu/FEX/blob/02e24ca5c01ed0c864466ed573db347336f70170/FEXCore/docs/IR.md and https://github.com/FEX-Emu/FEX/blob/02e24ca5c01ed0c864466ed573db347336f70170/FEXCore/Source/Interface/Core/JIT/JIT.cpp and https://github.com/FEX-Emu/FEX/blob/02e24ca5c01ed0c864466ed573db347336f70170/FEXCore/Source/Interface/Core/JIT/MemoryOps.cpp .

## C3-D7A real x86 load/store evidence gate (implemented; CI verdict pending)

- Linux ARM64 runtime source: android-host/tests/kernix_g2e_c3d7_original_fex_real_guest_ro_data_load_store_arm64.cpp. Workflow: .github/workflows/kernix-g2e-c3d7-original-fex-real-x86-elf-ro-load-result-store-linux-arm64.yml; run 41886251875.
- Stages authentic SHA-locked original ELF main/ld-linux/libc and initial stack into the same 609 kernel-chosen RO pages proven on Android by C3-D6 R2. Rechecks source byte equality for every original page before and after FEX execution.
- Drives exact source-pinned original FEXCore AArch64 JIT with fixed x86-64 sequence `mov rax,[rbx]; add rax,7; mov [rcx],rax; hlt`. RBX intentionally contains a **native host pointer** to a read-only original main-ELF page in the selected staging window, and RCX points to a distinct native writable host result page. The child verifies guest `RAX` AND host result against the authentic original 64-bit ELF bytes plus seven. No guest syscall can dispatch. It does not execute original guest ELF bytes as instructions.
- Even if run 41886251875 succeeds, this **only proves native-address / identity-pointer actual x86 memory load/store on Linux ARM64**. It is NOT the required guest-high-virtual-address -> compact-host-VA runtime translation: x86 RBX is not the original 0x5555... guest logical VA. The pinned FEX source remains unchanged. Never infer Android guest JIT or original ELF PT_INTERP/glibc execution from this CI.
- Release gate after proof: design real source-pinned FEX guest memory mapping across instruction fetch, loads, stores, stack, syscall pointers and signals; test nonidentity addresses with accurate RIP before Android APK/JIT path. KERNIX host v0.27 remains unchanged; no new signed APK in C3-D7A.
