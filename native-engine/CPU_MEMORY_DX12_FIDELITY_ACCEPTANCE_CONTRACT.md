# KERNIX — CPU, guest memory and DirectX 12 fidelity acceptance contract

2026-11-07. Engineering requirement requested after the user's observed failures in demanding Windows games (including The Last of Us and other D3D12-class titles). **Not a declaration of implementation or a guarantee of game compatibility.**

## Objective and diagnostic discipline

KERNIX must provide a coherent, *truthful* Windows/guest view of CPU ISA, thread topology, memory, available resources, GPU/D3D capabilities and driver behavior. A game that detects a processor, queries system memory, allocates GPU memory or probes D3D12 support must get mutually consistent responses backed by a tested implementation, or a clear unsupported-feature error. Do not fabricate CPU extensions, VRAM, D3D feature levels, driver versions or Windows APIs to clear startup checks. An observed black screen or process exit **does not prove** a CPU/memory-identification bug; first failing subsystem is determined by traces.

This is an independent cross-layer compatibility policy on top of the existing G0–G6 gates, NOT permission to conflate the phases or ship experimental code.

## Required subsystem contracts

### C1 — x86-64 CPU identity, execution and OS exposure

- Cross-check FEX guest CPUID leaves, vendor/brand string, logical processor count, topology, cache leaves, feature bits, family/model and supported instruction sets against what the actual translator can execute. CPUID must be internally consistent with XGETBV/XCR0/XSAVE exposure, context-switch state and Wine/Windows-visible processor information.
- Verify SSE/AVX/AVX2 and dependent state management **only where supported and translated correctly**. Test FMA, BMI, AES, atomics, unaligned memory, flags, SIMD width, exceptions, JIT cache invalidation and signal behavior separately. No unsupported AVX-512 or other feature advertised merely for a game check.
- Test physical/virtual CPU counts, affinity, timer/frequency and thread scheduling at the Win32 API boundary (e.g. GetNativeSystemInfo, GetLogicalProcessorInformationEx, IsProcessorFeaturePresent, QueryPerformanceCounter) in addition to raw Linux guest CPUID.
- Golden tests: identical CPUID and XGETBV on repeated runs; no feature advertised without an executable instruction test; deterministic failure with an explicit reason for an unsupported instruction; actual Windows guest API reporting verified from within Wine/Proton.

### M1 — guest memory correctness before performance tuning

- Reconcile guest x86_64 page permissions, fixed mappings, aligned/unaligned reads/writes, little-endian layout, stack guards, mmap/munmap/mprotect, TLS/FS/GS, memory faults, JIT coherence and signals with Android host page size. A 4 KiB guest page and a possible 16 KiB host kernel page require **explicit subpage accounting**, never unchecked 1:1 mprotect assumptions.
- Verify original ELF PE loader sections, RELRO timing, RELA/RELR/GLOB_DAT/JUMP_SLOT/IFUNC/TLS relocation ownership and completion. Never seal a page based only on preflight metadata or a diagnostic fixture's own relocation write.
- Verify genuine Win32 VirtualAlloc/VirtualFree/VirtualProtect/VirtualQuery, heap allocations, mapped files, section objects, address-space fragmentation, large allocations, memory-mapped asset streaming and exception behavior. Track Windows address-space availability/commit, native memory footprint, swap/pressure and Android low-memory termination separately.
- Resource reporting: distinguish physical RAM from *currently available* RAM, guest virtual memory from committed memory, and GPU local budgets from system RAM. Never promise a fixed GPU VRAM size on a shared-memory mobile GPU.
- Golden tests: genuine Windows PE probes exercising allocation/protection/query consistency and stress/fragmentation; guard-page faults must be reported correctly; no silent read corruption or stale mapping after unmap; verify resource reporting under constrained memory and lifecycle suspension/resume.

### G1 — Vulkan, D3D12 and DXGI capability truth

- Gate each immutable Turnip/Vulkan driver with real Adreno device ID, Vulkan API level, extensions, formats, feature chains, limits, descriptor indexing, subgroup/wave capabilities, synchronization, memory budgets and sparse resources (when actually implemented). Record the driver and kernel versions alongside device thermal state; do not assume all Adreno versions behave alike.
- For each immutable VKD3D-Proton + DXGI + Wine/Proton assembly, validate D3D12 adapter enumeration, CreateDevice, feature-level checks, GetFeatureSupport, shader model, root signatures, PSO creation, descriptor heaps, resource heaps, buffer/image memory bindings, barriers, fences, command queues, residency and device removal/recovery. Driver features reported to a game must be realizable, not spoofed.
- DXVK is for Direct3D 9/10/11 translation where applicable; **DX12 goes through VKD3D-Proton**. Validate DXGI interactions for both paths rather than swapping wrappers interchangeably.
- Gate actual D3D12 texture/geometry streaming, shader compilation and cache consistency with native Vulkan allocation limits. Verify dedicated vs shared video-memory budgets honestly through DXGI memory-info queries, not a hardcoded advertised VRAM amount.
- Golden tests: real Windows PE D3D12 adapter/feature enumerator on the target phone; allocate/upload/read back buffers and textures; compile shaders and create PSOs; submit command buffers, present first frame and validate GPU memory-budget/deferred destruction; capture DXGI/D3D12 HRESULT, VK_ERROR, device lost, resource budget and GPU driver logs as distinct diagnoses.

### W1 — real Windows runtime and dependency closure

- Verify the actual Windows-visible DLL/kernel32/ntdll/win32u/ntoskrnl-stub API contract that a selected game requires, including CPU/memory information and system calls; distinguish unsupported Win32 API from Linux guest syscall or translator faults.
- Use one signed/hash-verified component lock per game: pinned FEX, Wine or Proton, DXVK or VKD3D-Proton, Turnip/Vulkan, dependency versions and architecture. Reject incompatible ABI mixes rather than silently substituting components.
- Preserve exact call-path logs from game -> Windows API -> Wine/Proton -> guest Linux syscall -> FEX -> Android host -> Vulkan driver; redact user paths/tokens. Do not claim that source verification, a green CI job or startup tests mean a real game is playable.

## Required game-compatibility acceptance sequence

| Gate | Actual evidence | NOT enough |
| --- | --- | --- |
| C1/M1 unit | CPU leaf + executable opcode checks; Win32 process/memory API cross-check; real guest allocation and protection behavior | Synthetic CPUID strings or an Android-only metadata report |
| W1 integration | Native FEX executes a real Wine/Proton Windows PE and relevant CPU/memory APIs return consistent results; dynamic loader truly initialized | Green compile or artificial relocation fixture |
| G1 feature | Original target-device Vulkan feature/limit dump + selected VKD3D-Proton/DXGI feature probing + resource upload/readback | Picking the newest driver or setting a D3D feature-level flag |
| G1 first frame | Real game swapchain/frame capture, shader/PSO proof, GPU budget and fault logs | A solid test color or blank screen |
| Per-game play | Main menu, input/XInput, real gameplay, frame timing, repeated stable launches and memory/thermal measurements | One boot logo, benchmark synthetic FPS or launcher-only success |
| Release | Signed APK with pinned runtime components, rollback, independent device and game case evidence | A successful Linux ARM64 CI run |

### Priority regression matrix

- **The Last of Us Part I/II:** user's observed failure; start with CPU capability and Windows-memory/VRAM allocation tests, then DX12/DXGI feature negotiation and shader/resource pressure. These are *hypotheses*, not a verified root cause.
- **Other heavy D3D12 titles identified by the user:** capture title/version/executable and renderer as known; do not silently turn an unclear title into a different game. Reproduce first failure under a control emulator/reference when licensing and test access allow.
- **Known lighter control:** user-confirmed Hollow Knight or similar can check baseline FEX/Wine/input without incorrectly asserting D3D12 coverage.
- **Negative tests:** deliberately unsupported CPUID features, missing Vulkan extensions, exhausted guest RAM/commit or GPU budget, incompatible ABI and invalid PE imports must produce accurate errors, never fabricated compatibility.

### Historical game memory failure preservation and verified diagnostic gate (2026-11-08)

The user's earlier game/session failures are preserved as **observations rather than diagnosed root causes** in the [eight-case historical game memory triage ledger](evidence/kernix-game-memory-failure-regression-cases-2026-11-08.json). Its [fail-closed validator](ci/kernix_game_memory_triage.py) and [independent GitHub Actions regression gate](../.github/workflows/kernix-game-memory-triage-regression-gate.yml) require source-scoped, non-personal records and reject eleven falsified cause/proof promotions. The validator is **not** in the Android runtime, is **not** a memory fix and has executed no PC game.

- **The Last of Us Part II Remastered:** earlier FEX messages about failing to find an appropriate guest *virtual-address* location after 16 attempts and a later `0x80000003` event are not sufficient to prove physical RAM exhaustion, DXGI VRAM exhaustion, a guest-space fragmentation root cause, or the cause of the black screen. First failing guest RIP, reservation size/alignment, flags, address owner, Linux errno / NTSTATUS, host maps and real PSS/commit metrics must be captured before any such promotion.
- **Forza Horizon 5:** repeating `RtlInitializeExtendedContext2` context flags is not a memory-fault diagnosis. **The Witcher 3:** an exited launcher, still-live Wine child processes and a vanished window do not prove guest VA exhaustion. **Proton/WineServer:** a SIGSEGV before GDI plus a suspected message-queue failure still lacks a source-attested first faulting address and owner.
- **On-device hang/warmth:** a previous diagnostic stopped the app/phone, but no thermal or Android low-memory-killer root cause was established. Avoid prolonged stress and repeated loops; use bounded child watchdogs and one consent-only phone probe after independent host evidence.
- **Separate memory spaces:** any future on-device capture must keep (1) x86 guest VA reservation and protection, (2) Wine committed/available memory, (3) Android host RAM/PSS/LMKD, and (4) Vulkan/DXGI heap budget in distinct fields. Include host and guest page size for 4 KiB versus 16 KiB enforcement and first fault RIP, guest region ownership and protection.
- **No regression by default:** preserve all game saves, prefix directories, component versions and stable signed APK. Do not change game files, advertise fake CPUID/RAM/VRAM, or suppress a fault by making guest pages RWX.

The historical ledger is a **future G2/G4 acceptance input only**. Its PASS cannot advance current original GNU-ldso IRELATIVE/RELRO closure (G0/G1), Android Wine/PE execution, D3D12 compatibility or actual gameplay. Each game requires an independent and genuine first-failure capture before any compatibility-specific patch or per-game component-selection claim.

### Definition of done and operational constraint

This requirement is considered implemented **only** as separately evidenced gates per layer and real-device game sessions. No claim of 100% compatibility, flawless behavior, or guaranteed high FPS is justified in advance. Preserve current stable KERNIX and user files, do not modify working installation or game data, and isolate each change to its own reversible commit/test gate. While the current original GNU loader and main ELF RELRO runtime remain unfinished, this contract is a **future release blocker**, not a request to prematurely skip to Vulkan or ship a DX12 APK.
