# KERNIX: evidence-driven compatibility research and release gates
2026-11-03 — Active engineering policy; not a guarantee that all PC games can run.

## Non-negotiable approach

1. One phase at a time; use exact upstream source locks, independent acceptance tests, and an auditable rollback. Do not merge FEX, Wine, graphics and input changes into one trial.
2. Compare the same guest with a reference environment where possible (native Linux AArch64 FEXCore, x86_64 Linux Proton, original Windows), before assuming that an upstream translator is defective.
3. Distinguish green compile, diagnostic execution, correct guest registers, Android host integration, real rendered frame, playable game, and stable gameplay. One is never evidence of the next.
4. Never fake real guest values: actual x86 register values must reach the syscall handler. Do not substitute hardcoded flags, file descriptors, memory witness values or synthetic argument constants for real runtime state.
5. Verify Android Bionic, sandbox/seccomp, rootfs boundaries, filesystems, ELF dependencies and Vulkan separately. An Ubuntu ARM64 build does not demonstrate Android compatibility.
6. Use versioned component manifests with SHA256 verification, upstream licenses, per-game profiles and easy rollback. Protect user saves and prefixes.
7. Avoid endless phone stress loops. CI first, then one narrowly specified real-device test; record device, Android build, pinned driver and thermal observations.
8. Anti-cheat, DRM, authorization, entitlements, online-only requirements and kernel components are separate limits. Diagnose accurately; do not bypass them or promise unsupported games will run.

## Root-cause classification: the first failure matters

| ID | Layer | Evidence and focused probe |
| --- | --- | --- |
| A | x86-64 translation / JIT / syscall ABI | Register-state traces, x86 stack memory witness, instruction flags, real CPUState at syscall; cross-host reference |
| B | Android host | Bionic dynamic loading, denied syscalls/seccomp, file layout, rootfs and process signals |
| C | Windows runtime | Wine / Proton API and DLL imports, prefix, startup and WoW64 integration |
| D | Graphics | Driver Vulkan features, DXVK/VKD3D requirements, swapchain creation, shader and first frame |
| E | Launcher and online services | Steam / EA / Rockstar / Ubisoft official launcher status, entitlement and network-specific errors |
| F | Protection | Game/vendor anti-cheat requirements and kernel-level components, with official compatibility guidance |
| G | Resources and input | Memory pressure, thermal, frame pacing, device controls and XInput/SDL bridge |

A black/white screen and an exit code are observations, NOT proven root causes.

## Ordered phase gates

**G0 — Source and compatibility research.** Gather upstream issues, official requirements, device features, exact build revisions and known-good reference tests. Distinguish a specific reproduced bug from anecdotes.

**G1 — Translator correctness.** Confirm guest GPRs, flags, stack memory, block transitions, real mmap/write/getpid/munmap and syscall ABI on native ARM64. Validate real argument values in CPUState at callback, not just a green workflow. Separately validate on Android. No gaming-release claim until pass.

**G2 — Native Android/Wine bridge.** Verify Bionic libraries, process/permissions, rootfs or valid compatibility boundary, Wine or Proton initialization, Windows DLLs and genuine PE executable startup.

**G3 — Vulkan/DirectX.** Inspect real GPU Vulkan version/extensions and limits; match DXVK to D3D8–11 and VKD3D-Proton to D3D12 with validated DXGI implementation. Fail with an understandable missing-feature diagnosis rather than random drivers.

**G4 — Games.** Begin with Hollow Knight / another user-confirmed control, then stable D3D11/12, then difficult launcher/network cases. For each test require launch, real first frame, menu/input, real gameplay and a session of measured stability, keeping each case independent.

**G5 — Performance.** Optimize JIT/cache, GPU/driver, memory and frame times only after correctness. Record reproducible FPS/frame times, thermal and memory usage; no synthetic FPS success claims.

**G6 — Release quality.** Verified source+licenses+binary hashes, install/launch/uninstall, isolation/rollback, controls, actual game session and crash reporting. Diagnostic APKs must never be labeled a completed emulator.

## Initial game research matrix (user observations, not verified root causes)

| Game | Observed on prior setups | Candidate layers to investigate; cause unverified |
| --- | --- | --- |
| Hollow Knight | Reported playable in Bannerlator and earlier custom builds | Baseline Wine/2D rendering/input and executable launch |
| The Witcher 3 | Reported playable in Bannerlator | Compare renderer choice D3D11 vs D3D12 and GPU path |
| CarX Street | Reported playable with variable FPS | Frame pacing, graphics, XInput and memory |
| GTA V standard / Enhanced | Edition-dependent working/black screens | Rockstar authentication, official launcher, PE/Wine runtime, DX, exact edition hash |
| Forza Horizon 5 | Black screen or crash in certain Android setups | D3D12 Vulkan features, Wine/Xbox/launcher and performance; officially playable on SteamOS as a DIFFERENT host |
| NFS Unbound | White screen in Bannerlator but gameplay previously reported in GameHub | EA App webview/login/launcher boundary vs engine D3D12 |
| The Last of Us Part I / II | Past launch failures | VKD3D-Proton, driver capabilities, memory, launcher, game build; investigate separately |
| The Crew Motorfest | Black screen in multiple prior setups | Ubisoft Connect, online services, protected components and graphics; respect official auth and policies |
| Hogwarts Legacy, Cyberpunk 2077, God of War | Early exit or low FPS | Investigate game-specific graphics features, CPU/translation, memory and resource pressure |

## Source-backed research notes (read date-sensitive issue comments)

- FEX upstream https://github.com/FEX-Emu/FEX ; its Android FAQ https://wiki.fex-emu.com/index.php/FAQ says the complete FEX Linux runtime does not directly support Android, while FEXCore library can be built for Android if a host handles integration.
- DXVK driver feature support https://github.com/doitsujin/dxvk/wiki/Driver-support : Vulkan capabilities, required extensions, and lack of official Android/mobile driver support vary by DXVK version.
- VKD3D-Proton https://github.com/HansKristian-Work/vkd3d-proton : D3D12 over Vulkan requires substantial driver features; a separate DXGI implementation is required.
- Forza official SteamOS FAQ https://support.forza.net/hc/en-us/articles/13169879356947-Steam-Deck-and-SteamOS-FAQ : Forza Horizon 5 is playable on SteamOS/Steam Deck, NOT proof of ARM Android support.
- EA launcher / NFS Unbound historical Proton issue https://github.com/ValveSoftware/Proton/issues/7611 : specific launcher failure, NOT proof of the current version.
- The Last of Us Part II Proton report https://github.com/ValveSoftware/Proton/issues/8585 : launch failures reported for some Linux/PC driver configurations, NOT a Snapdragon diagnosis.
- Ubisoft official support response https://steamcommunity.com/app/2698940/discussions/1/585057730992321899/ : Linux not officially supported; launcher and service detection can fail even when some users can play.

## Evidence record per game

- Exact edition/store/build, legitimate authorization status (no credentials or private tokens), guest executable architecture.
- Exact KERNIX, Android, GPU, driver, Wine/Proton, FEX, DXVK/VKD3D and relevant dependencies by verified revision.
- Timestamped stages: process starts, Windows loader, first frame, menu, gameplay; identify the FIRST failing stage.
- Actual Vulkan feature report, event/error code, redacted log and artifact hash.
- Repeatability on two identical runs, reference-host comparison, one-variable test and a regression guard.
- Classification: unverified / reproduced / upstream-confirmed / fixed-in-CI / device-verified.

## Known current translator blocker

G1 is NOT passed. The native Ubuntu ARM64 FEX test of 2026-11-03 compiled a candidate but the four-syscall guest still failed: correct guest-written R10/R8 stack values did not appear in CPUState at callback. Run 41687568620 rejected v0.22 after R10/R8 were marked dirty but remained incorrect. Run 41690060009 failed at the diagnostic stage because a JIT-compile-time print was incorrectly demanded in guest runtime stderr; such an assertion is invalid evidence of runtime register capture. Correct instrumentation placement and prove actual callback CPUState; do not label v0.23 a repair. None of these native Ubuntu ARM64 outcomes prove Android/Bionic gameplay.

The priority after this roadmap is validate the reference translator and test harness itself, not increment APK versions or run more random games.