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

## Translator gate history: Linux passed, Android G1 proof subsequently observed (2026-11-03)

- **Root cause, now reproduced and corrected:** the KERNIX standalone FEXCore host had called `FEXCore::Config::Set(CONFIG_IS64BIT_MODE, "1")` *before* `ReloadMetaLayer()`. The reload clears its direct meta override, leaving the original unmodified ARM64 backend configured with the wrong guest mode. Previous v0.16–v0.24 JIT/IR register-capture experiments were not valid fixes.
- [Real native ARM64 run 41698161432](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41698161432) ran two independent variants with the exact pinned **unmodified** upstream FEXCore binary source. The original misordered host control failed expected R8/R10 callback values. Setting x86-64 guest mode AFTER `ReloadMetaLayer()` passed the real x86 SYSCALL callback with R10=34 and R8=-1 in `CpuStateFrame`, matched independent guest memory witnesses, passed four real guest syscalls (`mmap`, `write`, `getpid`, `munmap`), and passed single-instruction JIT/high-register controls. This is `G1-Linux-ARM64-verified` only.
- Android FEXCore host code was updated in [commit 81966dd](https://github.com/RM11Cor/RM11-WinCore/commit/81966dd8449fc96dbcbe32fa18a274f3799a6c3e) and the obsolete syscall source patch removed from the Android NDK audit. Compilation must be checked from [run 41699829425](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41699829425); this document does not claim its result.
- **Superseded by later v0.19 Android screenshot:** the user ran the corrected x86 ELF64 four-syscall probe on the actual Android phone and received `KERNIX_X86_ELF64_HEAP_EXEC_PASS`. The Java verifier requires child exit code 0 and exact two-line native stdout; its C++ guest test guards actual memory/syscall results and real PID-based RAX. Thus **the bounded four-syscall device test passed once**. Record as `device-observed`, not as a proof of full x86/Windows compatibility. The raw stderr/register trace, repeatability and broader G1 cases remain pending. Source: `native-engine/evidence/android-fexcore-v019-g1-4syscall-device-pass.json`.

Do not run random heavy games or release a complete-game emulator based solely on the Linux pass.
## Next active milestone after the on-device G1 four-syscall pass

G2 is now the **next separate engineering workstream**: source-attested Android/Bionic host process/runtime checks, dependency and namespace inventory, actual x86_64 Wine loader/PE startup through a supported and legally sourced distribution chain. First prove a tiny Windows PE test in a bounded sandbox with observable startup and import resolution. No random heavy-game trials, Steam launcher bypasses, or unsupported game-compatibility claims. Preserve Linux G1 and Android bounded G1 tests as fail-closed regressions. The GitHub Releases API currently refuses the publisher with HTTP 403 after APK validation; this is a release permission issue, not an execution failure.

## G2-A device-observed pass and strict G2-B separation (2026-11-03)

The user installed source-pinned, signed **KERNIX v0.20** ([CI 41706502028](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41706502028)) on REDMAGIC 11 Pro. Screenshot showed `KERNIX_G2_HOST_BOUNDARY_PASS` and exact original process output: `ABI=aarch64`, `PAGE_BYTES=4096`, `SECCOMP_MODE=2`, `NO_NEW_PRIVS=0`, `FEX_CORE_LOAD=1`, `FEX_CONFIG_SYMBOL=1`, `WINE_PE_EXECUTED=0`. The Java verifier enforces child exit 0 and exact stdout for this fixed Android native process probe. The source evidence is `native-engine/evidence/android-g2a-bionic-fex-v020-device-pass.json` (do not publish raw screenshot).

**Gate:** `G2-A Android Bionic-FEX host boundary = DEVICE-OBSERVED-PASS (one run)`. Do not extrapolate to Windows loader, guest glibc interpreter, syscalls beyond G1, Wine/Proton, Vulkan, DirectX, or games. Seccomp filter mode 2 is not proof of a specific prohibited syscall. Stage G2-B next with a *real Windows PE64 execution* positive control under an independently verified Linux x86_64 Wine host; separately gate ARM64 FEX and Android. Preserve the user's working v0.20 APK and G1 reference.

## G2-B architecture: reuse proven Linux FEX + Wine9 reference, isolate Android gap

The [Linux ARM64 FEX+Wine9 workflow run 41599070620](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41599070620) actually reported Linux guest /bin/true, x86_64 child process, real Windows PE64, Windows cmd.exe and a visible Wine Notepad X11 window. Its checks enforced real PE success before CI green; see `native-engine/evidence/linux-arm64-fex-wine9-pe-and-notepad-reference.json`. In that Linux runtime the host originally lacked `/usr/lib/wine`, so the successful test mirrored verified Wine bytes to a host path; Android cannot rely on this. The original `wine-11.0` Linux x86_64 source-built replay [run 41590803541](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41590803541) instead timed out on Wine service boot and PE even though distro Wine's same PE succeeded. Therefore **reuse the already proven Linux Wine9 guest baseline**; do not randomly repeat Wine11 failures or claim both Wine builds work.

New `G2-B` code protects access to a future app-owned guest rootfs, but is not wired to FEX syscall dispatch. Unit test does not imply Wine, PE or Android execution. The real Android bridge remains blocked on guest ELF dynamic interpreter + runtime/library resolution, process/thread syscalls and app sandbox compatibility. The existing user-observed G2-A result remains scoped to dlopen and Bionic host properties, not Windows execution.
