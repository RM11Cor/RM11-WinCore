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

## G2-B staged symlink-aware guest rootfs primitive (2026-11-03)

A new `kernix_guest_rootfs_symlinks.h` (separate from the original no-link reader) scopes ordinary Linux symbolic links to the app-owned guest-rootfs descriptor, with bounded traversal, exact in-root file FD, and CI tests for loop and path escapes. Legitimate absolute loader-style targets map inside the guest root. This is a Linux-native host CI unit test, **not** an Android kernel or Wine PE execution proof. Mutable filesystem races and rootfs mounts still require additional kernel-enforced isolation before accepting untrusted Wine installations. G2-B Windows PE on Android remains BLOCKED, while Linux ARM64 FEX+Wine9 has already passed the independent PE test.

## G2-B actual ELF64 dynamic-metadata read-only gate

CI now exercises a real host-compiled x86_64 dynamically linked ELF64 guest whose PT_INTERP and DT_NEEDED entries are verified from real ELF bytes and whose loader/libc are found inside a temporary, rootfd-scoped Linux filesystem. Missing or corrupted ELF objects fail the exact test. This does **not** execute ELF guest code and does **not** prove Wine/Windows PE on Android. The code lives in `native-engine/android-host/kernix_guest_elf64_dynamic_audit.h` and has a dedicated negative-test fixture. Next proof must connect the safely resolved guest files to FEX guest execution without using Android system-loader shortcuts; after that import/symbol resolution and real Wine9 startup need their own tests.

## G2-B transitive dynamic ELF dependency chain

Native x86_64 CI now exercises a *real* three-object linked dependency chain, recursively resolving guest PT_INTERP and DT_NEEDED inside a private root-FD tree. Nested missing/corrupted/symlink-escaped libraries are rejected. Unlike first-level checks, this validates that immediate dependencies' own ELF DT_NEEDED names are accessible as files too. It does not resolve GNU symbol versions, relocations, RUNPATH, runtime dlopen, glibc syscalls or Wine processes. The on-device G2-B executable gate remains CLOSED until real Android FEX Linux guest execution is observed.

## G2-B bounded PT_LOAD staging gate

Read-only anonymous memory images of actual x86_64 ELF PT_LOAD segments (executable, glibc libc, dynamic interpreter) are now audited with 4K/16K page constraints, segment overlap/file bounds, W^X and no-host-PROT_EXEC enforcement. Host unit tests verify exact bytes, BSS zero and malicious W|X rejection. The same source cross-links with NDK/Bionic ARM64 as a **build-only, not packaged** shared library. It is NOT a Linux guest loader: no FEX guest virtual memory, relocations, Linux initial stack/AUXV or Wine/PE execution is claimed. G2-B Android execution remains blocked until actual device evidence.

## G2-B bounded Linux process initial stack is build-only

A host-only x86_64 `argc/argv/envp/AUXV` constructor now validates guest stack canonical addresses, 16-byte alignment, explicit caller-owned AT_RANDOM, AT_BASE/AT_ENTRY/AT_PHDR and real ELF header metadata. CI checks exact generated byte layout against a real Linux x86_64 dynamic PIE and negative overflow/path cases. A separate Android NDK/Bionic compilation is build-only; the stack is not installed in FEX virtual memory and no glibc interpreter or Windows executable is run. G2-B Android runtime remains an independent blocked gate.

## G2-B guest virtual address and AUXV consistency preflight

A new read-only launch-layout unit composes real x86_64 dynamic ELF metadata, prior rootfs-safe dependency closure, main and interpreter PT_LOAD views, guest load biases, file-backed PT_PHDR/entry checks, nonoverlapping region plans, and actual argv/envp/AUXV stack bytes. All nonzero addresses derive from supplied bounded fixture guest regions and the original ELF header, not arbitrary code-generated constants. CI must reject colliding loader/stack, missing transitive libraries and bogus canonical guest addresses. Neither the host-only Linux CI nor the separate Android/Bionic crosslink executes FEX guest code; first dynamic guest ELF on the phone remains an unmet release gate.

## G2-B host-controlled no-access kernel VA reservation gate

The integrated dynamic-ELF launch plan now has a separate optional RAII proof of actual host VA availability: `mmap(nullptr, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS)` returns three kernel-selected, guard-bounded windows for main x86 ELF, interpreter and stack, with guest layout rebased to those exact windows, no MAP_FIXED or host executable pages. Linux native tests inspect `/proc/self/maps` for `---p`, enforce disjointness, reject missing transitive files and release all three mappings deterministically. Android NDK compilation exists only as an unbundled CI artifact. It is NOT a FEX-owned guest address-space reserve, actual PT_LOAD memory installation, or dynamic ELF execution, so Android real-execution gate remains CLOSED.

## G2-B guarded host readonly image staging regression gate (2026-11-04)

Real read-only host windows for main x86_64 ELF, ld-linux and initial stack are staged **only within previously kernel-selected, guard-bounded host mappings**, with a transient writable step followed by final `PROT_READ`. CI asserts actual `/proc/self/maps` guard and no-execute permissions and compares all in-memory bytes to source ELF and prepared AUXV. This is NOT FEX-owned guest memory and must never be reported as Linux glibc/Wine execution. Android component is build-only; no on-device execution claim. Future gate is FEX memory ownership and real x86 guest dynamic-ELF execution in bounded child after correct thread-context and syscall/loader integration.

## G2-C original FEX ARM64 dynamic PIE direct-entry JIT proof (separate CI gate)

A new source-pinned Ubuntu ARM64 integration workflow now goes beyond static metadata: it uses original FEXCore on a genuine x86_64 dynamically linked PIE and the guard-bounded G2-B guest image/auxiliary stack bytes to attempt **actual execution of that executable's own `_start`**. The guest has a real Linux PT_INTERP and DT_NEEDED libc.so.6 and validates its argv/envp/AUXV from inside x86 machine code, then returns an exact marker via HLT. It **intentionally does not enter ld-linux or call glibc**; all guest syscalls are rejected. A pass is possible only after real FEX JIT execution with exact x86 register marker/exit. Ubuntu ARM64 CI is not on-device Android. Until a CI success is observed the gate status is **PENDING/UNPROVEN**; until independent signed Android device logs exist, mobile dynamic ELF execution remains UNPROVEN. The exact files are `native-engine/android-guest/kernix_g2c_dynamic_pie_direct_entry_witness.S`, `native-engine/android-host/kernix_g2c_fex_dynamic_pie_direct_entry_probe.cpp`, and `native-engine/ci/kernix_g2c_native_arm64_real_fex.sh`.

## G2-C real FEX x86-64 ELF entry on Linux ARM64: PASSED with strict boundary

[Successful original pinned FEX native ARM64 run 41787757643](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41787757643) proves actual x86_64 guest `_start` JIT translation and checks live Linux ABI stack/AUXV and exact HLT RAX marker 0x4b45524e49584732, with real x86 dynamic PIE PT_INTERP and libc DT_NEEDED file metadata. The guest linker is NOT entered; ABI proof uses no syscalls. App-owned guarded host windows use safe kernel-chosen nonfixed low canonical mmap hints on ARM64; zero-size PT_LOAD entries are ignored without losing W^X protection. Linux process exit 0 plus exact marker from real JIT is required for PASS. This is not an Android runtime, Windows PE, Wine, or game test. See machine-readable `native-engine/evidence/linux-arm64-fex-g2c-real-dynamic-pie-direct-entry-pass.json`.

## Android G2-D fixed x86 imported DSO device-observed PASS (2026-11-04)

- On a REDMAGIC 11 Pro, user screenshot of signed **KERNIX v0.24** displayed the exact Java-verified marker `KERNIX_G2D_ANDROID_FEX_EXTERNAL_DSO_CALL_RET_VERIFIED_EXACT_RAX` after `KERNIX_G2D_MIT_IMPORT_APP_PRIVATE_ALREADY_ATTESTED_NO_GUEST_EXEC`. This is **one device-observed bounded original-FEX x86 external DSO CALL/RET test**, not broad runtime compatibility. Do not publish the source screenshot.
- The v0.23 failure `KERNIX_G2C_ANDROID_CHILD_REJECTED_EXIT_OR_MARKER` was traced to a concrete Java/native positional-argument mismatch: Java passed `FLAG, appFilesDir` but native required `appFilesDir, FLAG`; the source was repaired in commit `131d07cb8d13dd5673751bc0cb0c531acdfc91e8`, with a fail-closed build-order guard. The signed v0.24 CI run [41840371882](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41840371882) succeeded.
- Machine-readable, narrowly scoped screenshot-derived source record: `native-engine/evidence/android-g2d-v024-cross-dso-callret-device-pass.json`. Raw child stderr/registers and independent repeatability are NOT separately collected. No diagnosis of general Android/Linux ELF failure can be inferred from this success.
- **Next independent gate (G2-E):** build a minimal real, dynamically linked Linux x86_64 ELF whose genuine guest PT_INTERP/DT_NEEDED chain, symbol relocations and guest Linux ABI startup execute through original FEXCore on Linux ARM64 first, then separately on Android/Bionic under app-private/permission boundaries. Validate actual interpreter entry, syscall arguments, bounded logs, loader failure category, and negative tests. Do **not** count manual single-JUMP_SLOT binding, metadata inspection, arbitrary native-host glibc loading, or a synthetic marker as proof of running a real guest dynamic loader. Keep the working signed v0.24, prior v0.22, user data and other branches untouched.
- Windows PE on Android and Wine remain **BLOCKED / NOT DEVICE-VERIFIED** until guest dynamic-loader and ABI gates pass. No game or DXVK/VKD3D execution is established.

## G2-E real guest Linux dynamic interpreter + glibc reference (2026-11-04)

- [Original FEX Linux ARM64 run 41842294261](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41842294261) **completed successfully** with a genuine compiled x86-64 dynamic Linux PIE and pinned original upstream FEX ARM64 ELF. This is the first separately gated **actual x86 guest dynamic loader and glibc imported-function proof** in the independent G2-E workstream, not a repeat of the manual MIT JUMP_SLOT G2-D proof.
- Direct invocation of the genuine guest `/lib64/ld-linux-x86-64.so.2 --list /bin/kernix-g2e-dynamic-guest` under FEX returned exit **0** and resolved `libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6`. Actual guest execution through FEX returned exit **0**, printing exactly `KERNIX_G2E_REAL_GLIBC_IMPORTED_PUTS_EXECUTED` through an imported glibc `puts`. ELF readelf checks require PT_INTERP, DT_NEEDED, GNU x86 JUMP_SLOT, versioned undefined puts and x86-64 ABI.
- Fail-closed negative control: temporarily remove guest libc, repeat the **same** FEX app test, observe exit **127** with `libc.so.6: cannot open shared object file`. No marker or host libc fallback. The real guest and loader are Ubuntu x86_64 cross-sysroot package files with per-file hashes and package versions stored in run evidence.
- Full source-traced evidence is in `native-engine/evidence/linux-arm64-fex-g2e-real-ldso-glibc-pass.json`, CI evidence artifact `13329782010`. This proves **Linux ARM64 FEX process emulation** only; it does not prove the independent Android app's embedded FEXCore can execute a Linux guest interpreter, nor Android glibc, Wine/Proton, PE or games.
- **Next gated action, not yet passed:** bridge Android/Bionic FEXCore guest context to the app-private real dynamic ELF rootfs and guest syscalls, with strict per-file manifest/size/hash, legitimate guest interpreter entry, bounded child trace and one precise on-device approval test only after signed packaging. Do not transplant Ubuntu host libraries to /system or overwrite stable v0.24. Linux x86_64 original FEX launcher success cannot be substituted for the Android FEXCore execution gate.

## G2-E/A pinned real glibc Android Bionic data preflight: CI PASSED (2026-11-04)

- The Linux ARM64 original-FEX **G2-E** interpreter/real glibc execution reference remains [41842294261](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41842294261); no Android execution is inferred from it.
- A separate `G2-E/A` data-only boundary now admits precisely the three guest x86-64 files reproduced byte-identically from the successful Linux CI: the 15,976-byte x86 dynamic PIE, 235,408-byte ld-linux and 2,118,168-byte libc. Hashes are locked in `native-engine/android-host/kernix_g2e_pinned_glibc_preflight.h`. No silent system package repinning.
- The app-owned rootfd reader refuses all intermediate/final symlinks, verifies UID, read-only permissions, size and SHA-256, independently rehashes an anonymous RO copy, and resolves dependencies only from those immutable copies. Linux native tests explicitly reject changed ELF machine ID, missing libc, symlinked libc, symlinked interpreter directory, unlisted files and host path escapes. Crucially **genuine libc itself DT_NEEDEDs ld-linux**, so the real dependency graph contains **two edges**, not one. This caused the initial test rejection and was fixed rather than bypassed.
- The [two-job G2-E/A CI run 41844109160](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41844109160) **PASSED**: original Linux ARM64 source-byte reproduction and negative tests; then genuine Google Android NDK **Bionic AArch64 source compilation**. Bionic output SHA-256 `71e5b355454c76ed93f128172f5a423e75ad334ef8b34b50676992ca6d34f846` exports only a **read-only data verification boundary** and links Android libc/libm/libdl, NOT FEXCore, Wine or glibc as a host dependency. Bounded CI artifacts `13330980355` and `13329199840` include result and binary-linkage audit. See `native-engine/evidence/android-g2e-a-source-pinned-glibc-preflight-build-only-pass.json`.
- **Hard gate:** this output is **build-only, not inside a signed APK**, has **not executed on an Android device**, and **does not start the Linux x86 dynamic interpreter under the embedded FEXCore**. Original guest library provenance and redistribution license packaging must be reviewed before any app payload; never load x86 glibc into Bionic using Android dlopen.
- **Next distinct milestone:** bounded signed app-private data-only verification on device with exact license/source manifests, then a separate integrated FEX guest-address-space + Linux syscall ABI + genuine guest PT_INTERP run gate. Do not overwrite signed KERNIX v0.24 or claim Wine/Windows/game support until a real Android child runs the guest interpreter and records actual executable output.
