# KERNIX — game-specific component compatibility strategy

2026-11-07 — User-requested long-term architecture rule. This is a design/release criterion, **not** evidence of implemented runtime selection, availability of any particular game profile, or proof that every Windows game works.

**Clarified preference:** This project's first-choice solution for a game that needs different component behavior is **a source-level, targeted compatibility correction on a modern supported baseline**, *not* relying on an old component version. See [modern-component-first targeted patch policy](MODERN_COMPONENT_TARGETED_COMPATIBILITY_PATCH_POLICY.md). Older builds are A/B reference evidence or a voluntary temporary fallback only.

## Adopted universal rule: assess EVERY added game, including already playable titles

**Product decision (2026-11-07, confirmed by user):** The game compatibility/optimization pipeline is **on by default for every supported Windows PC game added to KERNIX**, not just games that crash, black-screen or refuse to launch. A previously working game is still eligible for a safer modern component pairing, better image quality, improved 1%-low frame pacing and less thermal instability. The user selects one game folder; the same pipeline prepares an isolated evidence-backed profile for every game build.

- **Always identify first:** read-only scan of the selected executable and known launch dependencies; exact SHA-256, PE architecture, version, storefront/launcher prerequisites and static D3D/graphics indicators; keep uncertainty if API/runtime imports are dynamic. Platform detection is mandatory: PS4 SELF/PKG must not be fed to the Windows PE/Wine backend.
- **Always resolve a safe starting profile:** choose one validated, recent, device-compatible component bank combination and keep a pinned rollbackable per-game lock. Before real runtime qualification, the profile must remain disabled and cannot be presented as a verified optimal combination. No unverified driver, CPU feature spoofing, DRM bypass or system-wide DLL replacement.
- **Already-working games get the SAME assessment:** collect first-frame, successful menu/input, rendering and crash-free-session metrics; investigate whether a modern driver, shader path, CPU configuration, graphics setting or component pairing measurably improves quality/stability. Do not classify a game as "complete" merely because it launches.
- **Optimize only against controlled measurements:** compare baseline and candidates on the **same device, same game executable/build, same scene/save, same resolution/preset, controlled temperature and comparable session duration**. Record median FPS, 1%-low/frametime distribution, stutters, first-frame time, sustained throttling, memory pressure, GPU/CPU errors, image quality/artifacts and battery/thermal risk. A higher peak FPS with worse 1%-low or graphical corruption is a regression, not an improvement.
- **Quality/stability objective:** retain correct rendering and input as hard requirements; prioritize sustained stable pacing and absence of crashes/visual glitches; when measured headroom exists, offer a higher-resolution/effects option without losing the user's configured minimum acceptable frame stability. The default policy should avoid silently raising settings if the game then stutters or the device overheats.
- **Bounded candidate search, no blanket experiments:** first use known validated profiles and real capability queries; change a single implicated component/setting per A/B step, cap runs and resource exposure, stop on crashes/thermal triggers, and roll back automatically to the previous known-good profile. Do not start long-running game benchmarks without the user opting in to the test session.
- **Learn per build, not falsely per title:** store measured positive and negative compatibility records keyed to executable SHA + device GPU/OS/driver + component versions + render preset. Reuse findings as suggestions for similar hardware but revalidate changed game builds, drivers or device firmware. Safe read-only analysis is universal; a single executable-specific binary patch is NEVER universal.
- **Never promise globally optimal settings:** static inspection cannot infer all requirements, and component/quality tradeoffs can be Pareto-incomparable (higher visual quality vs lower latency vs temperature). The resolver must expose objective and evidence confidence; when unknown, show a conservative baseline, an explicit `unverified` label and the precise missing evidence.
- **Implementation sequence:** universal static analysis and SHA-locked identity binding are initial, OFFLINE-only building blocks. Live component selection, performance tuning, runtime patches and automatic optimization need completed G0 Linux guest loader, G2 Windows runtime, G1 physical WSI results and real per-game device benchmarks. This document records the product contract, **not** a claim that the automatic optimization engine already works.

**Default user experience:** Add folder once → identity/version and backend check → select vetted base profile → launch and observe real behavior → when opted in, compare controlled candidates → choose a qualified quality/stability profile → store an exact per-game reproducible lock/rollback. The same sequence begins for a game that already worked in another emulator.

## Principle: one reliable core, many validated game profiles

- Maintain ONE source-verified, W^X-correct, ABI-correct core runtime: Android/Bionic host, guest Linux syscall/memory model, FEX CPU translator, wine/proton Windows runtime interface, Vulkan presentation, input and storage.
- Maintain an IMMUTABLE versioned COMPONENT BANK: selectable tested FEX/translation binaries, Wine and Proton builds, DXVK for D3D9/10/11, VKD3D-Proton for D3D12, DXGI compatibility layer, Turnip/Vulkan ICD releases, per-game runtimes/DLL dependencies, launch settings and workarounds. A **newer** version is not automatically regression-free, but the long-term target is to correct its identified incompatibility. Retain older verified versions for controlled differential comparison and optional rollback, not as the product's primary game solution.
- Resolve exactly ONE validated lockfile/profile at launch for each precise game build; profile changes do not replace the globally installed core, overwrite an unrelated game's DLLs, contaminate other prefixes or silently move another title to a different driver.
- Detect executable architecture, imports, local manifest, renderer and known dependency hints, but static detection is only a suggestion. The user may override per-game settings; never claim the engine can infer all requirements without runtime tests.
- If no available compatible combination exists, produce a precise missing-component/feature diagnosis and investigate or independently build a licensed, source-pinned new version/patch. Do **not** insert an unverified binary or lie about GPU/CPU/VRAM capabilities.

## Per-game profile fields (future implemented manifest requirements)

| Group | Required provenance and selection |
| --- | --- |
| Game identity | Title, edition, storefront, build/version, executable SHA-256, PE architecture, renderer/API (when verified), launcher/entitlement path |
| Translation | Source-pinned FEX version, CPU feature mask consistent with implemented instruction set and Wine-visible CPUID, JIT cache and TSO policy, known-safe memory behavior |
| Windows runtime | Wine or Proton precise version, architecture/WoW64, DLL override manifest, registry/per-game environment, runtime dependencies (VC++, .NET, media only if legally and technically available), prefix version and rollback |
| DirectX path | D3D9–11: DXVK; D3D12: VKD3D-Proton; explicit DXGI and d3d12/dxvk dependency consistency; selected component build SHA-256 |
| Vulkan driver | Turnip or appropriate Vulkan ICD exact device-specific version, real supported features/extensions, selected shader/compiler switches, graphics presentation, pipeline-cache provenance |
| Resource contract | Guest RAM and virtual memory reporting, device shared-memory GPU budget/VRAM reporting, CPU topology/feature assertions, Android 4K/16K host memory page constraints, thermal/memory pressure |
| Observability | First failing subsystem, earliest error code/HRESULT/VkResult/signal, CPU feature query, Win32 memory queries, Vulkan feature negotiation, logs, actual first frame and frame-time trace |
| Validation | User/device model, Android build, exact installed components, known-good runs, known-bad variants, session duration, performance with method, SHA-locked regression outcome, rollback identifier |

## Community video/reports — use as evidence leads, not verified recipes

- When a user reports YouTube/social demonstrations (e.g. The Last of Us or another demanding D3D12 game at 40–60 FPS), record the URL, upload date, precise title/edition/build, device SoC/GPU/RAM, operating system, emulator fork/version, any described driver/Wine/FEX/VKD3D configuration, video capture technique and settings if actually visible.
- Classify: **Observed demonstration**, **publicly documented full reproducible settings**, **reproduced in controlled reference**, **reproduced on user's REDMAGIC 11 Pro**. Do not silently promote one category into another; a displayed frame-rate overlay is not a stable frame-time measurement.
- Search upstream source, official issue trackers, public developer discussions and lawful release assets for the cause and known safe revisions. Compare the same game build and original failure signature in two controlled configs; change **one relevant layer at a time** to isolate causality. Do not assert what a video creator configured if it is unpublished.
- Record both old versions that work and newer versions that regress. Use the older working versions to find the changed function/driver requirement, then patch or correctly integrate the **modern** version. Keep "negative" profiles to avoid repeating known failing combinations.

## Focused implementation and test order (after G0–G2 core proof)

1. Component bank installs original/upstream-source-verified binaries atomically with SHA, ABI, dependencies, licenses, namespace/isolation and version rollback.
2. Game investigator emits an initial *proposal*, never a guaranteed choice; runtime resolver validates all component interfaces and produces a per-game immutable launch lock before running any executable.
3. Independent CPU/Win32 memory/D3D feature probes run under that same lock, not a synthetic alternate runtime. Fail with a specific unsupported-feature reason instead of falsely advertising AVX, VRAM or Vulkan capabilities.
4. Evidence-backed compatibility search selects a modern, validated baseline; on failure, use older working builds only as A/B controls, isolate the regression or cross-component mismatch and implement a narrow, source-reviewed modern component patch or integration fix. Keep a game-specific patch switch and rollback; preserve saves and allow expert per-game overrides.
5. First real rendered frame, menu, input, play session, repeatability, memory pressure and thermals are separate gates. A launch video, successful build or solid color is never a gaming compatibility PASS.

## Target cases from user's experience

- The Last of Us Part I / Part II: prior failing user observations; prioritize CPU/Windows-memory and actual D3D12 feature/VRAM-budget traces, but **do not** assume those layers are the cause without captured diagnostics. Community play demonstrations are useful leads even when settings were not published.
- Other heavy or ambiguously named titles: retain the user's exact wording until the game title and edition are verified, then capture the executable/build; avoid attributing a failure to the wrong game.
- Controlled known-working lightweight title such as Hollow Knight: baseline FEX/Wine/PE/input control, not proof of DX12.
- Separate unsupported external platform dependencies (kernel anti-cheat/DRM/online activation) from CPU translation, DXGI, drivers and resource-pressure faults; never bypass those dependencies or promise the same outcomes across all devices.

## Non-negotiable safety and project status

- Compatible components do not guarantee that every demanding title can run on any specific Android GPU/SoC; feature gaps, memory pressure and proprietary services are possible external constraints. **Work toward broader compatibility with evidence rather than calling observed demonstrations impossible or universally reproducible.**
- The source-pinned original GNU ld-linux / libc memory and relocation project must finish its current acceptance gates before upgrading the graphics stack. This file changes design requirements only: it does not claim that FEX+Wine+VKD3D+Turnip are all installed together in a release APK.
- Preserve stable build, the user's installed games, prefixes and save data; no auto-deletion, global component replacement or mixing unverified binaries. Release gates in [COMPATIBILITY_RESEARCH_AND_RELEASE_GATES.md](COMPATIBILITY_RESEARCH_AND_RELEASE_GATES.md) and [CPU_MEMORY_DX12_FIDELITY_ACCEPTANCE_CONTRACT.md](CPU_MEMORY_DX12_FIDELITY_ACCEPTANCE_CONTRACT.md) remain mandatory.
