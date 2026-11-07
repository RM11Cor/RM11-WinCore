# KERNIX — game-specific component compatibility strategy

2026-11-07 — User-requested long-term architecture rule. This is a design/release criterion, **not** evidence of implemented runtime selection, availability of any particular game profile, or proof that every Windows game works.

## Principle: one reliable core, many validated game profiles

- Maintain ONE source-verified, W^X-correct, ABI-correct core runtime: Android/Bionic host, guest Linux syscall/memory model, FEX CPU translator, wine/proton Windows runtime interface, Vulkan presentation, input and storage.
- Maintain an IMMUTABLE versioned COMPONENT BANK: selectable tested FEX/translation binaries, Wine and Proton builds, DXVK for D3D9/10/11, VKD3D-Proton for D3D12, DXGI compatibility layer, Turnip/Vulkan ICD releases, per-game runtimes/DLL dependencies, launch settings and workarounds. A **newer** version is NOT automatically better; retain an older verified combination when required and compatible.
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
- Record both old versions that work and newer versions that regress. Keep "negative" profiles to avoid repeating known failing combinations.

## Focused implementation and test order (after G0–G2 core proof)

1. Component bank installs original/upstream-source-verified binaries atomically with SHA, ABI, dependencies, licenses, namespace/isolation and version rollback.
2. Game investigator emits an initial *proposal*, never a guaranteed choice; runtime resolver validates all component interfaces and produces a per-game immutable launch lock before running any executable.
3. Independent CPU/Win32 memory/D3D feature probes run under that same lock, not a synthetic alternate runtime. Fail with a specific unsupported-feature reason instead of falsely advertising AVX, VRAM or Vulkan capabilities.
4. Evidence-backed compatibility search selects a known-good preset; on failure compare the first error and try only compatible, authorized variant(s) with a tracked hypothesis. Preserve saves and previous working setup; allow per-game manual version controls.
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
