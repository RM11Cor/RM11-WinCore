# KERNIX native engine — architecture decision v1

This is the new **independent** KERNIX product direction, not a reskinned Bannerlator application.

## Immutable boundaries
1. **Component sources and licenses:** build individual Wine/Proton, FEX, DXVK, VKD3D-Proton, Turnip and other required runtimes from their appropriate original source repositories, with source SHA locks, reproducible toolchains and GPL/other license compliance. These are upstream technologies, not assets copied from other emulators.
2. **Android host:** Android UI, game browser, input/XInput/HID, filesystem permissions, protected lifecycle, Vulkan presentation and native ABI bootstrap must be implemented and verified for Android ARM64. Hardware and graphics support are still fundamental.
3. **Component manager:** immutable component build ID + source revision + ELF/PE architecture + SHA256 + verified dependencies; install atomically and retain previous versions. Unknown or mismatched binaries cannot be enabled.
4. **Runtime assembler:** resolve valid Windows runtime + x86 translator + DirectX wrapper + Vulkan/Turnip driver, then build an isolated per-game launch environment. Never select random versions by number alone.
5. **Static game investigator:** PE headers, import tables, bounded local engine markers, optional metadata. Static findings are *hints* only; dynamic LoadLibrary, hidden engine names, anti-cheat and launchers may defeat inference.
6. **Game profiles:** source-addressed saved configuration and revertible tests, distinct from shared component installation. Runtime validation and FPS come from actual game/frame evidence, not synthetic probes.
7. **Safety and staged rollout:** keep current KERNIX, old RM11 archive and integrated Bannerlator experimental branch untouched; do not migrate or delete user prefixes.

## First actual implementation
- `tools/kernix_native_planner.py`: standalone game-requirements planner consumes previously existing PE import and header readers.
- `tools/test_kernix_native_planner.py`: tests DX11/DX12/DXGI ambiguity, engine marker and fail-closed safety.
- `.github/workflows/kernix-native-engine-v1.yml`: executes tests on this branch and **does not package or clone** Bannerlator.
- `components/registry.json`: currently empty for verified, executable runtime bundles. We will not claim that GitHub release metadata constitutes a working Android runtime.

## Next real integration gates
- Build verified ARM64 Android/Bionic native launcher and Vulkan presentation skeleton independently; capture its real output, input and lifecycle.
- Build and package individual upstream components with explicit dependencies, ABI and hashes; implement transactional versioned resolver.
- Wire per-game proposals into a dedicated Android KERNIX UI, with user-controlled overrides and run history.
- Compile, install and test a real APK. The current Python checks **are not an APK build or gameplay proof**.
- Preserve licenses and disclose upstream source authors. No promise of running every PC game.

**Project rule:** do not label an upstream Bannerlator clone as finished KERNIX. The independent engine must pass its own Android build and on-device session tests before distribution.

## Verified progress: independent runtime lock compiler
- `tools/kernix_runtime_resolver.py` creates a deterministic per-game lock for **only verified** component IDs, requiring FEX, one Windows runtime, and the Vulkan driver.
- It rejects missing dependency closure, mismatched component kinds, unsupported x86_64 host packages, missing D3D wrappers, and missing/unverified payload entries.
- Immutable SHA256-based run plan changes when a selected component version changes; no "latest wins" policy.
- `tools/test_kernix_runtime_resolver.py` runs in dedicated CI. CI run 41479047982 succeeded.
- This is still the **plan/compiler layer**, not a binary package manager or Android launch implementation. `components/registry.json` remains empty intentionally until real component binaries are built and validated.
