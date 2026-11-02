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

## Source provenance + native binary gate (2026-11-02)

- `components/upstream-source-lock.json` now pins immutable Git commits from the **original upstream** repositories of FEX, DXVK, and VKD3D-Proton. Repository license identifiers are recorded as metadata; packaging must preserve applicable notices and licenses. Git commit IDs are 40-character SHA-1 identifiers, **not** runtime binary SHA-256 checksums.
- `tools/kernix_native_artifact_gate.py` validates that source pins reference only these known original repositories and do not claim Android binaries have been built. Its separate ELF gate checks a supplied native AArch64 ELF file's basic header, bounded load segments and an expected **64-character SHA-256 digest**.
- The gate deliberately **does not** assert Android/Bionic dynamic linking, GPU/Turnip support, Wine/FEX integration, or on-device compatibility. Synthetic test ELF files are never real runtime payloads.
- `tools/test_kernix_native_artifact_gate.py` exercises correct/incorrect ABI, mismatched SHA-256, invalid headers, symlinks, unpinned source and false build claims.
- **Not yet sourced or packaged:** Wine, Proton and Turnip Android runtime binaries. The runtime registry remains empty and no installable Android APK is produced by this workflow.
- Next gate: an actual reproducible upstream component build, per-file manifest, dependency/ABI linkage inspection and license bundle; then a separate independent Android host proof.

## Verified progress: versioned component payload staging gate

- `tools/kernix_component_payload_gate.py` verifies complete staged component payload manifests with source revision pin, explicit file list, safe relative paths, checksums, file sizes, ELF AArch64 or PE CPU headers, and recorded license notices.
- The gate rejects unexpected files, symlinks, hardlinks, missing or altered license entries, and wrong architecture. PE DLLs are not mistaken for native ARM64 ELF executables.
- `tools/test_kernix_component_payload_gate.py` includes positive synthetic-file and tampering tests.
- GitHub CI run `41480623210` completed successfully.
- **No source-built executable payload, Android app, loader or game launch was demonstrated.** This gate validates an input bundle once one exists; it is not a component builder or installer.

## Independent Android Host Preview APK — compiled

- Standalone Android application source is in `native-engine/android-app`; independent original C host code plus JNI shim in `native-engine/android-host`.
- Verified GitHub Actions run `41483064411` **completed successfully**, with `KERNIX-Host-Preview-APK` artifact ID `13161001210`.
- The APK includes native `libkernix_host.so` and `libkernix_host_jni.so` for `arm64-v8a`; GitHub build checks static ARM64 ELF hashes and both libraries' presence in APK.
- When installed on a real Android phone, the preview displays native ABI / system Vulkan-loader discovery. **No phone test has yet been performed**; successful CI compilation does not prove successful Java/JNI loading, GPU rendering, game launch or device compatibility.
- This small APK is a diagnostic host preview, **not** the KERNIX Windows-game emulator. Its standalone app ID `org.kernix.host` avoids overwriting old apps.

## Verified FEX upstream ARM64 Linux baseline (2026-11-02)

- Official FEX-Emu/FEX commit `02e24ca5c01ed0c864466ed573db347336f70170` was compiled **without source patches** using Clang 18 on the native Ubuntu 24.04 ARM64 runner. Build run `41493275871` passed all steps and uploaded `KERNIX-FEX-native-ARM64-linux-build-audit` (artifact `13165032966`).
- The baseline selects the pinned FEX `External/fmt` submodule rather than incompatible Ubuntu system fmt, disables unrelated x86 NASM unit-test targets and records per-file SHA-256 for produced `.a` / `.so` outputs.
- The audit is **Linux AArch64/glibc provenance**, not an Android/Bionic executable bundle. It does not yet verify every archive member's ELF machine ID, Android dynamic-link compatibility, rootfs setup, Wine integration, Vulkan presentation, or on-device games. No Linux binary is admitted to the Android runtime registry.
- Next gate: validate ELF architecture and dependency linkage for every built FEX payload, preserve upstream licenses, and establish an Android-specific port/runtime boundary before considering an installable component.

## FEX Linux ELF integrity audit hardening (2026-11-02)

- The pinned upstream FEX ARM64 Linux workflow now calls the existing tested `attest_arm64_elf` gate for **each copied real ELF**: AArch64 machine ID, ELF64 header, bounded program headers and PT_LOAD segments, and exact SHA-256 of the staged bytes. This closes the previous gap where the workflow only checked the ELF machine field and computed a digest without validating load-segment bounds.
- `readelf -d` and `readelf -l` are now fail-closed (`check=True`, bounded timeout); an inspection error can no longer silently produce an empty dependency list. The upstream FEX `LICENSE` is included in the Linux ELF evidence artifact; transitive submodule license audit remains required before redistribution as a runtime.
- Two new malformed-ELF regression tests (no PT_LOAD and wrong ELF64 program-header size) passed with the independent foundation checks in run `41505351623`. The separate full FEX source-build / real ELF artifact audit is being validated in run `41505334933`; do not claim its outcome until it finishes.
- **Scope remains Linux AArch64/glibc only**. Static checks and CI are not Android/Bionic linkage, rootfs, FEX-to-Wine integration, APK packaging or game-execution proof. No FEX payload has been admitted into the verified Android component registry.

## Verified upstream Wine 11 Linux x86_64 source-build baseline (2026-11-02)

- GitHub Actions run `41507415519` completed successfully: official `wine-mirror/wine` Wine 11.0 source commit `db11d0fe6a169c457e23d007e20404643d067aa8` compiled with Clang/LLD 19 on Ubuntu 24.04 x86_64. The compiled `loader/wine` reported `wine-11.0` and is an ELF x86-64 Linux executable; its recorded SHA-256 is `237d4a88c2cccf5de732d485ef8d823a460d56770c6ddfd15f62bf02e20f0a53`.
- The Wine toolchain was repaired by pairing `x86_64-w64-mingw32-dlltool` with the corresponding MinGW COFF assembler; this avoids both missing-`dlltool` and host-assembler RVA relocation failures.
- The successful workflow only uploaded its small provenance audit (`KERNIX-Wine-11-source-built-linux-x64-audit-only`); **that is not a runnable Wine runtime archive, FEX integration, or an Android APK**.
- The separate `.github/workflows/kernix-wine-linux-runtime-stage.yml` now attempts an actual `make install DESTDIR` stage of upstream Wine on Linux x86_64, with PE/ELF machine checks, complete file SHA-256 manifest, upstream license and a versioned archive. A completed CI run and artifact inspection are required before this staged runtime can be called verified.
- Even a successful staging run remains **Linux x86_64/glibc only**. FEX on Linux ARM64 must be tested with a suitable x86_64 guest environment; Android ARM64/Bionic and phone game execution are separate, unproven milestones.

## Wine Linux runtime archive integrity and WinMD metadata boundary (2026-11-02)

- The first full Wine 11 Linux staging attempt (run `41510273723`) successfully compiled and installed approximately 639 MB of original Wine, but **failed the staged ABI audit**: `share/wine/winmd/windows.applicationmodel.winmd` is PE-format Windows metadata, not a native x86_64 runtime DLL. The previous checker incorrectly required its PE machine field to be x86_64.
- The staged-file classifier now distinguishes WinMD metadata (i386 machine `0x14c`) **only** under `share/wine/winmd/*.winmd`; all executable Windows PE elsewhere must still be x86_64 (`0x8664`). WinMD metadata is counted separately and is not claimed to be executable.
- Upstream Wine's `LICENSE` is now embedded **inside** the staged Linux runtime tar, not only alongside it in the GitHub artifact. `tools/kernix_wine_stage_archive_gate.py` independently reads the tar **without extraction**, rejects unexpected paths, unsupported member types and symlink changes, checks every regular file against the staged SHA-256 manifest and ELF/PE machine classes, and requires the embedded license.
- Synthetic regression tests include a legitimate WinMD fixture, wrong-ABI and tampering cases, missing license, symlink changes, and false Android-compatibility claims. These tests are included in the independent CI workflow; they are **not** a real Wine/FEX execution test.
- A full rebuild with the WinMD correction and archive-integrity gate must finish successfully before claiming the Linux x86_64 Wine runtime tar is verified. Even then it is **not** Android/Bionic, not a FEX rootfs, and not an APK or proof of game compatibility.
