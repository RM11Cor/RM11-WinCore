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

## Wine archive audit PE-classification correction (2026-11-02)

- The independent integration suite was green in run `41511804974`, but the subsequent **real** Wine Linux staging run `41511805058` failed after successfully compiling/installing and manifesting 2,636 entries (35 Linux x86_64 ELF, 757 Windows x86_64 PE, 10 WinMD). The failure was in archive verification: `ValueError: INVALID_PE_SIGNATURE` at `tools/kernix_wine_stage_archive_gate.py`. This does **not** indicate a compiler failure.
- The staging manifest classifier reads the PE header at the file's `e_lfanew` offset and treats `MZ`-prefixed non-PE data as data. The independent archive verifier previously examined only the first 4 KiB and rejected all `MZ` data lacking a PE signature. This mismatch could reject a valid archive; the log alone did not identify which file caused it.
- The verifier now buffers at most the first 1 MiB of each streamed archive member (while hashing the complete member), accepts non-PE `MZ` data **only when its manifest class is data**, and still rejects wrong PE machine IDs, changed bytes and PE-to-data relabeling. Tests include a PE header at byte 8192 and an `MZ`-prefixed non-PE file.
- Independent integration checks passed on the corrected source and regression tests in run `41522381213`. Real Wine archive staging run `41522375842` must independently pass before its archive can be called verified. The archive is still **Linux x86_64/glibc**, not Android/Bionic, FEX-integrated or game-tested. Upstream Wine license remains embedded in the staged payload.

## Verified source-built Wine 11 Linux x64 runtime artifact (2026-11-03)

- The previously pending **real** upstream Wine 11.0 stage run [41522375842](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41522375842) completed successfully on the pinned source commit `db11d0fe6a169c457e23d007e20404643d067aa8`. Its published GitHub artifact ID is `13178952323`, named `KERNIX-Wine-11-real-Linux-x64-runtime-NOT-Android`, with outer GitHub artifact ZIP digest `898f539cc9ac1c1d77cbf7f177238f2e3413be24da8ae636a6d7ade3993c5bc2` (SHA-256). The embedded Wine runtime tar SHA-256 reported by CI is `849a53d855fe2be2568f1369f0edce904733ed0888853a9404ba4d938a9213d8`. These are distinct archives and must not be interchanged.
- The successful job installed upstream Wine into an isolated prefix, recorded **2,636 manifest entries** (35 x86_64 Linux ELF, 757 x86_64 Windows PE, 10 WinMD metadata), and independently re-read the tar to verify every regular file SHA-256 and embedded upstream Wine license. The verified total of regular-file bytes was 669,932,496. The archive is **Linux x86_64/glibc**, not an Android ARM64/Bionic package and not a tested FEX guest runtime.
- The independent integration checks also passed in run `41522602881`. Neither result proves a Windows EXE runs under FEX, game compatibility, phone performance, or APK packaging.
- The Wine archive audit has since gained a fail-closed lexical symlink check: even if the manifest and tar agree on a target, absolute links and links escaping the Wine installation prefix are rejected. Synthetic regression tests cover both attacks and legitimate relative links inside the prefix. Synthetic regression checks for the stronger symlink policy **passed** in independent integration run [41528281034](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41528281034) (13 Wine archive gate tests, including three new link-policy cases). **Real Wine source-build/staging revalidation is still running in [41528260008](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41528260008); do not claim the hardened real archive passes until that run completes.**
- Next gates: revalidate the real Wine archive with the stronger symlink check; capture required Linux shared-library dependencies and rootfs requirements; test the original Linux ARM64 FEX binary with an appropriate x86_64 Linux guest environment. Only then investigate Android/Bionic host integration. Preserve Wine's upstream license in every redistributed package and keep the Android verified registry empty until actual Android binaries pass their own gates.

## Wine Linux ELF dependency evidence gate (2026-11-03)

- The previously pending hardened **real** Wine 11 source-build/staging run [41528260008](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41528260008) **completed successfully**, including the strengthened archive symlink check. It published Linux-only artifact [13181806835](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41528260008/artifacts/13181806835), with outer GitHub artifact SHA-256 `8f3eea4701fb18e230fb8c49b1b8ea8aec0414ebb3b5381a5c192c04bd4df8a8`. This is not an Android APK.
- Added `tools/kernix_wine_linux_deps.py`: for each **real** staged x86_64 ELF listed in the Wine SHA-256 manifest, it rechecks bytes and ABI, runs fail-closed `readelf -W -d` / `readelf -W -l`, and records `DT_NEEDED`, `RPATH`/`RUNPATH`, and `PT_INTERP` for a future Linux x86_64 guest rootfs/FEX integration plan. It does not infer that external libraries are resolved or runnable.
- Added eight synthetic regression tests covering ELF SHA-256, architecture, symlink safety, dependency parsing, and interpreter parsing. Independent CI [41538714882](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41538714882) passed all eight and the remaining foundation tests.
- The actual source-built Wine workflow now generates `dist/wine-linux-x64-elf-dependencies.json` and includes it with its staged runtime artifact. **The new real dependency-audit stage has not yet passed** at the time of this entry; see [41538732334](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41538732334). Do not treat synthetic tests as proof of a working guest rootfs.
- Next: inspect the real dependency report and supply a pinned, licensed Linux x86_64 guest rootfs for an ARM64 FEX smoke test. FEX-to-Wine execution, Android/Bionic integration and on-device games remain unverified.

## Wine Linux guest rootfs contract compiler (2026-11-03)

- Real source-built Wine 11 Linux x86_64 staging and dependency inspection succeeded in [run 41538732334](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41538732334). The verified GitHub artifact [13185324229](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41538732334/artifacts/13185324229) has outer ZIP SHA-256 0c907b6b9d113a717a6eeb50e498c944ed30ec3ba13fac553377cb9008ed55bb. It is NOT Android.
- The real report audited 35 Linux x86_64 ELF files. DT_NEEDED listed libc.so.6, libgcc_s.so.1, libm.so.6, libresolv.so.2, ntdll.so and win32u.so. The first four SONAMEs were not named in staged Wine files; the latter two were named. The ELF interpreter was /lib64/ld-linux-x86-64.so.2. Filename matching is not library resolution.
- New independent tool tools/kernix_wine_rootfs_plan.py compiles a deterministic SHA-256-addressed static Linux guest rootfs requirement contract, rejecting inconsistent dependencies, unsafe paths, invalid hashes, unpinned source provenance and unsupported success claims. Eight synthetic regression tests exercise those boundaries.
- Independent CI now runs those tests; the real Wine staging workflow now emits a rootfs contract alongside its existing audit. The NEW real build must pass separately before that output is called verified.
- Next: pin a licensed Linux x86_64 guest rootfs, verify its actual ELF ABI, SHA-256, licenses, loader and symbol versions, and run a real Linux ARM64 FEX + Wine smoke test. Android/Bionic integration, game execution and a complete emulator APK are not demonstrated.

## Verified real Wine rootfs contract and static evidence hardening (2026-11-03)

- Previously pending [Wine source-build run 41546882091](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41546882091) **succeeded** on the pinned original Wine 11.0 commit. Artifact [13188893468](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41546882091/artifacts/13188893468) is a **Linux x86_64/glibc Wine archive**, not Android. The GitHub artifact ZIP SHA-256 is `6620b9222b7e7586a2322261b020c2c998d0dbfde012ceb58aca9bc51ac63da3`; the staged Wine tar SHA-256 is `0d0c3a287155856e367e42220b4ebbc84535f913c71e96366951d4a25a308865`. The job verified 2,636 staged entries and embedded upstream Wine licensing. The static guest-rootfs contract records 35 audited ELF files and dependency-report SHA-256 `9990024e1fadecef6e5bd3f994fee2ff627375baf38d1d7a0f004d4972cca603`.
- Hardened `tools/kernix_wine_rootfs_plan.py` to reject malformed/non-string/duplicate external SONAME records deterministically rather than raising incidental type errors. The contract now retains each ELF's non-empty `RPATH`/`RUNPATH` evidence for later guest loader analysis; **this is not resolution or execution**.
- Two regression tests were added. The updated ten-test rootfs-plan suite passed locally on a separate Python copy of the branch files. GitHub CI for the new commits must be checked separately before claiming remote integration success.
- **Unproven:** a pinned and licensed Linux x86_64 guest rootfs, actual ELF loader/symbol resolution, FEX-to-Wine execution on ARM64, Android/Bionic runtime integration, game compatibility, and an integrated emulator APK. The independent Android host preview remains a diagnostic only. Do not admit these Linux binaries to the Android component registry.

## First real FEX to Wine on Linux ARM64 smoke test (2026-11-03)

- Added isolated workflow `.github/workflows/kernix-fex-wine-linux-arm64-smoke.yml` on `ubuntu-24.04-arm`. It downloads exact previously built upstream FEX ARM64 Linux ELF artifact from [run 41505334933](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41505334933) and the verified Wine 11 Linux x64 runtime artifact from [run 41568610374](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41568610374). It independently validates FEX ELF AArch64 identities and SHA-256, Wine tar SHA-256 and the complete existing archive gate; no third-party Android binaries enter the verified registry.
- For a Linux-only smoke it builds a temporary Ubuntu 24.04 `amd64` guest rootfs from the distro's signed package repository using `debootstrap --foreign`, unpacks verified Wine into its isolated `/opt` directory, then attempts `FEX /usr/bin/true` and `FEX /opt/kernix-wine-linux-x64/bin/wine --version` under an ARM64 Linux runner. The rootfs's package versions are **not yet locked**; this is not a reproducible Android rootfs or an Android/Bionic runtime.
- The first actual integration attempt [41575497256](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41575497256) confirmed artifact fetches, byte-for-byte component audits and guest rootfs preparation, then failed **before executing FEX** with exit code 126 (`Permission denied`). GitHub artifact download did not retain POSIX executable mode for `Bin/FEX`. The workflow now restores that mode on the SHA-256-verified ELF without changing its bytes; [run 41575674680](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41575674680) is the follow-up. Do not claim FEX-to-Wine runtime execution unless this later job's real logs pass.
- Even a successful `wine --version` through FEX would prove only a **Linux ARM64 / Linux x86_64 CLI path**. Actual Windows PE execution, Vulkan/Turnip, Android/Bionic, controllers and games remain separate unverified milestones.
