# RM11-WinCore v2.5.4: integration stage 1

**Scope: source integration and read-only runtime audit, not a working Windows-game launcher.**

## Concrete changes

1. Original RM11 Java `RuntimeCatalog` declares two mutually exclusive backends:
   - `BIONIC_ARM64EC_FEX` (Bionic + Wine ARM64EC/WoW64 + FEX DLLs)
   - `GLIBC_BOX64` (Linux/glibc rootfs + Box64 + corresponding Wine build)
2. Adds an actual Wine dosdevices mapping helper (`WineDriveMapper`) creating a new D:–Y: symlink to an already accessible directory; no copied game files and no overwriting an existing drive. This operates only on raw readable filesystem paths, **not** SAF content URIs, encrypted paths, protected Android/data, or file providers. It is not yet wired to a folder-picker UI.
3. Adds read-only ELF64/AArch64 `PT_INTERP` and `DT_NEEDED` inspection. This helps diagnose early WineServer exits but does not prove dynamic linker resolution or process IPC.
4. Adds a read-only audit button to RM11 MainActivity without removing existing controls.
5. Documents and explicitly configures `HODLL64=libarm64ecfex.dll` for x86-64, while retaining the existing `HODLL=libwow64fex.dll` for x86-32 in the current Bionic FEX setup. Hangover documents these as distinct selection points.
6. VersionCode 28 -> 29; `scripts-check.py` synchronized. Original applicationId, ABI filter, SDK, signing configuration and GitHub Secrets **unchanged**.

## Intentionally NOT integrated yet

* Upstream executables, binary libraries, full Wine/Proton distributions, patched PRoot, Turnip, DXVK or VKD3D are **not bundled** by this package.
* Native child re-exec, Android syscall bridge, shared-memory service, WineServer IPC, game EXE execution and graphical output are **not verified**.
* GLIBC and Bionic libraries must not be mixed into one process. The initial profile is a source-level contract, not automatic switching or performance measurement.
* Guest `/etc/machine-id` absence is only logged as a diagnostic, not automatically modified or asserted to cause exit 1.

## Why the first stage is constrained

Android apps targeting API 29+ cannot directly exec binary files from writable private app data. The repository already uses signed native library entry points. New guest Linux executables require a properly implemented loader/process bridge, not just `chmod +x`.

## Upstream technical references (study only; no third-party code redistributed here)

- Winlator `WineUtils` drive mappings: https://github.com/brunodev85/winlator-app/blob/8077f374ef2d54127b088de9e8cd7b4af14d9c8b/app/src/main/java/com/winlator/core/WineUtils.java — LGPL-2.1 for app repo; verify third-party component licences separately.
- GameNative Bionic launcher: https://github.com/utkarshdalal/GameNative/blob/a66f7d8a2536b6e1f39553eab64fe2e29ecc4eb2/app/src/main/java/com/winlator/xenvironment/components/BionicProgramLauncherComponent.java — GPL-3.0; preserve source and notices if copying.
- DroidDeck patched PRoot: https://github.com/Droid-Deck/DroidDeck/blob/3a09e5698beba8b97406ac378ea8007f0f828f87/tools/proot/PATCHES.md — GPL-3.0 repository; patches and upstream licences need audit.
- Hangover emulator selection: https://github.com/AndreRH/hangover — LGPL-2.1 repository; follow submodule licences and ABI requirements.
- Box64: https://github.com/ptitSeb/box64 — MIT.
- Android W^X guidance: https://developer.android.com/privacy-and-security/security-best-practices

## Acceptance gates

1. `python3 tools/apply-integration-v1.py` succeeds on v2.5.3 source.
2. `python3 scripts-check.py` succeeds on the complete repository.
3. `./gradlew testDebugUnitTest` passes for `IntegrationContractTest` and existing tests in GitHub Actions.
4. GitHub Actions builds a signed APK *with the same signing secrets*, and device upgrade is verified.
5. The new audit button reports native ELF loader and dependencies; only after that should implementation of child-reexec and IPC proceed.

The ten Java integration contract tests were run locally with Java 21 and a minimal JUnit-compatible runner and matching RuntimeLayout stub. This **does not** constitute a full Android Gradle / emulator / APK runtime test.
