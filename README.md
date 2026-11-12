# CarX Street PC → Android | Port Lab

**Status: Stage 01: REAL Android APK source-file inspector only. NOT a PC game port or playable build.**

This is a **game-specific, standalone Android APK project** dedicated to **CarX Street PC**, built independently of the KERNIX emulator branch and the separate Forza Horizon 5 effort.

This prototype uses the Android system folder picker, never requests broad storage rights, and scans a user-owned extracted PC installation read-only. It creates a JSON manifest with:
- CarX Street.exe PE header / x86-64 machine detection.
- UnityPlayer.dll and GameAssembly.dll (Windows IL2CPP).
- `CarX Street_Data`, global-metadata.dat, globalgamemanagers, Unity resources and Windows64 asset bundles.
- File counts/sizes, small first-64KiB sample fingerprints, Android hardware ABIs, memory and Vulkan feature flags.
- Easy Anti-Cheat presence (NO bypass).
- No internet permission. No automatic copy of gigabytes of game data. No game binaries shipped.
- Android scoped storage (ACTION_OPEN_DOCUMENT_TREE) and an exportable JSON report.

## Install prototype

GitHub Actions → **CarX Street PC Port Lab - real Android APK source inspector** → latest successful run → artifact:
`CarXStreet-PC-PortLab-v0.1.0-File-Inspector-Only-ARM64-Gate-Open`.
Extract the artifact zip and sideload `app-debug.apk` on Android. Pick the **root folder containing your extracted CarX Street PC game**, run the scan, save report, send only the report.

## Why isn't it immediately playable?

CarX Street PC is a Unity IL2CPP **Windows** build with x86-64 `GameAssembly.dll` and `UnityPlayer.dll`. Android ARM64 cannot execute those Windows DLLs natively. PC `StandaloneWindows64` Unity assets/shaders may not be Android-compatible. A legitimate native port requires authorization to build the original Unity project for Android (the publisher has an official but separate Android edition) OR developing an independent native runtime/source port. A dedicated APK including FEX/Wine could automatically run game files but **would still be CPU translation and a compatibility layer, despite hiding emulator configuration**. We will not misrepresent this as native code.

The app does **not** bypass DRM, Steam or Easy Anti-Cheat, distribute copyrighted game assets, include leaked source, or claim online play.

## Release gates

1. **G1 / PC evidence:** detect exactly which CarX PC build, PE architecture, Unity+IL2CPP and asset catalog exist. Real APK v0.1.0 can do this.
2. **G2 / assets:** platform-compatible Android textures, Unity Addressables and shaders, or legitimately reauthored equivalents, verified by actual load.
3. **G3 / executable:** tested legal native ARM64 Unity game runtime/source-port code. Source visibility/rights must be confirmed; no source means **native G3 is blocked**.
4. **G4 / first frame:** instrument genuine engine load, rendering on Adreno Vulkan and playable driving; APK inspector success is not game success.
5. **G5 / stability:** joystick/touch, audio, save, frame pacing, thermals and 30/60 FPS measurements.

Until G3–G4 are passed, reports must say **not playable**. Every game gets its own APK; no global emulator app setup is required once an actual runtime exists.

Sources: Steam CarX Street PC version FAQ, SteamDB depot 1114151 (`GameAssembly.dll`, `UnityPlayer.dll`, `CarX Street_Data`), UnityDataTools Android vs standalone player format.

## Stage 02 / v0.2.0 — exact Unity headers, not a playable APK

The first phone-side report confirmed **914 files / 23 folders / 22,750,725,816 bytes**, a Windows x86-64 launcher and GameAssembly.dll, UnityPlayer.dll, global-metadata.dat, globalgamemanagers, Windows64 Addressables bundles and Easy Anti-Cheat. This is a file-identity scan, NOT executable ARM64 Unity code or gameplay.

The v0.2 header audit reads **at most 64 bytes** of original IL2CPP global-metadata.dat and validates its classic little-endian magic and version. It reads **up to 12 × 512 bytes** of Windows64 bundle headers and reports UnityFS / UnityWeb signature, bundle header format and **bundle-produced** Unity version/revision strings, **not** a definitive Unity Player version. It samples just the first 16 KiB of catalog.json for syntax hints (not complete dependencies) and records boot.config key names only. It also counts Windows64 bundles.

All reads use the user-approved Android document provider and remain on device. There are no full game-file hashes, raw assets, extractors, internet permissions, game runtime, native ARM64 game port, EAC bypass, or hidden emulator in this inspector. Valid metadata and UnityFS headers **cannot** recompile Windows x86-64 IL2CPP code, reconstruct the game's Unity source, or convert Windows platform shaders/textures into Android game content.

**Independent test:** Java 17 vectors for header recognition and corrupt inputs are run before APK build. Android Gradle debug APK is then built, fingerprinted and published in a separate inspector-only release. The Android debug signing certificate may differ between build runners: if Android refuses an in-place update due to certificate mismatch, uninstall the prior inspector (keep exported JSON first).

**Next gate after v0.2 report:** Compare original Unity bundle and IL2CPP metadata versions with a legally obtained native Android ARM64 game code/runtime. Native-game G3 remains BLOCKED without authorized source/rebuild path or independently implemented executable. Windows64 assets are NOT validated as Android-compatible until a real runtime loads them.
