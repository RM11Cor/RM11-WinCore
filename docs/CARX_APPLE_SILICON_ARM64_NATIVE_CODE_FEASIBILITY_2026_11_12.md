# CarX Street PC — Apple Silicon architecture feasibility gate, 2026-11-12

## Verified public sources, NOT original Mac binary execution

1. CarX announced the official Apple Silicon macOS version on September 9, 2025. Its separate Easy Anti-Cheat launcher may require Rosetta; do not use that launcher to infer architecture of original game code. https://steamdb.info/patchnotes/19910222/
2. SteamDB's CarX Street app 1114150 has a Windows depot 1114151, Linux depot 1114152, and macOS depot 1114153. Public build 26481722 was dated November 6, 2026. https://steamdb.info/app/1114150/depots/
3. Published macOS depot inventory lists the following user-owned-file candidates:
   - CarX Street.app/Contents/Frameworks/GameAssembly.dylib (about 358.50 MiB)
   - CarX Street.app/Contents/Frameworks/UnityPlayer.dylib (about 60.22 MiB)
   - CarX Street.app/Contents/MacOS/CarX Street (about 113.36 KiB)
   - NativeCarX.bundle plugin; macOS Steam/EOS SDK dylibs; FMOD.
   - macOS Unity data and Addressables under StreamingAssets/aa/StandaloneOSX/
   - https://steamdb.info/depot/1114153/
4. SteamDB warns that the *visible file manifest* is out-of-date; its listed file names/sizes are public reference evidence, NOT actual original file header/architecture proof.
5. An official Apple Silicon announcement alone does not identify the CPU slices of GameAssembly and UnityPlayer. Both must be tested independently.

## Native Android executability, without pretending the code is directly portable

- The user's Windows CarX GameAssembly.dll is PE/x86-64, and the game has Windows64 bundles. It cannot be directly loaded as Android ARM64.
- A potential macOS ARM64 GameAssembly.dylib might contain ARM64 machine code, but macOS Mach-O is NOT Android ELF/Bionic. Its dyld/Darwin ABI, Apple frameworks, macOS native plugins, UnityPlayer and graphics stack are platform-bound.
- Windows64 and macOS StandaloneOSX Unity AssetBundles are not proven loadable on Android. Authorized Android-target resources are required.
- Darling currently describes initial ARM64 support as of November 8, 2026, and evolving GUI/Metal-on-Vulkan work, NOT a proven CarX game runner on Android. It is a macOS compatibility layer; using it would violate the user's strict no-compatibility-runtime native-port requirement:
  https://blog.darlinghq.org/2026/11/08/development-update-q4-2026/
  https://github.com/darlinghq/darling
- Therefore even a confirmed ARM64 Mach-O result is architecture research, NOT a claim that original CarX game code runs inside our Android APK.

## Actual implementation in this project

- tools/carx_macho_architecture_gate.py performs read-only, bounded inspection of exact native code headers of user-owned macOS game files: Mach-O thin/FAT slices, CPU architecture, declared min OS, linked libraries, Apple-framework dependency paths, original GameAssembly+UnityPlayer ARM64 pair status.
- tests/test_carx_macho_architecture_gate.py supplies 15 original synthetic test/negative controls for ARM64, x86-64, FAT headers, incorrect CPU, malformed headers, ELF confusion, only one Mac game binary, missing originals and symlinks.
- GitHub Actions #43190305235 SUCCESS verified all 15 synthetic tests. No original proprietary game files were uploaded or executed by CI, and the gate's initial state is UNVERIFIED for original Mac binaries.
- This is NOT a new playable APK and does not change the working native Android Vulkan v0.6 success.

## Engineering acceptance gate

M0: Actual user-owned macOS GameAssembly.dylib AND UnityPlayer.dylib independently verified as Mach-O ARM64 slices with real library imports. OPEN until original bytes are supplied locally; public manifest cannot close it.
M1: Mac ABI and linked platform service / graphics compatibility comprehensively specified. OPEN.
A0: Legally usable original gameplay source + Android ARM64 IL2CPP build and Android-target asset bundles, or independent clean-room implementation. OPEN.
A1: First original CarX gameplay scene with actual Android game code, physics and controller responding. OPEN.

Until A0 is satisfied, another sample Vulkan frame, source header scan or MacOS shim cannot be described as a finished native CarX PC Android port.
