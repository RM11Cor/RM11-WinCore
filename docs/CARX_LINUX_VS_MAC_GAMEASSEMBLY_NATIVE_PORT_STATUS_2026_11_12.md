# CarX Street native Android port feasibility — Linux versus Mac source binaries

Date 2026-11-12. REDMAGIC NX809J user-provided CarX v0.6 test has real original independent Android ARM64 Vulkan offscreen queue/fence/readback success, but has not executed any original CarX game logic.

## Official cross-platform evidence

CarX Steam App 1114150 includes official Windows depot 1114151, Linux 1114152 and macOS 1114153:
https://steamdb.info/app/1114150/depots/

Public Linux depot inventory lists GameAssembly.so (245.84 MiB), UnityPlayer.so (38.73 MiB), and Linux EAC/runtime files:
https://steamdb.info/depot/1114152/

Public Mac depot inventory lists GameAssembly.dylib (358.50 MiB) and UnityPlayer.dylib (60.22 MiB), native plugins and StandaloneOSX Unity data:
https://steamdb.info/depot/1114153/

CarX announced official Apple Silicon support September 9, 2025, with possible Rosetta requirement for the EAC launcher:
https://steamdb.info/patchnotes/19910222/

Depot tables provide file names/sizes, not original binary CPU architecture headers, and some file lists are outdated. Linux GameAssembly.so architecture is UNVERIFIED. Mac GameAssembly.dylib ARM64 slice presence is UNVERIFIED despite developer's hardware support announcement.

## True native Android port route comparison

| Original platform | Native code container | Original CPU ISA | Direct Android ARM64 executable? |
|---|---|---|---|
| User Windows PC build | PE GameAssembly.dll | VERIFIED x86-64 | NO |
| Linux Steam build | ELF GameAssembly.so | UNVERIFIED | NO PROOF (Linux ELF might use glibc and/or x86-64) |
| macOS Steam build | Mach-O GameAssembly.dylib | UNVERIFIED | NO PROOF (Darwin ABI, dyld, Metal, frameworks) |

Even if Linux code proves ELF/AArch64, Linux glibc/host service dependencies still differ from Android Bionic. Even if Mac code proves ARM64, Android does not directly dlopen Darwin Mach-O. Using a macOS/Linux runtime compatibility layer is NOT the user's strict native-only port. No platform depot automatically supplies Android-target Unity asset bundles.

Unity 6000.3 IL2CPP documentation says each build target compiles the game's managed code to target-specific native machine code:
https://docs.unity.com/en-us/engine/6000.3/manual/programming-environment/scripting-backends/il2cpp/il2cpp-introduction

Unity AssetBundle platform restrictions:
https://docs.unity.com/en-us/engine/6000.0/manual/assets-and-media/assets-managing-runtime/assetbundles-section/platforms

## Real source work and independently verified CI

1. Mac architecture parser: tools/carx_macho_architecture_gate.py; thin and FAT Mach-O original user-owned binary inspection and dependency classification. 15 synthetic negative tests, Actions #43190305235 SUCCESS:
https://github.com/RM11Cor/RM11-WinCore/actions/runs/43190305235

2. Linux source architecture parser: tools/carx_linux_elf_architecture_gate.py; bounded ELF64 program header, e_machine, PT_DYNAMIC, DT_NEEDED and glibc dependencies inspection. Linux ELF/AArch64 never becomes false Android Bionic claim. 16 independent synthetic negative tests, Actions #43192244173 SUCCESS:
https://github.com/RM11Cor/RM11-WinCore/actions/runs/43192244173

Original proprietary Linux or Mac CarX game binaries were NOT present in GitHub CI or the user's Windows scan. Thus these test passes prove inspector behavior, NOT game CPU architecture or executable ARM64 Android CarX code.

## Acceptance gates for future genuinely playable game port

G0: Authorized source or fully legitimate native Android ARM64 game logic is available and runnable in Android ELF/Bionic. OPEN.

G1: Android-target Unity 6000.3.8f1 game assets and script dependencies legally rebuilt or otherwise provided; Linux, Mac and Windows bundles do not prove this. OPEN.

G2: Real original CarX game scene loaded and presented with controller/vehicle physics, not a Vulkan-only synthetic image. OPEN.

Decision: retain v0.6 Android APK for now; no more cosmetic inspector APKs. KERNIX remains paused; FH5 remains separate. Native port proof cannot advance past G0 merely from Steam depots or shader preflight.
