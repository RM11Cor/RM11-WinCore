# Architectural decision — 12 November 2026

## What other developers actually do

1. Native source ports / recompilation: compile or reconstruct legal original game logic to ARM64 and implement compatible graphics and asset loader. Usually no commercial Windows executable is executed.
2. Game-specific Android wrappers: ship a dedicated launcher that imports game data and embeds or depends upon FEX CPU translation, Wine/Windows compatibility, Turnip/Vulkan/DXVK, PS4 syslibs or other custom runtimes. This **is emulation/translation even if there is only one APK and no visible emulator settings**.
3. Launchers around existing native ports: game files can be selected and booted with one tap **because the executable engine already exists**; simple folder detection is not the hard step.

Reference implementations to inspect: `erickmendes22/tlou-remastered-android` (FEXCore + shadPS4 Vulkan), `zFitness/gow3_android` ARM port branch (FEX and nixport host), `rushilvishwakarma/Rush5` launcher on an ARM64 GTA port, `Unity-Technologies/UnityDataTools` for cross-platform asset-pack differences.

## CarX Street desktop Unity IL2CPP exact barriers

PC `GameAssembly.dll` is a compiled Windows x86-64 game assembly and `UnityPlayer.dll` is a Windows game engine binary; neither can be loaded as Android ARM64 native library. `CarX Street_Data` contains serialized Unity assets/metadata, not a substitute for native compiled game code. Unity asset bundles may be platform dependent: shaders, texture formats and streaming Addressables need verification/conversion; copying StandaloneWindows64 bundles into an Android APK is not an engine port. CarX already has an official, commercially different mobile edition, and a publicly available game source project or licensed Unity project is not established.

We must avoid claiming a native working port from a file import alone. Next evidence gate requires a real manifest from the user's extracted installation and an **authorized source/runtime path**. Custom per-game dynamic translation is an alternative technical track if user later explicitly agrees; it is not secretly a native port.

Do not include proprietary game files in GitHub, bypass anti-cheat or license enforcement, or build a counterfeit game APK. No gameplay claim until the APK produces a real game-rendered frame.
