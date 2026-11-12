# CarX Street PC: v0.6 real GPU pass; no standalone native PC game port yet

Report received and inspected on 2026-11-12: `CarX_Street_PC_Port_Report_v0.6.json`, version `0.6.0`. Test device REDMAGIC NX809J, Android SDK36, `arm64-v8a`, SM8850, GPU Adreno 840, reported Vulkan 1.4.295. Source file folder name CarX Street, 906 files, 21 dirs, total bytes 22,710,138,866. Source Windows64 addressable bundles: 808, 19,819,549,827 bytes.

## Closed: independent native ARM64/Vulkan GPU execution gate (device evidence)

- Original independent app JNI `libcarx_native_probe.so` loaded and its ARM64 function executed on user device.
- `vkCreateInstance == VK_SUCCESS (0)`, Vulkan GPU count 1; Vulkan Device created true.
- Physical graphics queue family index 0, real VK_FORMAT_R8G8B8A8_UNORM 32 × 32 image created.
- `command_buffer_submitted_to_gpu: true`, `gpu_fence_completed: true`, `host_readback_completed: true`.
- `stage = complete_verified_gpu_offscreen_clear`, `vk_result = 0`.
- Expected `[51,128,204,255]`; readback first `[51,128,204,255]`; **all 1024 pixels matched**, verified=true.
- `real_android_surface_created = false`, `real_android_swapchain_created = false`; test is offscreen only. No user-visible first frame.
- **None of this is the original CarX game engine**. Source report expressly has `runtime_present=false`, `game_executed=false`, `native_ARM64_port_proven=false`, `carx_game_logic_executed=false`, `original_carx_game_frame_rendered=false`, `original_unity_6000_3_8f1_android_runtime_present=false`.

**Decision:** Basic native Android Vulkan availability, physical device discovery, queue submit, GPU-fence and CPU-readback **have sufficient real device evidence; do NOT spend the next stage rerunning generic GPU setup tests**.

## Still open, fundamental CarX game port blockers

1. Exact original game logic: `CarX Street Launcher.exe` and `GameAssembly.dll` are Windows PE x86-64 binaries. Original Unity IL2CPP outputs **platform-specific native machine code**. The current Android APK only contains our original independent `libcarx_native_probe.so`, not CarX IL2CPP Android machine code.
2. Data/metadata: the first 4096 bytes of the source `CarX Street_Data/il2cpp_data/Metadata/global-metadata.dat` lacked classic `af 1b b1 fa` metadata magic; first 16 bytes are `ab1459494a01f63c75f25b31cc15c122`. This is **nonstandard**, not proof of any encryption algorithm or recoverable original source.
3. Original Unity editor candidate from `globalgamemanagers` and `resources.assets` agrees: **6000.3.8f1**, format 22, known serialized header offset 48. This identifies the Windows source asset serialization build, **not** a legally usable original Android CarX Unity project/runtime.
4. All 808 original addressable bundles are under `StandaloneWindows64`. Unity officially says AssetBundles are platform specific. The v0.6 app has not loaded one on Android. The original Android-target AssetBundles have **not** been provided or legitimately generated from a Unity project.
5. Original PC gameplay, scene scripts, physics, gameplay loop, user controls, save logic, audio, multiplayer services and EAC are NOT ported. Do not claim a first game frame/FPS/complete APK.

## Engineering paths ranked by *actual feasibility*

**A — true native game-specific port (user goal: no emulator).** Requires authorized CarX gameplay source/IL2CPP compilation inputs or a legitimately available compatible native ARM64 CarX game runtime **plus** Android-target project assets, with necessary permissions. Rebuild Unity game code and bundles targeting Android, then prove initial game scene, real character/car controls and a frame. An Android app with a different CarX Street mobile build is not by itself proof that its gameplay binaries/bundles can legally or technically execute the PC edition, whose game balance and assets differ.

**B — clean-room implementation of compatible gameplay.** Implement a separate engine and game mechanics authored independently and legitimately import assets where permissible. This is a new/recreated game and cannot be presented as an automatic binary port of 142MB `GameAssembly.dll`. Very large scope.

**C — game-specific executable wrapper / compatibility runtime.** A standalone APK could hide a preconfigured FEX/Wine/driver stack; it may run the original Windows PC binary, but remains x86 translation and API compatibility **despite not presenting a user-facing emulator**. It does not meet a strict no-emulation native port requirement; it is a separate user-selectable route if requirements change.

## Next actual acceptance criteria, not more GPU test APKs

- **G-L0: game-code ownership/executability gate.** Identify documented, licensed native ARM64 engine/game-logic inputs for this exact CarX PC build. Inspect available materials without bypassing service protections. **Fail closed** if none exist: no app-only tool can infer legally recompilable original game code from a PE binary and nonstandard metadata.
- **G-A0: Android assets gate.** Identify a permitted Android-target set of scene/assets built from same PC content. Check Unity build/asset GUID dependencies and verify the full scene can load on a legitimate native Android runtime; a readable Windows UnityFS header is insufficient.
- **G-V1: real on-screen game frame.** AFTER both previous gates, attach a native window and render an original CarX scene with proof of game code execution and controller response. A synthetic Vulkan color or triangle is explicitly **not** this criterion.
- Keep `com.rm11cor.carxstreet.portlab` and permanent signer SHA256 `73759b890548a1cc52cc513ce859013e0e2c0884258f66ee19da45e59b30e2bc`; monotonic versionCode from 6 onward for any real new feature. No certificate rotation.
- KERNIX is paused. FH5 project is isolated. Do not silently use either engine.

## Public technical references

- Unity AssetBundle platform restrictions (current): https://docs.unity.com/en-us/engine/6000.0/manual/assets-and-media/assets-managing-runtime/assetbundles-section/platforms
- Unity IL2CPP native target compilation explanation: https://docs.unity.com/en-us/engine/6000.5/manual/scripting/compilation-and-code-reload/script-compilation/backends/il2cpp/il2cpp-introduction
- Original CarX developer PC/mobile divergence (balance and graphical improvements): https://store.steampowered.com/news/posts/?appids=1114150&enddate=1724762921&feed=steam_community_announcements

This document records independently **reported user-device runtime results** and the actual missing port dependencies. It does not claim the CarX PC source files or original app game code were uploaded to our CI.
