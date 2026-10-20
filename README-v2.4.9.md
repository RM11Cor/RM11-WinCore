# RM11-WinCore v2.4.9: Android Vulkan Native Smoke Probe

## Purpose

This release adds a **real Vulkan driver probe** on the Android phone, not merely
`PackageManager.FEATURE_VULKAN_HARDWARE_VERSION` metadata. It advances the GPU
validation milestone before any Wine/FEX/DXVK/VKD3D runtime is bundled.

## New functions

- `VulkanNativeProbe.java`: loads app-owned ARM64 `librm11_vulkan_probe.so` and
  formats actual Vulkan API results in Arabic, plus optional raw JSON share.
- `app/src/main/cpp/vulkan_probe.c`: uses the Android Vulkan loader to call
  `vkCreateInstance`, enumerate GPU devices/queues, read Vulkan API and extension
  properties, attempt `vkCreateDevice` with a graphics queue, then destroy both
  Vulkan device and instance. There is **no rendering, shader, graphics benchmark,
  game access, persistence, root, network call, or DLL execution**.
- `VulkanEvidence.java`: separates Vulkan smoke-test success from any claim of
  game compatibility. Extension presence is not a feature or rendering guarantee.
- UI button `اختبار تعريف Vulkan الفعلي (GPU)` runs the native probe on a worker
  thread, displaying non-fatal failure details. Separate share-report button.
- Preserves game directory scanning, auto-compatibility preflight and Android
  system feature report from v2.4.8.

## Build

- Android `applicationId`: `com.rm11.autocore` (unchanged).
- `versionCode`: 10 (was 9), `versionName`: `2.4.9-alpha`.
- CMake `3.22.1`, Android NDK `27.2.12479018`, `arm64-v8a` only.
- Existing GitHub Actions build already requests NDK/CMake; runtime source is
  selected from the latest exact `RM11-WinCore-v*-source.zip` archive.
- Stable release signing comes ONLY from `RM11_RELEASE_KEYSTORE` and
  `RM11_RELEASE_PASSWORD` injected through encrypted GitHub Actions secrets.
- The old workflow artifact label might still say `v2.4.3`; identify releases by
  `versionName` and `Using RM11-WinCore-v2.4.9-source.zip` log entry.

## Verification level

- Source structure script: passed.
- Pure Java unit tests: 50 / 50 passed with local harness.
- Native C syntax check with mock Vulkan/JNI headers: passed; **does not certify
  Android NDK compilation or Vulkan driver runtime behavior**.
- APK, NDK build and phone tests: pending GitHub Actions and REDMAGIC 11 Pro.

## Interpretation

`VK_KHR_swapchain`, timeline semaphore and ray tracing extension reports are
extension **declarations**, not proof that the translated Windows graphics stack
can use them. Vulkan `vkCreateDevice` success alone does not prove FPS or DX12.
No Wine/Proton/FEX packages are installed by this release. No Windows EXE can
be executed with RM11-WinCore yet. That execution engine is the next milestone.

## Privacy

Everything runs locally and reads only graphics/OS state. No telemetry or network
permission is requested, game data is unchanged, and native probe is confined to
the app process. Never publish your keystore or secret values.
