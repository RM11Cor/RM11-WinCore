# RM11-WinCore v2.4.11 — Vulkan Surface Frame Test

This version preserves `com.rm11.autocore` and the existing PKCS12 signing key and introduces a separate 180-frame Vulkan surface presentation test.

What it genuinely checks:
- Creates an Android Vulkan surface through a real `SurfaceView`.
- Chooses a physical GPU and graphics/present queues; checks the swapchain extension.
- Creates a logical device and swapchain, acquires images, submits actual GPU transfer commands, and presents continuously changing colors.
- Measures host-observed frame presentation throughput/average frame time; can be limited by vsync and CPU `vkQueueWaitIdle` serialization.

**Limitations:** no graphics shaders or pipeline, DXVK, Turnip replacement, R4 utilization proof, Windows EXE execution, or measured GPU execution time. Successful presentation is evidence of a working Android Vulkan rendering path, *not* game compatibility.

## Build

After a one-time GitHub repository conversion from the existing v2.4.10 source archive to tracked source files, `.github/workflows/build-apk.yml` directly builds the source at the repository root on every matching push to `main`, first running `:app:testDebugUnitTest`, then signing the APK using the existing GitHub Secrets (`RM11_RELEASE_KEYSTORE_B64`, `RM11_RELEASE_PASSWORD`). It rejects a certificate different from the verified v2.4.10 stable signature.

`versionCode=12`, `versionName=2.4.11-alpha`, applicationId `com.rm11.autocore`. NDK `27.2.12479018` and CMake `3.22.1` remain pinned.

This source is prepared for GitHub Actions validation and on-device inspection; it has **not** passed an Android build or GPU runtime test yet.
