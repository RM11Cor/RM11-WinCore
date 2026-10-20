# RM11-WinCore v2.4.12 — One-run Vulkan GPU Five-Stage Suite

**One tap** on the new main-screen test opens a `SurfaceView`, runs the native checks, and produces **one shareable report** with raw JSON.

1. `Vertex/Fragment Shader Modules`: GLSL is compiled to SPIR-V during GitHub Actions; Vulkan creates shader modules at runtime.
2. `Graphics Pipeline + Triangle`: real `vkCreateGraphicsPipelines` and `vkCmdDraw` submit and present 240 frames on the Android display.
3. `Compute Shader`: dispatch 256 GPU operations; map coherent host-visible storage buffer and compare all 256 results. Mark unavailable if the graphics queue lacks compute support or suitable host-coherent memory.
4. `Frame timing and short stability`: report wall-clock presentation throughput and **optional** GPU query timestamp range (which is not the actual display-present latency). These measurements are not game FPS benchmarks. The loop is deliberately limited to 240 frames.
5. `DXVK prerequisite inventory`: report advertised Vulkan core/extension prerequisites; **no Wine, FEX, DXVK, DirectX or Windows EXE is launched or validated**. Advertised API/extension availability does not guarantee DXVK compatibility.

## Build

Direct tracked source on `main`, no ZIP source uploads. GitHub Actions installs glslang-tools, compiles three tracked GLSL files to generated SPIR-V C arrays, runs existing Java tests, builds the Android ARM64 app with NDK 27.2/CMake 3.22.1, and checks APK certificate SHA-256 against the earlier signed build.

Identity is unchanged: `applicationId=com.rm11.autocore`, `versionCode=13`, `versionName=2.4.12-alpha`, SHA-256 signing certificate `d398e7effe9302645e449fb02ecc42a409f7e7566274cbc37c4361e0482152f0`.

**Safety:** No game-file edits, launcher modification, EXE execution, system root, DRM bypass or background stress run. On-device suite tests are **not yet completed** by source packaging; they must run on the handset after GitHub Actions succeeds.
