# KERNIX independent Android host bridge v1

This is KERNIX-owned native C source, compiled with Android NDK r27c for
Android API 26 and AArch64. This is NOT an APK, emulator or game runtime.

## Exports
- `kernix_host_abi_version()` returns native interface version 1.
- `kernix_host_probe_v1(struct kernix_host_info_v1 *)` reports AArch64,
  whether `libvulkan.so` loads and whether the system Vulkan loader exposes
  `vkEnumerateInstanceVersion` with API >= 1.1.

The caller allocates the C structure, sets `struct_size` before the call, and
checks returned API version and capabilities. A Vulkan loader is not proof of
Vulkan device support, swapchain creation, Turnip compatibility or rendering.

## CI
`.github/workflows/kernix-android-arm64-host.yml` compiles from this
directory with NDK Clang, audits the real AArch64 ELF architecture, checks
exported symbols, records SHA-256 and emits an artifact plus source license.

## Not implemented
Wine/FEX translation, Vulkan surface/swapchain, game launch, input controls,
Android UI, runtime component installation or per-game execution. Never
advertise this native bridge as functioning Windows emulation.
